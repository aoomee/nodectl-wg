package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"nodectl/internal/agent/wgrelay"
	"nodectl/internal/database"
)

var ErrWGConflict = errors.New("pair revision or node reservation conflict")
var ErrWGUnavailable = errors.New("WireGuard dependencies unavailable")

// A single bounded critical section intentionally serializes pair operations and
// parent node mutations. Callers MUST unlock after mutation; do not nest locks.
var wgNodeMu sync.Mutex

func WGAcquireNodeLocks(uuids ...string) func() { wgNodeMu.Lock(); return wgNodeMu.Unlock }
func WGNodeInUse(id string) bool {
	if database.DB == nil {
		return true
	}
	var n int64
	return database.DB.Model(&database.WGPairNode{}).Where("node_uuid = ?", id).Count(&n).Error != nil || n != 0
}
func WGNodeMutationAllowed(id string) error {
	if WGNodeInUse(id) {
		return errors.New("disable WireGuard pair and wait for cleanup before changing node")
	}
	return nil
}

type WGPairPush struct {
	UUID      string `json:"uuid"`
	PeerUUID  string `json:"peer_uuid"`
	EntryPort int    `json:"entry_port"`
	Revision  uint64 `json:"revision"`
	Enabled   bool   `json:"enabled"`
}
type WGPairDTO struct {
	ID              string `json:"id"`
	UUID            string `json:"uuid"`
	PeerUUID        string `json:"peer_uuid"`
	EntryPort       int    `json:"entry_port"`
	Revision        uint64 `json:"revision"`
	AppliedRevision uint64 `json:"applied_revision"`
	Enabled         bool   `json:"enabled"`
	Status          string `json:"status"`
	Phase           string `json:"phase"`
	Error           string `json:"error,omitempty"`
}
type WGPeerDTO struct {
	UUID  string `json:"uuid"`
	Name  string `json:"name"`
	Ready bool   `json:"ready"`
}
type WGPairOptionsDTO struct {
	Pair  *WGPairDTO  `json:"pair"`
	Peers []WGPeerDTO `json:"peers"`
	Ready bool        `json:"ready"`
}

func wgDTO(p database.WGPair) WGPairDTO {
	return WGPairDTO{p.ID, p.EntryUUID, p.PeerUUID, p.EntryPort, p.DesiredRevision, p.AppliedRevision, p.Enabled, p.Status, p.Phase, p.Error}
}

type wgPairCoordinator struct {
	db      *gorm.DB
	ready   func(string) bool
	send    func(context.Context, string, string, interface{}) (json.RawMessage, error)
	now     func() time.Time
	timeout time.Duration
	// Proof is process-local: persisted active alone can never publish a link.
	confirmed map[string]uint64
}

var wgDefault = &wgPairCoordinator{ready: WGAgentReady, send: SendWGCommand, now: time.Now, timeout: 20 * time.Second, confirmed: map[string]uint64{}}

func (c *wgPairCoordinator) database() *gorm.DB {
	if c.db != nil {
		return c.db
	}
	return database.DB
}
func wgHash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func wgIPv4(s string) bool {
	a, e := netip.ParseAddr(s)
	return e == nil && a.Is4() && a.IsGlobalUnicast() && !a.IsLoopback() && a.String() == s
}
func wgNodeEligible(n database.NodePool, role string) bool {
	route := 1
	if role == "landing" {
		route = 2
	}
	return n.RoutingType == route && !n.IsBlocked && !n.TrafficThresholdReached && !n.TunnelEnabled && n.TunnelID == "" && wgIPv4(n.IPV4)
}
func wgReality(n database.NodePool) (string, int, error) {
	link := strings.TrimSpace(n.Links["reality"])
	if contains(n.DisabledLinks, "reality") || link == "" {
		return "", 0, ErrWGUnavailable
	}
	u, e := url.Parse(link)
	if e != nil || u.Scheme != "vless" || u.User == nil || u.Hostname() == "" || u.Path != "" {
		return "", 0, ErrWGUnavailable
	}
	if _, e = uuid.Parse(u.User.Username()); e != nil {
		return "", 0, ErrWGUnavailable
	}
	if _, present := u.User.Password(); present {
		return "", 0, ErrWGUnavailable
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return "", 0, ErrWGUnavailable
	}
	key, e := base64.RawURLEncoding.DecodeString(q.Get("pbk"))
	port, e2 := strconv.Atoi(u.Port())
	sid, e3 := hex.DecodeString(q.Get("sid"))
	if q.Get("security") != "reality" || q.Get("sni") == "" || e != nil || len(key) != 32 || e2 != nil || port < 1 || port > 65535 || e3 != nil || len(sid) > 8 || (q.Get("type") != "" && q.Get("type") != "tcp") {
		return "", 0, ErrWGUnavailable
	}
	if configured := n.LinkPorts["reality"]; configured != 0 && configured != port {
		return "", 0, ErrWGUnavailable
	}
	return link, port, nil
}
func (c *wgPairCoordinator) identity(db *gorm.DB, n database.NodePool) (string, error) {
	var i database.AgentIdentity
	if db.Where("node_uuid = ? AND install_id = ?", n.UUID, n.InstallID).First(&i).Error != nil || !i.Bound || i.SecretHash == "" || !c.ready(n.InstallID) {
		return "", ErrWGUnavailable
	}
	return wgHash(i.SecretHash), nil
}
func (c *wgPairCoordinator) dependencies(db *gorm.DB, aID, bID string) (a, b database.NodePool, ah, bh, link string, port int, err error) {
	err = ErrWGUnavailable
	if aID == bID || db.First(&a, "uuid = ?", aID).Error != nil || db.First(&b, "uuid = ?", bID).Error != nil || !wgNodeEligible(a, "entry") || !wgNodeEligible(b, "landing") || a.InstallID == b.InstallID || a.IPV4 == b.IPV4 {
		return
	}
	ah, err = c.identity(db, a)
	if err != nil {
		return
	}
	bh, err = c.identity(db, b)
	if err != nil {
		return
	}
	link, port, err = wgReality(b)
	return
}
func (c *wgPairCoordinator) valid(p database.WGPair) bool {
	a, b, ah, bh, link, port, e := c.dependencies(c.database(), p.EntryUUID, p.PeerUUID)
	return e == nil && a.InstallID == p.EntryInstallID && b.InstallID == p.PeerInstallID && a.IPV4 == p.EntryIP && b.IPV4 == p.PeerIP && ah == p.EntryIdentityHash && bh == p.PeerIdentityHash && wgHash(link) == p.LinkHash && port == p.TargetPort
}
func SaveWGPair(ctx context.Context, r WGPairPush) (WGPairDTO, error) {
	unlock := WGAcquireNodeLocks(r.UUID, r.PeerUUID)
	defer unlock()
	return wgDefault.save(ctx, r)
}
func (c *wgPairCoordinator) save(ctx context.Context, r WGPairPush) (WGPairDTO, error) {
	if c.database() == nil || r.UUID == "" || len(r.UUID) > 36 || r.Revision < 1 || r.Revision > 1<<63-1 {
		return WGPairDTO{}, ErrWGConflict
	}
	var p database.WGPair
	err := c.database().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		e := tx.First(&p, "entry_uuid = ?", r.UUID).Error
		exists := e == nil
		if e != nil && !errors.Is(e, gorm.ErrRecordNotFound) {
			return e
		}
		if exists {
			if r.Revision == p.DesiredRevision && r.Enabled == p.Enabled && (!r.Enabled || r.PeerUUID == p.PeerUUID && r.EntryPort == p.EntryPort) {
				return nil
			}
			if r.Revision != p.DesiredRevision+1 {
				return ErrWGConflict
			}
			if r.Enabled && p.Status != "disabled" {
				return errors.New("disable pair and finish cleanup before editing")
			}
			if !r.Enabled {
				p.Enabled = false
				p.DesiredRevision = r.Revision
				if p.Status != "disabled" {
					p.Status = "cleanup_pending"
					p.Phase = "remove_a"
				}
				p.NextRetryAt = time.Time{}
				p.RetryCount = 0
				p.Error = ""
				return tx.Save(&p).Error
			}
		} else if !r.Enabled || r.Revision != 1 {
			return ErrWGConflict
		}
		if r.EntryPort < 1 || r.EntryPort > 65535 || r.PeerUUID == "" || len(r.PeerUUID) > 36 {
			return ErrWGConflict
		}
		a, b, ah, bh, link, port, e := c.dependencies(tx, r.UUID, r.PeerUUID)
		if e != nil {
			return e
		}
		for proto, v := range a.LinkPorts {
			if v == r.EntryPort && !contains(a.DisabledLinks, proto) {
				return errors.New("entry port conflicts with existing protocol")
			}
		}
		if !exists {
			var id [12]byte
			if _, e = rand.Read(id[:]); e != nil {
				return e
			}
			p.ID = hex.EncodeToString(id[:])
			sum := sha256.Sum256([]byte(p.ID))
			host := binary.BigEndian.Uint32(sum[:4])%((1<<21)-1)*2 + 2
			p.EntryAddress = fmt.Sprintf("10.%d.%d.%d/32", 64+(host>>16), host>>8&255, host&255)
			host++
			p.PeerAddress = fmt.Sprintf("10.%d.%d.%d/32", 64+(host>>16), host>>8&255, host&255)
			p.EntryWGPort = 20000 + int(binary.BigEndian.Uint16(sum[4:6]))%20000
			p.PeerWGPort = 40000 + int(binary.BigEndian.Uint16(sum[6:8]))%20000
		}
		p.EntryUUID = a.UUID
		p.PeerUUID = b.UUID
		p.EntryInstallID = a.InstallID
		p.PeerInstallID = b.InstallID
		p.EntryIP = a.IPV4
		p.PeerIP = b.IPV4
		p.EntryIdentityHash = ah
		p.PeerIdentityHash = bh
		p.EntryPort = r.EntryPort
		p.TargetPort = port
		p.RealityLink = link
		p.LinkHash = wgHash(link)
		p.DesiredRevision = r.Revision
		p.Enabled = true
		p.Status = "pending"
		p.Phase = "prepare_a"
		p.Error = ""
		p.RetryCount = 0
		p.NextRetryAt = time.Time{}
		p.HealthCheckedAt = time.Time{}
		p.EntryPublicKey = ""
		p.PeerPublicKey = ""
		if e = tx.Create(&database.WGPairNode{NodeUUID: a.UUID, PairID: p.ID}).Error; e != nil {
			return ErrWGConflict
		}
		if e = tx.Create(&database.WGPairNode{NodeUUID: b.UUID, PairID: p.ID}).Error; e != nil {
			return ErrWGConflict
		}
		return tx.Save(&p).Error
	})
	if err == nil && p.Status != "active" {
		delete(c.confirmed, p.ID)
	}
	return wgDTO(p), err
}
func WGPairOptions(id string) (WGPairOptionsDTO, error) {
	unlock := WGAcquireNodeLocks(id)
	defer unlock()
	return wgDefault.options(id)
}
func (c *wgPairCoordinator) options(id string) (WGPairOptionsDTO, error) {
	out := WGPairOptionsDTO{Peers: []WGPeerDTO{}}
	db := c.database()
	if db == nil {
		return out, ErrWGUnavailable
	}
	var a database.NodePool
	if db.First(&a, "uuid = ?", id).Error != nil {
		return out, ErrWGUnavailable
	}
	_, e := c.identity(db, a)
	out.Ready = e == nil && wgNodeEligible(a, "entry")
	var p database.WGPair
	e = db.First(&p, "entry_uuid = ?", id).Error
	if e == nil {
		dto := wgDTO(p)
		out.Pair = &dto
	} else if !errors.Is(e, gorm.ErrRecordNotFound) {
		return out, e
	}
	var nodes []database.NodePool
	if e = db.Where("routing_type = ?", 2).Order("name, uuid").Find(&nodes).Error; e != nil {
		return out, e
	}
	for _, b := range nodes {
		if b.UUID == id || !wgNodeEligible(b, "landing") {
			continue
		}
		var count int64
		if e = db.Model(&database.WGPairNode{}).Where("node_uuid = ? AND pair_id <> ?", b.UUID, p.ID).Count(&count).Error; e != nil {
			return out, e
		}
		if count != 0 {
			continue
		}
		if _, _, e = wgReality(b); e != nil {
			continue
		}
		_, e = c.identity(db, b)
		out.Peers = append(out.Peers, WGPeerDTO{b.UUID, b.Name, e == nil})
	}
	return out, nil
}
func (c *wgPairCoordinator) payload(p database.WGPair, entry bool) wgrelay.Payload {
	v := wgrelay.Payload{PairID: p.ID, Revision: p.DesiredRevision, EntryPort: p.EntryPort, TargetPort: p.TargetPort}
	if entry {
		v.Role = "entry"
		v.LocalAddress = p.EntryAddress
		v.PeerAddress = p.PeerAddress
		v.ListenPort = p.EntryWGPort
		v.PeerEndpoint = p.PeerIP
		v.PeerPort = p.PeerWGPort
		v.PeerPublicKey = p.PeerPublicKey
	} else {
		v.Role = "landing"
		v.LocalAddress = p.PeerAddress
		v.PeerAddress = p.EntryAddress
		v.ListenPort = p.PeerWGPort
		v.PeerEndpoint = p.EntryIP
		v.PeerPort = p.EntryWGPort
		v.PeerPublicKey = p.EntryPublicKey
	}
	return v
}
func (c *wgPairCoordinator) command(ctx context.Context, p database.WGPair, entry bool, action string) (wgrelay.Status, error) {
	var s wgrelay.Status
	id := p.PeerInstallID
	if entry {
		id = p.EntryInstallID
	}
	if !c.ready(id) {
		return s, ErrWGUnavailable
	}
	payload := c.payload(p, entry)
	if action == "wg-prepare" {
		payload.PeerPublicKey = ""
		payload.PeerEndpoint = ""
		payload.PeerPort = 0
	}
	if action != "wg-prepare" && action != "wg-configure" {
		payload = wgrelay.Payload{PairID: p.ID, Revision: p.DesiredRevision}
	}
	timeout := c.timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, e := c.send(cmdCtx, id, action, payload)
	if e != nil {
		return s, ErrWGUnavailable
	}
	if json.Unmarshal(raw, &s) != nil || s.PairID != p.ID || s.Revision != p.DesiredRevision {
		return s, errors.New("invalid WireGuard acknowledgement")
	}
	if action == "wg-remove" {
		if s.Phase != "removed" || s.ProxyListening {
			return s, ErrWGUnavailable
		}
		return s, nil
	}
	role := "landing"
	if entry {
		role = "entry"
	}
	if s.Role != role {
		return s, ErrWGUnavailable
	}
	switch action {
	case "wg-prepare":
		key, e := base64.StdEncoding.DecodeString(s.PublicKey)
		if e != nil || len(key) != 32 || s.Phase != "prepared" {
			return s, ErrWGUnavailable
		}
	case "wg-configure":
		if s.Phase != "configured" {
			return s, ErrWGUnavailable
		}
	case "wg-verify":
		if (s.Phase != "verified" && s.Phase != "active") || (entry && !s.TargetTCPVerified) {
			return s, ErrWGUnavailable
		}
	case "wg-activate":
		if s.Phase != "active" || !s.ProxyListening || !s.TargetTCPVerified {
			return s, ErrWGUnavailable
		}
	case "wg-status":
		if (entry && (!s.TargetTCPVerified || s.Phase != "active" || !s.ProxyListening)) || (!entry && s.Phase != "verified") {
			return s, ErrWGUnavailable
		}
	}
	return s, nil
}
func (c *wgPairCoordinator) persist(p *database.WGPair) error { return c.database().Save(p).Error }
func (c *wgPairCoordinator) fail(p *database.WGPair) error {
	delete(c.confirmed, p.ID)
	p.Status = "cleanup_pending"
	p.Phase = "remove_a"
	p.Error = "WireGuard operation or dependency failed; cleanup required"
	p.NextRetryAt = time.Time{}
	p.RetryCount = 0
	return c.persist(p)
}
func (c *wgPairCoordinator) cleanup(ctx context.Context, p *database.WGPair) error {
	entry := p.Phase != "remove_b"
	if _, e := c.command(ctx, *p, entry, "wg-remove"); e != nil {
		p.RetryCount++
		delay := time.Second << min(p.RetryCount, 6)
		p.NextRetryAt = c.now().Add(delay)
		p.Error = "cleanup pending; authenticated agent acknowledgement required"
		return c.persist(p)
	}
	p.RetryCount = 0
	p.NextRetryAt = time.Time{}
	if entry {
		p.Phase = "remove_b"
		return c.persist(p)
	}
	return c.database().Transaction(func(tx *gorm.DB) error {
		p.Status = "disabled"
		p.Phase = "disabled"
		p.Enabled = false
		p.RealityLink = ""
		p.Error = ""
		if e := tx.Save(p).Error; e != nil {
			return e
		}
		return tx.Where("pair_id = ?", p.ID).Delete(&database.WGPairNode{}).Error
	})
}

// step performs at most two bounded commands (active health probes), persisting
// the next stage before returning. No command runs inside a database transaction.
func (c *wgPairCoordinator) step(ctx context.Context, id string) error {
	var p database.WGPair
	if e := c.database().First(&p, "id = ?", id).Error; e != nil {
		return e
	}
	if p.Status == "disabled" || c.now().Before(p.NextRetryAt) {
		return nil
	}
	if p.Status == "cleanup_pending" {
		return c.cleanup(ctx, &p)
	}
	if !p.Enabled || !c.valid(p) {
		return c.fail(&p)
	}
	if p.Status == "active" {
		delete(c.confirmed, p.ID)
		if _, e := c.command(ctx, p, true, "wg-status"); e != nil {
			return c.fail(&p)
		}
		if _, e := c.command(ctx, p, false, "wg-status"); e != nil {
			return c.fail(&p)
		}
		if !c.valid(p) {
			return c.fail(&p)
		}
		p.HealthCheckedAt = c.now()
		if e := c.persist(&p); e != nil {
			return c.fail(&p)
		}
		c.confirmed[p.ID] = p.DesiredRevision
		return nil
	}
	stages := map[string]struct {
		entry        bool
		action, next string
	}{
		"prepare_a": {true, "wg-prepare", "prepare_b"}, "prepare_b": {false, "wg-prepare", "configure_b"},
		"configure_b": {false, "wg-configure", "configure_a"}, "configure_a": {true, "wg-configure", "verify_a"},
		"verify_a": {true, "wg-verify", "verify_b"}, "verify_b": {false, "wg-verify", "activate_a"}, "activate_a": {true, "wg-activate", "active"},
	}
	stage, ok := stages[p.Phase]
	if !ok {
		return c.fail(&p)
	}
	s, e := c.command(ctx, p, stage.entry, stage.action)
	if e != nil {
		return c.fail(&p)
	}
	if !c.valid(p) {
		return c.fail(&p)
	}
	if stage.action == "wg-prepare" {
		if stage.entry {
			p.EntryPublicKey = s.PublicKey
		} else {
			p.PeerPublicKey = s.PublicKey
			if p.PeerPublicKey == p.EntryPublicKey {
				return c.fail(&p)
			}
		}
	}
	p.Phase = stage.next
	p.Status = "pending"
	if p.Phase == "active" {
		p.Status = "active"
		p.AppliedRevision = p.DesiredRevision
		p.HealthCheckedAt = c.now()
	}
	if e = c.persist(&p); e != nil {
		return c.fail(&p)
	}
	if p.Status == "active" {
		c.confirmed[p.ID] = p.DesiredRevision
	}
	return nil
}
func (c *wgPairCoordinator) recover() error {
	c.confirmed = map[string]uint64{}
	// A crash can occur after an agent acted but before its acknowledgement was
	// persisted. Never infer success or reopen a listener from saved stage alone.
	return c.database().Model(&database.WGPair{}).Where("status NOT IN ?", []string{"disabled", "cleanup_pending"}).Updates(map[string]interface{}{"status": "cleanup_pending", "phase": "remove_a", "error": "coordinator restarted; cleanup required", "next_retry_at": time.Time{}}).Error
}

var wgReconcilerMu sync.Mutex

// StartWGPairReconciler blocks until cancellation; launch once from server startup.
// On every process start all interrupted/active pairs are conservatively removed.
func StartWGPairReconciler(ctx context.Context) {
	wgReconcilerMu.Lock()
	defer wgReconcilerMu.Unlock()
	if ctx.Err() != nil || wgDefault.database() == nil {
		return
	}
	unlock := WGAcquireNodeLocks()
	e := wgDefault.recover()
	unlock()
	if e != nil {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		var pairs []database.WGPair
		if wgDefault.database().Where("status <> ? AND (next_retry_at <= ? OR next_retry_at IS NULL)", "disabled", time.Now()).Order("updated_at ASC, id").Limit(64).Find(&pairs).Error == nil {
			for _, p := range pairs {
				if ctx.Err() != nil {
					return
				}
				unlock = WGAcquireNodeLocks(p.EntryUUID, p.PeerUUID)
				_ = wgDefault.step(ctx, p.ID)
				unlock()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// wgSubscriptionLinks never publishes a persisted-only claim of activation.
// Dependency checks run on each request, independently of reconciler cadence.
func wgSubscriptionLinks(routingType int) []string {
	unlock := WGAcquireNodeLocks()
	defer unlock()
	return wgDefault.subscriptionLinks(routingType)
}
func (c *wgPairCoordinator) subscriptionLinks(routingType int) []string {
	if routingType != 0 && routingType != 1 || c.database() == nil {
		return nil
	}
	var pairs []database.WGPair
	if c.database().Where("status = ? AND enabled = ?", "active", true).Find(&pairs).Error != nil {
		return nil
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].ID < pairs[j].ID })
	var links []string
	for _, p := range pairs {
		if c.confirmed[p.ID] != p.DesiredRevision || p.AppliedRevision != p.DesiredRevision || c.now().Sub(p.HealthCheckedAt) > 30*time.Second || !c.valid(p) {
			continue
		}
		u, e := url.Parse(p.RealityLink)
		if e != nil {
			continue
		}
		var a, b database.NodePool
		if c.database().First(&a, "uuid = ?", p.EntryUUID).Error != nil || c.database().First(&b, "uuid = ?", p.PeerUUID).Error != nil {
			continue
		}
		u.Host = net.JoinHostPort(p.EntryIP, strconv.Itoa(p.EntryPort))
		u.Fragment = a.Name + " → " + b.Name + " [WG]"
		links = append(links, u.String())
	}
	return links
}
