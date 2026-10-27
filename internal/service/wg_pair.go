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

// This lock covers local snapshots/commits and parent node mutations only.
// Never hold it while waiting for an Agent. Callers must not nest locks.
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
	TopologyVersion int    `json:"topology_version"`
	SourceProtocol  string `json:"source_protocol"`
	TargetProtocol  string `json:"target_protocol"`
	EntryWGPort     int    `json:"entry_wg_port"`
	PeerWGPort      int    `json:"peer_wg_port"`
	RestoreDirect   bool   `json:"restore_direct"`
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
	UUID      string         `json:"uuid"`
	Name      string         `json:"name"`
	Ready     bool           `json:"ready"`
	Readiness WGReadinessDTO `json:"readiness"`
}
type WGPairOptionsDTO struct {
	Pair      *WGPairDTO     `json:"pair"`
	Peers     []WGPeerDTO    `json:"peers"`
	Ready     bool           `json:"ready"`
	Readiness WGReadinessDTO `json:"readiness"`
}

func wgDTO(p database.WGPair) WGPairDTO {
	out := WGPairDTO{ID: p.ID, UUID: p.EntryUUID, PeerUUID: p.PeerUUID, EntryPort: p.EntryPort, Revision: p.DesiredRevision, AppliedRevision: p.AppliedRevision, Enabled: p.Enabled, Status: p.Status, Phase: p.Phase, Error: p.Error, TopologyVersion: p.TopologyVersion, EntryWGPort: p.EntryWGPort, PeerWGPort: p.PeerWGPort, RestoreDirect: p.RestoreDirect}
	if p.TopologyVersion == 2 {
		out.SourceProtocol = "reality"
		out.TargetProtocol = "ss"
	}
	return out
}

type wgPairCoordinator struct {
	db          *gorm.DB
	ready       func(string) bool
	agentStatus func(string) string
	legacyReady func(string) bool
	send        func(context.Context, string, string, interface{}) (json.RawMessage, error)
	now         func() time.Time
	timeout     time.Duration
	// Proof is process-local: persisted active alone can never publish a link.
	confirmed map[string]uint64
	// Protected by wgNodeMu; only one remote transition per pair may run.
	inflight   map[string]context.CancelFunc
	generation uint64
}

var wgDefault = &wgPairCoordinator{ready: WGAgentV2Ready, agentStatus: WGAgentV2Status, legacyReady: WGAgentReady, send: SendWGCommand, now: time.Now, timeout: 20 * time.Second, confirmed: map[string]uint64{}}

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

// Public SS links are dependency fingerprints only. Credentials must come from
// the authenticated agent's canonical local configuration, never URI parsing.
func wgSS(n database.NodePool) (string, int, error) {
	link := strings.TrimSpace(n.Links["ss"])
	port := n.LinkPorts["ss"]
	if contains(n.DisabledLinks, "ss") || !strings.HasPrefix(link, "ss://") || len(link) <= len("ss://") || port < 1 || port > 65535 {
		return "", 0, ErrWGUnavailable
	}
	return link, port, nil
}
func (c *wgPairCoordinator) identity(db *gorm.DB, n database.NodePool) (string, error) {
	return c.identityState(db, n, true)
}
func (c *wgPairCoordinator) identityState(db *gorm.DB, n database.NodePool, online bool) (string, error) {
	var i database.AgentIdentity
	if db.Where("node_uuid = ? AND install_id = ?", n.UUID, n.InstallID).First(&i).Error != nil || !i.Bound || i.SecretHash == "" || (online && !c.ready(n.InstallID)) {
		return "", ErrWGUnavailable
	}
	return wgHash(i.SecretHash), nil
}
func (c *wgPairCoordinator) dependencies(db *gorm.DB, aID, bID string) (a, b database.NodePool, ah, bh, link string, port int, err error) {
	return c.dependencyState(db, aID, bID, true)
}
func (c *wgPairCoordinator) dependencyState(db *gorm.DB, aID, bID string, online bool) (a, b database.NodePool, ah, bh, link string, port int, err error) {
	err = ErrWGUnavailable
	if aID == bID || db.First(&a, "uuid = ?", aID).Error != nil || db.First(&b, "uuid = ?", bID).Error != nil || !wgNodeEligible(a, "entry") || !wgNodeEligible(b, "landing") || a.InstallID == b.InstallID || a.IPV4 == b.IPV4 {
		return
	}
	ah, err = c.identityState(db, a, online)
	if err != nil {
		return
	}
	bh, err = c.identityState(db, b, online)
	if err != nil {
		return
	}
	if _, _, err = wgReality(a); err != nil {
		return
	}
	link, port, err = wgSS(b)
	return
}
func (c *wgPairCoordinator) valid(p database.WGPair) bool {
	return c.validState(p, true)
}
func (c *wgPairCoordinator) validState(p database.WGPair, online bool) bool {
	var owners int64
	if c.database().Model(&database.WGPairNode{}).Where("pair_id = ? AND node_uuid IN ?", p.ID, []string{p.EntryUUID, p.PeerUUID}).Count(&owners).Error != nil || owners != 2 {
		return false
	}
	a, b, ah, bh, link, port, e := c.dependencyState(c.database(), p.EntryUUID, p.PeerUUID, online)
	source, entryPort, sourceErr := wgReality(a)
	return p.TopologyVersion == 2 && sourceErr == nil && entryPort == p.EntryPort && wgHash(source) == p.LinkHash && e == nil && a.InstallID == p.EntryInstallID && b.InstallID == p.PeerInstallID && a.IPV4 == p.EntryIP && b.IPV4 == p.PeerIP && ah == p.EntryIdentityHash && bh == p.PeerIdentityHash && wgHash(link) == p.TargetLinkHash && port == p.TargetPort
}
func SaveWGPair(ctx context.Context, r WGPairPush) (WGPairDTO, error) {
	return wgDefault.save(ctx, r)
}
func (c *wgPairCoordinator) save(ctx context.Context, r WGPairPush) (WGPairDTO, error) {
	unlock := WGAcquireNodeLocks(r.UUID, r.PeerUUID)
	defer unlock()
	if c.database() == nil || r.UUID == "" || len(r.UUID) > 36 || r.Revision < 1 || r.Revision > 1<<63-1 {
		return WGPairDTO{}, ErrWGConflict
	}
	var p database.WGPair
	changed := false
	err := c.database().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		e := tx.First(&p, "entry_uuid = ?", r.UUID).Error
		exists := e == nil
		if e != nil && !errors.Is(e, gorm.ErrRecordNotFound) {
			return e
		}
		if exists {
			if r.Revision == p.DesiredRevision && r.Enabled == p.Enabled && (r.Enabled || p.TopologyVersion != 2 || p.RestoreDirect) && (!r.Enabled || p.TopologyVersion == 2 && r.PeerUUID == p.PeerUUID && (r.EntryPort == 0 || r.EntryPort == p.EntryPort)) {
				return nil
			}
			if r.Revision != p.DesiredRevision+1 {
				return ErrWGConflict
			}
			if r.Enabled && (p.Status != "disabled" || !p.RestoreDirect) {
				return errors.New("disable pair and finish cleanup before editing")
			}
			if !r.Enabled {
				p.Enabled = false
				p.RestoreDirect = true
				p.DesiredRevision = r.Revision
				if p.Status != "disabled" || p.TopologyVersion == 2 {
					p.Status = "cleanup_pending"
					p.Phase = "remove_a"
					if p.TopologyVersion == 2 {
						p.Phase = "block_a"
					}
				}
				p.NextRetryAt = time.Time{}
				p.RetryCount = 0
				p.Error = ""
				changed = true
				return tx.Save(&p).Error
			}
		} else if !r.Enabled || r.Revision != 1 {
			return ErrWGConflict
		}
		if r.EntryPort < 0 || r.EntryPort > 65535 || r.PeerUUID == "" || len(r.PeerUUID) > 36 {
			return ErrWGConflict
		}
		a, b, ah, bh, link, port, e := c.dependencies(tx, r.UUID, r.PeerUUID)
		if e != nil {
			return e
		}
		source, entryPort, e := wgReality(a)
		if e != nil {
			return e
		}
		if r.EntryPort != 0 && r.EntryPort != entryPort {
			return errors.New("entry port must match existing local REALITY")
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
		p.EntryPort = entryPort
		p.TopologyVersion = 2
		p.RestoreDirect = false
		p.TargetPort = port
		p.RealityLink = source
		p.LinkHash = wgHash(source)
		p.TargetLinkHash = wgHash(link)
		p.DesiredRevision = r.Revision
		p.Enabled = true
		p.Status = "pending"
		p.Phase = "guard_a"
		p.Error = ""
		p.RetryCount = 0
		p.NextRetryAt = time.Time{}
		p.HealthCheckedAt = time.Time{}
		p.RecoveryDeadline = time.Time{}
		p.EntryPublicKey = ""
		p.RealityDigest = ""
		p.SSDigest = ""
		p.PeerPublicKey = ""
		if e = tx.Create(&database.WGPairNode{NodeUUID: a.UUID, PairID: p.ID}).Error; e != nil {
			return ErrWGConflict
		}
		if e = tx.Create(&database.WGPairNode{NodeUUID: b.UUID, PairID: p.ID}).Error; e != nil {
			return ErrWGConflict
		}
		changed = true
		return tx.Save(&p).Error
	})
	if err == nil && changed {
		delete(c.confirmed, p.ID)
		if cancel := c.inflight[p.ID]; cancel != nil {
			cancel()
		}
	}
	return wgDTO(p), err
}
func WGPairOptions(id string) (WGPairOptionsDTO, error) {
	return wgDefault.options(id)
}
func (c *wgPairCoordinator) options(id string) (WGPairOptionsDTO, error) {
	unlock := WGAcquireNodeLocks()
	defer unlock()
	out := WGPairOptionsDTO{Peers: []WGPeerDTO{}}
	db := c.database()
	if db == nil {
		return out, ErrWGUnavailable
	}
	var a database.NodePool
	if db.First(&a, "uuid = ?", id).Error != nil {
		return out, ErrWGUnavailable
	}
	var p database.WGPair
	e := db.First(&p, "entry_uuid = ?", id).Error
	if e == nil {
		dto := wgDTO(p)
		out.Pair = &dto
	} else if !errors.Is(e, gorm.ErrRecordNotFound) {
		return out, e
	}
	role := "entry"
	if a.RoutingType == 2 {
		role = "landing"
	}
	out.Readiness, e = c.nodeReadiness(db, a, role)
	if e != nil {
		return out, e
	}
	out.Ready = role == "entry" && out.Readiness.Ready
	var nodes []database.NodePool
	if e = db.Where("routing_type = ?", 2).Order("name, uuid").Find(&nodes).Error; e != nil {
		return out, e
	}
	for _, b := range nodes {
		if b.UUID == id {
			continue
		}
		var count int64
		if e = db.Model(&database.WGPairNode{}).Where("node_uuid = ? AND pair_id <> ?", b.UUID, p.ID).Count(&count).Error; e != nil {
			return out, e
		}
		readiness, err := c.nodeReadiness(db, b, "landing")
		if err != nil {
			return out, err
		}
		if count != 0 {
			readiness.add("available", "配对占用", false, "已被其他 WG 配对占用，请先在对应入口停用并完成清理。")
		}
		if a.InstallID == b.InstallID || a.IPV4 == b.IPV4 {
			readiness.add("distinct", "双机条件", false, "入口和落地需使用不同的机器身份和 IPv4 地址。")
		}
		out.Peers = append(out.Peers, WGPeerDTO{UUID: b.UUID, Name: b.Name, Ready: readiness.Ready, Readiness: readiness})
	}
	return out, nil
}
func (c *wgPairCoordinator) payload(p database.WGPair, entry bool) wgrelay.Payload {
	v := wgrelay.Payload{PairID: p.ID, Revision: p.DesiredRevision, EntryPort: p.EntryPort, TargetPort: p.TargetPort}
	if p.TopologyVersion == 2 {
		v.Topology = "reality_ss_v2"
	}
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

// Canonical SS credentials have command-local lifetime only. Never persist or
// return this type in an API DTO, log, error, or coordinator state.
type wgCanonicalSS struct {
	Method   string `json:"method"`
	Password string `json:"password"`
	Port     int    `json:"port"`
	Digest   string `json:"digest"`
}
type wgRouteRequest struct {
	PairID                string `json:"pair_id"`
	Revision              uint64 `json:"revision"`
	Method                string `json:"method"`
	Password              string `json:"password"`
	Port                  int    `json:"port"`
	SSDigest              string `json:"ss_digest"`
	ExpectedRealityDigest string `json:"expected_reality_digest"`
}

func (c *wgPairCoordinator) request(ctx context.Context, p database.WGPair, entry bool, action string, payload interface{}) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id := p.PeerInstallID
	if entry {
		id = p.EntryInstallID
	}
	ready := c.ready
	if p.TopologyVersion != 2 && c.legacyReady != nil {
		ready = c.legacyReady
	}
	if ready == nil || !ready(id) {
		return nil, ErrWGUnavailable
	}
	timeout := c.timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, err := c.send(cmdCtx, id, action, payload)
	if err != nil {
		return nil, ErrWGUnavailable
	}
	if err := cmdCtx.Err(); err != nil {
		return nil, err
	}
	return raw, nil
}
func (c *wgPairCoordinator) canonicalSS(ctx context.Context, p database.WGPair) (wgCanonicalSS, error) {
	var secret wgCanonicalSS
	raw, err := c.request(ctx, p, false, "wg-v2-ss", wgrelay.Payload{PairID: p.ID, Revision: p.DesiredRevision})
	if err != nil || json.Unmarshal(raw, &secret) != nil || secret.Method == "" || secret.Password == "" || secret.Port != p.TargetPort || secret.Digest == "" {
		return wgCanonicalSS{}, ErrWGUnavailable
	}
	return secret, nil
}
func (c *wgPairCoordinator) command(ctx context.Context, p database.WGPair, entry bool, action string) (wgrelay.Status, error) {
	var s wgrelay.Status
	payload := c.payload(p, entry)
	if action == "wg-prepare" {
		payload.PeerPublicKey = ""
		payload.PeerEndpoint = ""
		payload.PeerPort = 0
	}
	if action != "wg-prepare" && action != "wg-configure" {
		payload = wgrelay.Payload{PairID: p.ID, Revision: p.DesiredRevision}
	}
	var request interface{} = payload
	if action == "wg-v2-route" {
		secret, err := c.canonicalSS(ctx, p)
		if err != nil {
			return s, err
		}
		if p.SSDigest == "" || secret.Digest != p.SSDigest {
			return s, ErrWGUnavailable
		}
		request = wgRouteRequest{PairID: p.ID, Revision: p.DesiredRevision, Method: secret.Method, Password: secret.Password, Port: secret.Port, SSDigest: secret.Digest, ExpectedRealityDigest: p.RealityDigest}
	}
	raw, err := c.request(ctx, p, entry, action, request)
	if err != nil {
		return s, err
	}
	if json.Unmarshal(raw, &s) != nil || s.PairID != p.ID || s.Revision != p.DesiredRevision {
		return s, ErrWGUnavailable
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
	case "wg-v2-guard", "wg-v2-block":
		if (s.Phase != "guarded" && s.Phase != "blocked") || s.RouteActive || s.ProxyListening {
			return s, ErrWGUnavailable
		}
	case "wg-v2-direct":
		if s.Phase != "direct" || s.RouteActive || s.ProxyListening {
			return s, ErrWGUnavailable
		}
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
	case "wg-v2-route", "wg-v2-status":
		if s.Phase != "active" || !s.RouteActive || !s.TargetTCPVerified || s.ProxyListening || p.RealityDigest == "" || s.SourceDigest != p.RealityDigest {
			return s, ErrWGUnavailable
		}
	case "wg-status":
		if entry || s.Phase != "verified" || s.ProxyListening {
			return s, ErrWGUnavailable
		}
	default:
		return s, ErrWGUnavailable
	}
	return s, nil
}

const (
	wgStepTimeout    = 20 * time.Second
	wgRecoveryWindow = 30 * time.Second
	wgHealthInterval = 10 * time.Second
	wgWorkerCount    = 8
)

// failWG changes only a work snapshot; persistence requires the revision fence.
func failWG(p *database.WGPair) {
	p.Status = "cleanup_pending"
	p.Phase = "remove_a"
	if p.TopologyVersion == 2 {
		p.Phase = "block_a"
	}
	p.RestoreDirect = false
	p.Error = "WireGuard operation or dependency failed; cleanup required"
	p.NextRetryAt = time.Time{}
	p.RecoveryDeadline = time.Time{}
	p.RetryCount = 0
}

// advanceCleanup issues one command and mutates only its private snapshot.
func (c *wgPairCoordinator) advanceCleanup(ctx context.Context, p *database.WGPair) {
	entry, action := true, "wg-remove"
	switch p.Phase {
	case "block_a":
		action = "wg-v2-block"
	case "remove_a":
	case "remove_b":
		entry = false
	case "direct_a":
		if p.TopologyVersion != 2 || !p.RestoreDirect {
			failWG(p)
			return
		}
		action = "wg-v2-direct"
	default:
		failWG(p)
		return
	}
	if _, err := c.command(ctx, *p, entry, action); err != nil {
		p.RetryCount++
		p.NextRetryAt = c.now().Add(time.Second << min(p.RetryCount, 6))
		p.Error = "cleanup pending; authenticated agent acknowledgement required"
		return
	}
	p.RetryCount = 0
	p.NextRetryAt = time.Time{}
	switch p.Phase {
	case "block_a":
		p.Phase = "remove_a"
		return
	case "remove_a":
		p.Phase = "remove_b"
		return
	case "remove_b":
		if p.TopologyVersion == 2 && p.RestoreDirect {
			p.Phase = "direct_a"
			return
		}
	}
	p.Status = "disabled"
	p.Phase = "disabled"
	p.Enabled = false
	p.RealityLink = ""
	if p.TopologyVersion == 2 && !p.RestoreDirect {
		p.Phase = "blocked"
		p.Error = "REALITY remains blocked; explicitly disable to restore direct routing"
	} else {
		p.Error = ""
	}
}

// checkActive verifies the landing first and renews A only after its dependencies
// pass. It never sends activation, direct-routing, or configuration commands.
func (c *wgPairCoordinator) checkActive(ctx context.Context, p database.WGPair) error {
	if p.DesiredRevision == 0 || p.AppliedRevision != p.DesiredRevision || p.RealityDigest == "" {
		return ErrWGUnavailable
	}
	secret, err := c.canonicalSS(ctx, p)
	if err != nil || p.SSDigest == "" || secret.Digest != p.SSDigest {
		return ErrWGUnavailable
	}
	landing, err := c.command(ctx, p, false, "wg-verify")
	if err != nil || p.PeerPublicKey == "" || landing.PublicKey != p.PeerPublicKey {
		return ErrWGUnavailable
	}
	_, err = c.command(ctx, p, true, "wg-v2-status")
	return err
}

func (c *wgPairCoordinator) advance(ctx context.Context, p *database.WGPair) {
	if p.Status == "cleanup_pending" {
		c.advanceCleanup(ctx, p)
		return
	}
	if p.Status == "active" || p.Status == "recovering" {
		if err := c.checkActive(ctx, *p); err != nil {
			failWG(p)
			return
		}
		p.Status, p.Phase, p.Error = "active", "active", ""
		p.HealthCheckedAt = c.now()
		p.RecoveryDeadline = time.Time{}
		p.NextRetryAt = time.Time{}
		return
	}
	stages := map[string]struct {
		entry        bool
		action, next string
	}{
		"guard_a":   {true, "wg-v2-guard", "prepare_a"},
		"prepare_a": {true, "wg-prepare", "prepare_b"}, "prepare_b": {false, "wg-prepare", "configure_b"},
		"configure_b": {false, "wg-configure", "configure_a"}, "configure_a": {true, "wg-configure", "verify_a"},
		"verify_a": {true, "wg-verify", "verify_b"}, "verify_b": {false, "wg-verify", "activate_a"}, "activate_a": {true, "wg-v2-route", "active"},
	}
	stage, ok := stages[p.Phase]
	if !ok {
		failWG(p)
		return
	}
	if p.Phase == "prepare_a" {
		secret, err := c.canonicalSS(ctx, *p)
		if err != nil {
			failWG(p)
			return
		}
		p.SSDigest = secret.Digest
	}
	result, err := c.command(ctx, *p, stage.entry, stage.action)
	if err != nil {
		failWG(p)
		return
	}
	if stage.action == "wg-v2-guard" {
		if result.SourceDigest == "" {
			failWG(p)
			return
		}
		p.RealityDigest = result.SourceDigest
	}
	if stage.action == "wg-prepare" {
		if stage.entry {
			p.EntryPublicKey = result.PublicKey
		} else {
			p.PeerPublicKey = result.PublicKey
			if p.PeerPublicKey == p.EntryPublicKey {
				failWG(p)
				return
			}
		}
	}
	p.Phase, p.Status = stage.next, "pending"
	if p.Phase == "active" {
		p.Status = "active"
		p.AppliedRevision = p.DesiredRevision
		p.HealthCheckedAt = c.now()
	}
}

// step snapshots under the node lock, runs all remote I/O outside it, and then
// commits only if the user's intent and coordinator generation still match.
func (c *wgPairCoordinator) step(parent context.Context, id string) error {
	if err := parent.Err(); err != nil {
		return err
	}
	wgNodeMu.Lock()
	if c.inflight[id] != nil {
		wgNodeMu.Unlock()
		return nil
	}
	db := c.database()
	var before database.WGPair
	if db == nil {
		wgNodeMu.Unlock()
		return ErrWGUnavailable
	}
	if err := db.WithContext(parent).First(&before, "id = ?", id).Error; err != nil {
		wgNodeMu.Unlock()
		return err
	}
	if before.Status == "disabled" || c.now().Before(before.NextRetryAt) {
		wgNodeMu.Unlock()
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, wgStepTimeout)
	if c.inflight == nil {
		c.inflight = make(map[string]context.CancelFunc)
	}
	c.inflight[id] = cancel
	generation := c.generation
	next := before
	skipRemote := false
	if next.Status != "cleanup_pending" {
		if next.TopologyVersion != 2 || !next.Enabled || next.RestoreDirect || !c.validState(next, false) {
			failWG(&next)
			skipRemote = true
		} else if next.Status == "recovering" && (next.RecoveryDeadline.IsZero() || !c.now().Before(next.RecoveryDeadline)) {
			failWG(&next)
			skipRemote = true
		} else if !c.valid(next) {
			if next.Status == "recovering" {
				next.NextRetryAt = c.now().Add(time.Second)
				next.Error = "waiting for authenticated agents after panel restart"
			} else {
				failWG(&next)
			}
			skipRemote = true
		}
	}
	wgNodeMu.Unlock()
	defer func() { cancel(); wgNodeMu.Lock(); delete(c.inflight, id); wgNodeMu.Unlock() }()
	if !skipRemote {
		c.advance(ctx, &next)
	}
	wgNodeMu.Lock()
	defer wgNodeMu.Unlock()
	if err := parent.Err(); err != nil {
		return err
	}
	if generation != c.generation || db != c.database() {
		return ErrWGConflict
	}
	var current database.WGPair
	if err := db.First(&current, "id = ?", id).Error; err != nil {
		return err
	}
	if current.DesiredRevision != before.DesiredRevision || current.Status != before.Status || current.Phase != before.Phase || current.Enabled != before.Enabled || current.RestoreDirect != before.RestoreDirect || !current.UpdatedAt.Equal(before.UpdatedAt) {
		return ErrWGConflict
	}
	// Revocation or protocol drift during the remote command invalidates success.
	if next.Status == "active" || next.Status == "pending" {
		if ctx.Err() != nil || !c.valid(next) {
			failWG(&next)
		}
	}
	if before.Status == "recovering" && next.Status == "active" && !c.now().Before(before.RecoveryDeadline) {
		failWG(&next)
	}
	// Shutdown can arrive during dependency checks, after the earlier fence.
	// It must not turn a cancelled worker into a persisted failure transition.
	if err := parent.Err(); err != nil {
		return err
	}
	err := db.WithContext(parent).Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(&next).Error; err != nil {
			return err
		}
		if next.Status == "disabled" && (next.TopologyVersion != 2 || next.RestoreDirect) {
			return tx.Where("pair_id = ?", id).Delete(&database.WGPairNode{}).Error
		}
		return nil
	})
	if err != nil {
		delete(c.confirmed, id)
		return err
	}
	if next.Status == "active" {
		if c.confirmed == nil {
			c.confirmed = make(map[string]uint64)
		}
		c.confirmed[id] = next.DesiredRevision
	} else {
		delete(c.confirmed, id)
	}
	return nil
}

func (c *wgPairCoordinator) recover() error {
	wgNodeMu.Lock()
	defer wgNodeMu.Unlock()
	c.generation++
	for _, cancel := range c.inflight {
		cancel()
	}
	c.confirmed = make(map[string]uint64)
	return c.database().Transaction(func(tx *gorm.DB) error {
		// Only fully acknowledged v2 pairs are candidates for a live status check.
		// Recovery never replays an activation command or trusts persisted active.
		if err := tx.Model(&database.WGPair{}).Where("topology_version = ? AND status = ? AND enabled = ? AND restore_direct = ? AND applied_revision = desired_revision AND reality_digest <> '' AND ss_digest <> '' AND peer_public_key <> ''", 2, "active", true, false).
			Updates(map[string]interface{}{"status": "recovering", "phase": "verify_active", "recovery_deadline": c.now().Add(wgRecoveryWindow), "health_checked_at": time.Time{}, "next_retry_at": time.Time{}, "error": "verifying active agents after panel restart"}).Error; err != nil {
			return err
		}
		// Do not extend an already-persisted recovery deadline on repeated restarts.
		for _, v2 := range []bool{false, true} {
			query := tx.Model(&database.WGPair{}).Where("status NOT IN ?", []string{"disabled", "cleanup_pending"})
			phase := "remove_a"
			if v2 {
				phase = "block_a"
				query = query.Where("topology_version = ? AND status <> ?", 2, "recovering")
			} else {
				query = query.Where("topology_version <> ? OR topology_version IS NULL", 2)
			}
			if err := query.Updates(map[string]interface{}{"status": "cleanup_pending", "phase": phase, "restore_direct": false, "error": "coordinator restarted during an incomplete operation; cleanup required", "next_retry_at": time.Time{}}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

var wgReconcilerMu sync.Mutex

// StartWGPairReconciler runs a bounded dispatcher. Slow/offline pairs occupy only
// their own worker; there is no network I/O under the global node lock.
func StartWGPairReconciler(ctx context.Context) {
	wgReconcilerMu.Lock()
	defer wgReconcilerMu.Unlock()
	if ctx.Err() != nil || wgDefault.database() == nil {
		return
	}
	if err := wgDefault.recover(); err != nil {
		return
	}
	wgDefault.run(ctx, time.Second, wgWorkerCount)
}

func (c *wgPairCoordinator) run(ctx context.Context, interval time.Duration, workers int) {
	if workers < 1 {
		workers = 1
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	running := make(map[string]bool)
	done := make(chan string, workers)
	var group sync.WaitGroup
	defer group.Wait()
	dispatch := func() {
		capacity := workers - len(running)
		if capacity == 0 || ctx.Err() != nil {
			return
		}
		ids := make([]string, 0, len(running))
		for id := range running {
			ids = append(ids, id)
		}
		var pairs []database.WGPair
		query := c.database().WithContext(ctx).Where("status <> ? AND (next_retry_at <= ? OR next_retry_at IS NULL)", "disabled", c.now()).
			Where("status <> ? OR health_checked_at <= ? OR health_checked_at IS NULL", "active", c.now().Add(-wgHealthInterval))
		if len(ids) > 0 {
			query = query.Where("id NOT IN ?", ids)
		}
		// Oldest due work first; active checks are cooled down after successful renewal.
		if query.Order("updated_at ASC, id").Limit(capacity).Find(&pairs).Error != nil {
			return
		}
		for _, p := range pairs {
			id := p.ID
			running[id] = true
			group.Add(1)
			go func() { defer group.Done(); _ = c.step(ctx, id); done <- id }()
		}
	}
	dispatch()
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-done:
			delete(running, id)
		case <-ticker.C:
			dispatch()
		}
	}
}

// wgSubscriptionLinks never publishes a persisted-only claim of activation.
// Dependency checks run on each request, independently of reconciler cadence.
func wgSubscriptionLinks(routingType int) []string {
	return wgDefault.subscriptionLinks(routingType)
}
func (c *wgPairCoordinator) subscriptionLinks(routingType int) []string {
	unlock := WGAcquireNodeLocks()
	defer unlock()
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
		// Publish the original A REALITY link, never B credentials or a new listener.
		links = append(links, p.RealityLink)
	}
	return links
}

// WGRealitySubscriptionAllowed fences ordinary REALITY publication whenever a
// pair owns A. Active v2 links are emitted once by subscriptionLinks instead.
func WGRealitySubscriptionAllowed(id string) bool {
	return wgDefault.realitySubscriptionAllowed(id)
}
func (c *wgPairCoordinator) realitySubscriptionAllowed(id string) bool {
	unlock := WGAcquireNodeLocks()
	defer unlock()
	if c.database() == nil {
		return false
	}
	var p database.WGPair
	err := c.database().First(&p, "entry_uuid = ?", id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return true
	}
	if err != nil {
		return false
	}
	return p.Status == "disabled" && (p.TopologyVersion != 2 || p.RestoreDirect)
}
