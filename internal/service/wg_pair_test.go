package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"nodectl/internal/agent/wgrelay"
	"nodectl/internal/database"
)

type wgFake struct {
	mu             sync.Mutex
	db             *gorm.DB
	calls          []string
	states         map[string]wgrelay.Status
	offline        map[string]bool
	fail           string
	badRevision    bool
	ssPort         int
	ssDigest       string
	badRoute       bool
	secretRequests []wgRouteRequest
}

func (f *wgFake) ready(id string) bool { f.mu.Lock(); defer f.mu.Unlock(); return !f.offline[id] }
func (f *wgFake) send(ctx context.Context, id, action string, v interface{}) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("unbounded command")
	}
	var p wgrelay.Payload
	switch request := v.(type) {
	case wgrelay.Payload:
		p = request
	case wgRouteRequest:
		p = wgrelay.Payload{PairID: request.PairID, Revision: request.Revision}
		f.secretRequests = append(f.secretRequests, request)
		if request.Method != "2022-blake3-aes-128-gcm" || request.Password != "CANONICAL_SECRET" || request.Port != 443 || request.SSDigest != "canonical-ss-digest" || request.ExpectedRealityDigest != "canonical-reality-digest" {
			return nil, errors.New("invalid canonical route payload")
		}
	default:
		return nil, errors.New("unexpected payload")
	}
	var stored database.WGPair
	if f.db.First(&stored, "id = ?", p.PairID).Error != nil {
		return nil, errors.New("command before commit")
	}
	f.calls = append(f.calls, id+":"+action)
	if f.fail == id+":"+action {
		return nil, errors.New("SECRET credential must not escape")
	}
	s := f.states[id]
	s.PairID = p.PairID
	s.Revision = p.Revision
	switch action {
	case "wg-v2-ss":
		port := f.ssPort
		if port == 0 {
			port = 443
		}
		digest := f.ssDigest
		if digest == "" {
			digest = "canonical-ss-digest"
		}
		return json.Marshal(wgCanonicalSS{Method: "2022-blake3-aes-128-gcm", Password: "CANONICAL_SECRET", Port: port, Digest: digest})
	case "wg-v2-guard", "wg-v2-block":
		s.Role = "entry"
		s.Phase = "guarded"
		if action == "wg-v2-block" {
			s.Phase = "blocked"
		}
		s.SourceDigest = "canonical-reality-digest"
		s.RouteActive = false
		s.ProxyListening = false
	case "wg-v2-direct":
		s.Role = "entry"
		s.Phase = "direct"
		s.RouteActive = false
		s.ProxyListening = false
	case "wg-prepare":
		if p.Topology != "reality_ss_v2" {
			return nil, errors.New("wrong topology")
		}
		s.Role = p.Role
		s.PublicKey = base64.StdEncoding.EncodeToString([]byte(strings.Repeat(id[:1], 32)))
		s.Phase = "prepared"
	case "wg-configure":
		s.Phase = "configured"
	case "wg-verify":
		if s.Phase != "active" {
			s.Phase = "verified"
		}
		s.TargetTCPVerified = s.Role == "entry"
	case "wg-v2-route":
		s.Phase = "active"
		s.ProxyListening = false
		s.RouteActive = !f.badRoute
		s.TargetTCPVerified = true
	case "wg-v2-status":
		if f.badRoute {
			s.RouteActive = false
		}
	case "wg-remove":
		s.Phase = "removed"
		s.ProxyListening = false
	}
	f.states[id] = s
	if f.badRevision {
		s.Revision++
	}
	return json.Marshal(s)
}
func newWGTest(t *testing.T) (*wgPairCoordinator, *wgFake) {
	t.Helper()
	db, e := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if e != nil {
		t.Fatal(e)
	}
	sqlDB, e := db.DB()
	if e != nil {
		t.Fatal(e)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if e = db.AutoMigrate(&database.NodePool{}, &database.SysConfig{}, &database.AgentIdentity{}, &database.WGPair{}, &database.WGPairNode{}, &database.AirportNode{}, &database.CustomNode{}); e != nil {
		t.Fatal(e)
	}
	link := "vless://11111111-2222-4333-8444-555555555555@198.51.100.1:8443?security=reality&type=tcp&sni=example.com&pbk=" + base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("p", 32))) + "&sid=1234&flow=xtls-rprx-vision#secret"
	for _, n := range []database.NodePool{
		{UUID: "entry", InstallID: "aaaaaaaaaaaa", Name: "Entry", RoutingType: 1, IPV4: "198.51.100.1", Links: map[string]string{"reality": link}, LinkPorts: map[string]int{"reality": 8443}},
		{UUID: "landing", InstallID: "bbbbbbbbbbbb", Name: "Landing", RoutingType: 2, IPV4: "198.51.100.2", Links: map[string]string{"ss": "ss://PUBLIC_LINK_NOT_CANONICAL_SECRET@198.51.100.2:443#landing"}, LinkPorts: map[string]int{"ss": 443}},
	} {
		if e = db.Create(&n).Error; e != nil {
			t.Fatal(e)
		}
		if e = db.Create(&database.AgentIdentity{NodeUUID: n.UUID, InstallID: n.InstallID, Bound: true, SecretHash: strings.Repeat(n.InstallID[:1], 64)}).Error; e != nil {
			t.Fatal(e)
		}
	}
	f := &wgFake{db: db, states: map[string]wgrelay.Status{}, offline: map[string]bool{}}
	now := time.Now()
	c := &wgPairCoordinator{db: db, ready: f.ready, send: f.send, now: func() time.Time { return now }, timeout: time.Second, confirmed: map[string]uint64{}}
	return c, f
}
func createWG(t *testing.T, c *wgPairCoordinator) WGPairDTO {
	t.Helper()
	p, e := c.save(context.Background(), WGPairPush{UUID: "entry", PeerUUID: "landing", EntryPort: 8443, Revision: 1, Enabled: true})
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func wgSteps(t *testing.T, c *wgPairCoordinator, id string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if e := c.step(context.Background(), id); e != nil {
			t.Fatal(e)
		}
	}
}
func wgStored(t *testing.T, c *wgPairCoordinator, id string) database.WGPair {
	t.Helper()
	var p database.WGPair
	if e := c.db.First(&p, "id = ?", id).Error; e != nil {
		t.Fatal(e)
	}
	return p
}
func TestWGPairHappyPathAndSubscriptions(t *testing.T) {
	c, f := newWGTest(t)
	p := createWG(t, c)
	if len(f.calls) != 0 {
		t.Fatal("save issued commands")
	}
	wgSteps(t, c, p.ID, 8)
	want := []string{"aaaaaaaaaaaa:wg-v2-guard", "bbbbbbbbbbbb:wg-v2-ss", "aaaaaaaaaaaa:wg-prepare", "bbbbbbbbbbbb:wg-prepare", "bbbbbbbbbbbb:wg-configure", "aaaaaaaaaaaa:wg-configure", "aaaaaaaaaaaa:wg-verify", "bbbbbbbbbbbb:wg-verify", "bbbbbbbbbbbb:wg-v2-ss", "aaaaaaaaaaaa:wg-v2-route"}
	if fmt.Sprint(f.calls) != fmt.Sprint(want) {
		t.Fatalf("order %v", f.calls)
	}
	row := wgStored(t, c, p.ID)
	if row.Status != "active" || row.AppliedRevision != 1 {
		t.Fatalf("%+v", wgDTO(row))
	}
	links := c.subscriptionLinks(1)
	if len(links) != 1 {
		t.Fatal(links)
	}
	u, e := url.Parse(links[0])
	if e != nil {
		t.Fatal(e)
	}
	if u.Host != "198.51.100.1:8443" || u.User.Username() != "11111111-2222-4333-8444-555555555555" || u.Query().Get("sni") != "example.com" {
		t.Fatal("credentials/endpoint were corrupted")
	}
	if len(c.subscriptionLinks(2)) != 0 {
		t.Fatal("wrong route")
	}
	oldDB, oldCoordinator := database.DB, wgDefault
	database.DB = c.db
	wgDefault = c
	t.Cleanup(func() { database.DB = oldDB; wgDefault = oldCoordinator })
	raw, e := GenerateV2RaySubBase64(false)
	if e != nil {
		t.Fatal(e)
	}
	decoded, _ := base64.StdEncoding.DecodeString(raw)
	if !strings.Contains(string(decoded), "198.51.100.1:8443") {
		t.Fatal("raw integration missing pair")
	}
	yaml, e := GenerateRawNodesYAML(1, false)
	if e != nil || !strings.Contains(yaml, "198.51.100.1") || !strings.Contains(yaml, "8443") {
		t.Fatalf("clash integration %s %v", yaml, e)
	}
	var count int64
	c.db.Model(&database.CustomNode{}).Count(&count)
	if count != 0 {
		t.Fatal("custom nodes mutated")
	}
	var a database.NodePool
	c.db.First(&a, "uuid = ?", "entry")
	if len(a.Links) != 1 || a.Links["reality"] != links[0] {
		t.Fatal("entry links mutated")
	}
	options, e := c.options("entry")
	if e != nil {
		t.Fatal(e)
	}
	out, _ := json.Marshal(options)
	if strings.Contains(string(out), "vless") || strings.Contains(string(out), "pbk") || strings.Contains(string(out), "secret") {
		t.Fatal("secret exposed")
	}
	out, _ = json.Marshal(row)
	if strings.Contains(string(out), "vless") || strings.Contains(string(out), row.EntryIdentityHash) {
		t.Fatal("model secret exposed")
	}
	f.offline["bbbbbbbbbbbb"] = true
	if len(c.subscriptionLinks(0)) != 0 {
		t.Fatal("offline subscription not filtered immediately")
	}
	wgSteps(t, c, p.ID, 1)
	if wgStored(t, c, p.ID).Status != "cleanup_pending" {
		t.Fatal("offline pair not failed closed")
	}
}
func TestWGPairFailureAtEveryStageAndCleanup(t *testing.T) {
	stages := []string{"aaaaaaaaaaaa:wg-v2-guard", "aaaaaaaaaaaa:wg-prepare", "bbbbbbbbbbbb:wg-prepare", "bbbbbbbbbbbb:wg-configure", "aaaaaaaaaaaa:wg-configure", "aaaaaaaaaaaa:wg-verify", "bbbbbbbbbbbb:wg-verify", "aaaaaaaaaaaa:wg-v2-route"}
	for index, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			c, f := newWGTest(t)
			p := createWG(t, c)
			f.fail = stage
			wgSteps(t, c, p.ID, index+1)
			row := wgStored(t, c, p.ID)
			if row.Status != "cleanup_pending" || strings.Contains(row.Error, "SECRET") {
				t.Fatal(wgDTO(row))
			}
			f.fail = ""
			wgSteps(t, c, p.ID, 3)
			row = wgStored(t, c, p.ID)
			if row.Status != "disabled" || row.RealityLink != "" {
				t.Fatal(wgDTO(row))
			}
			calls := f.calls[len(f.calls)-2:]
			if calls[0] != "aaaaaaaaaaaa:wg-remove" || calls[1] != "bbbbbbbbbbbb:wg-remove" {
				t.Fatal(calls)
			}
			var n int64
			c.db.Model(&database.WGPairNode{}).Count(&n)
			if n != 2 {
				t.Fatal("blocked guard lost reservations")
			}
		})
	}
}
func TestWGPairCleanupOfflineRetryAndRestart(t *testing.T) {
	c, f := newWGTest(t)
	p := createWG(t, c)
	wgSteps(t, c, p.ID, 7)
	if e := c.recover(); e != nil {
		t.Fatal(e)
	}
	if len(c.subscriptionLinks(0)) != 0 {
		t.Fatal("restart falsely published active")
	}
	f.offline["aaaaaaaaaaaa"] = true
	wgSteps(t, c, p.ID, 1)
	row := wgStored(t, c, p.ID)
	if row.Phase != "block_a" || row.RetryCount != 1 || row.NextRetryAt.IsZero() {
		t.Fatal(wgDTO(row))
	}
	before := len(f.calls)
	wgSteps(t, c, p.ID, 1)
	if len(f.calls) != before {
		t.Fatal("ignored backoff")
	}
	var n int64
	c.db.Model(&database.WGPairNode{}).Count(&n)
	if n != 2 {
		t.Fatal("released reservations before cleanup")
	}
	now := row.NextRetryAt.Add(time.Second)
	c.now = func() time.Time { return now }
	f.offline["aaaaaaaaaaaa"] = false
	wgSteps(t, c, p.ID, 2)
	if wgStored(t, c, p.ID).Phase != "remove_b" {
		t.Fatal("entry not cleaned")
	}
	if e := c.recover(); e != nil {
		t.Fatal(e)
	}
	wgSteps(t, c, p.ID, 1)
	if wgStored(t, c, p.ID).Status != "disabled" {
		t.Fatal("restart lost cleanup stage")
	}
}
func TestWGPairRestartEveryStage(t *testing.T) {
	for stage := 0; stage < 8; stage++ {
		t.Run(fmt.Sprint(stage), func(t *testing.T) {
			c, _ := newWGTest(t)
			p := createWG(t, c)
			wgSteps(t, c, p.ID, stage)
			if e := c.recover(); e != nil {
				t.Fatal(e)
			}
			wgSteps(t, c, p.ID, 3)
			if wgStored(t, c, p.ID).Status != "disabled" || len(c.subscriptionLinks(0)) != 0 {
				t.Fatal("restart inferred success")
			}
		})
	}
}
func TestWGPairRevisionReservationsAndDisable(t *testing.T) {
	c, _ := newWGTest(t)
	p := createWG(t, c)
	if _, e := c.save(context.Background(), WGPairPush{UUID: "entry", PeerUUID: "landing", EntryPort: 8443, Revision: 1, Enabled: true}); e != nil {
		t.Fatal("idempotency", e)
	}
	for _, r := range []WGPairPush{
		{UUID: "entry", PeerUUID: "landing", EntryPort: 2443, Revision: 1, Enabled: true},
		{UUID: "entry", PeerUUID: "landing", EntryPort: 2443, Revision: 2, Enabled: true},
		{UUID: "entry", Revision: 0}, {UUID: "entry", Revision: 3},
	} {
		if _, e := c.save(context.Background(), r); e == nil {
			t.Fatal("accepted stale/edit request")
		}
	}
	wgSteps(t, c, p.ID, 8)
	if _, e := c.save(context.Background(), WGPairPush{UUID: "entry", Revision: 2, Enabled: false}); e != nil {
		t.Fatal(e)
	}
	if len(c.subscriptionLinks(0)) != 0 {
		t.Fatal("disable did not filter immediately")
	}
	old := database.DB
	database.DB = c.db
	t.Cleanup(func() { database.DB = old })
	if !WGNodeInUse("landing") || WGNodeMutationAllowed("entry") == nil {
		t.Fatal("guard did not reserve endpoints")
	}
	wgSteps(t, c, p.ID, 4)
	if WGNodeInUse("entry") || WGNodeMutationAllowed("landing") != nil {
		t.Fatal("guard did not release endpoints")
	}
	if _, e := c.save(context.Background(), WGPairPush{UUID: "entry", PeerUUID: "landing", EntryPort: 8443, Revision: 3, Enabled: true}); e != nil {
		t.Fatal("reenable", e)
	}
}
func TestWGPairValidationAndDependencyChanges(t *testing.T) {
	cases := []struct {
		name   string
		change func(*gorm.DB)
	}{
		{"blocked", func(db *gorm.DB) {
			db.Model(&database.NodePool{}).Where("uuid = ?", "landing").Update("is_blocked", true)
		}},
		{"route", func(db *gorm.DB) {
			db.Model(&database.NodePool{}).Where("uuid = ?", "landing").Update("routing_type", 1)
		}},
		{"tunnel", func(db *gorm.DB) {
			db.Model(&database.NodePool{}).Where("uuid = ?", "entry").Update("tunnel_enabled", true)
		}},
		{"ipv4", func(db *gorm.DB) { db.Model(&database.NodePool{}).Where("uuid = ?", "entry").Update("ipv4", "::1") }},
		{"identity", func(db *gorm.DB) {
			db.Model(&database.AgentIdentity{}).Where("node_uuid = ?", "entry").Update("secret_hash", "")
		}},
		{"link", func(db *gorm.DB) {
			db.Model(&database.NodePool{}).Where("uuid = ?", "landing").Update("links", `{"ss":"bad"}`)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newWGTest(t)
			p := createWG(t, c)
			wgSteps(t, c, p.ID, 8)
			tc.change(c.db)
			if len(c.subscriptionLinks(0)) != 0 {
				t.Fatal("stale dependency published")
			}
			wgSteps(t, c, p.ID, 1)
			if wgStored(t, c, p.ID).Status != "cleanup_pending" {
				t.Fatal("not failed closed")
			}
		})
	}
	c, f := newWGTest(t)
	p := createWG(t, c)
	f.badRevision = true
	wgSteps(t, c, p.ID, 1)
	if wgStored(t, c, p.ID).Status != "cleanup_pending" {
		t.Fatal("stale acknowledgement accepted")
	}
}
func TestWGPairCrossRoleUniquenessAndTransactionalSave(t *testing.T) {
	c, _ := newWGTest(t)
	if e := c.db.Create(&database.WGPairNode{NodeUUID: "landing", PairID: "another-pair"}).Error; e != nil {
		t.Fatal(e)
	}
	if _, e := c.save(context.Background(), WGPairPush{UUID: "entry", PeerUUID: "landing", EntryPort: 8443, Revision: 1, Enabled: true}); e == nil {
		t.Fatal("cross-role reserve accepted")
	}
	var n int64
	c.db.Model(&database.WGPair{}).Count(&n)
	if n != 0 {
		t.Fatal("failed transaction left pair")
	}
	c.db.Model(&database.WGPairNode{}).Where("node_uuid = ?", "entry").Count(&n)
	if n != 0 {
		t.Fatal("failed transaction left reservation")
	}
}

func TestWGPairV2CanonicalCredentialsAndPorts(t *testing.T) {
	for _, stage := range []int{1, 7} {
		t.Run(fmt.Sprint(stage), func(t *testing.T) {
			c, f := newWGTest(t)
			p := createWG(t, c)
			wgSteps(t, c, p.ID, stage)
			f.ssPort = 444
			before := len(f.calls)
			wgSteps(t, c, p.ID, 1)
			if wgStored(t, c, p.ID).Status != "cleanup_pending" {
				t.Fatal("canonical port mismatch accepted")
			}
			if fmt.Sprint(f.calls[before:]) != "[bbbbbbbbbbbb:wg-v2-ss]" {
				t.Fatal(f.calls[before:])
			}
			if len(f.secretRequests) != 0 {
				t.Fatal("sent mismatched canonical credentials to A")
			}
		})
	}
	c, f := newWGTest(t)
	p, e := c.save(context.Background(), WGPairPush{UUID: "entry", PeerUUID: "landing", Revision: 1, Enabled: true})
	if e != nil || p.EntryPort != 8443 || p.TopologyVersion != 2 || p.SourceProtocol != "reality" || p.TargetProtocol != "ss" {
		t.Fatalf("%+v %v", p, e)
	}
	wgSteps(t, c, p.ID, 8)
	if len(f.secretRequests) != 1 {
		t.Fatal("route did not receive canonical credentials")
	}
	row := wgStored(t, c, p.ID)
	if row.LinkHash == row.TargetLinkHash || row.RealityDigest != "canonical-reality-digest" {
		t.Fatal("source fingerprints missing")
	}
	// Every persisted value, not only JSON-safe DTO fields, must exclude the SS secret.
	var persisted map[string]interface{}
	if e = c.db.Table("wg_pairs").Where("id = ?", p.ID).Take(&persisted).Error; e != nil {
		t.Fatal(e)
	}
	serialized, _ := json.Marshal(persisted)
	if strings.Contains(string(serialized), "CANONICAL_SECRET") {
		t.Fatal("canonical SS password persisted")
	}
	dto, _ := json.Marshal(p)
	if strings.Contains(string(dto), "CANONICAL_SECRET") {
		t.Fatal("canonical SS password exposed")
	}
}

func TestWGPairV2RejectsWrongEntryPortAndProtocols(t *testing.T) {
	for _, port := range []int{-1, 443, 1443, 65536} {
		c, _ := newWGTest(t)
		if _, e := c.save(context.Background(), WGPairPush{UUID: "entry", PeerUUID: "landing", EntryPort: port, Revision: 1, Enabled: true}); e == nil {
			t.Fatalf("accepted entry port %d", port)
		}
	}
	for _, id := range []string{"entry", "landing"} {
		t.Run(id, func(t *testing.T) {
			c, _ := newWGTest(t)
			proto := "ss"
			if id == "entry" {
				proto = "reality"
			}
			if e := c.db.Model(&database.NodePool{}).Where("uuid = ?", id).Update("disabled_links", `["`+proto+`"]`).Error; e != nil {
				t.Fatal(e)
			}
			if _, e := c.save(context.Background(), WGPairPush{UUID: "entry", PeerUUID: "landing", Revision: 1, Enabled: true}); e == nil {
				t.Fatal("disabled protocol accepted")
			}
			options, e := c.options("entry")
			if e != nil {
				t.Fatal(e)
			}
			if id == "entry" && options.Ready || id == "landing" && len(options.Peers) != 0 {
				t.Fatalf("bad readiness %+v", options)
			}
		})
	}
}

func TestWGPairV2BlockedFailureNeedsExplicitDisable(t *testing.T) {
	c, f := newWGTest(t)
	p := createWG(t, c)
	if c.realitySubscriptionAllowed("entry") {
		t.Fatal("pending pair published ordinary REALITY")
	}
	f.fail = "aaaaaaaaaaaa:wg-v2-guard"
	wgSteps(t, c, p.ID, 1)
	f.fail = ""
	wgSteps(t, c, p.ID, 3)
	row := wgStored(t, c, p.ID)
	if row.Status != "disabled" || row.Phase != "blocked" || row.RestoreDirect || c.realitySubscriptionAllowed("entry") {
		t.Fatalf("automatic failure reopened direct %+v", wgDTO(row))
	}
	for _, call := range f.calls {
		if strings.HasSuffix(call, ":wg-v2-direct") {
			t.Fatal("automatic direct restore")
		}
	}
	if _, e := c.save(context.Background(), WGPairPush{UUID: "entry", Revision: 1}); e == nil {
		t.Fatal("stale disable bypassed revision")
	}
	if _, e := c.save(context.Background(), WGPairPush{UUID: "entry", Revision: 2}); e != nil {
		t.Fatal(e)
	}
	wgSteps(t, c, p.ID, 3)
	row = wgStored(t, c, p.ID)
	if row.Phase != "direct_a" || !row.RestoreDirect || c.realitySubscriptionAllowed("entry") {
		t.Fatal("restored before direct ack")
	}
	// Restart preserves explicit cleanup intent and only retries the current stage.
	if e := c.recover(); e != nil {
		t.Fatal(e)
	}
	f.fail = "aaaaaaaaaaaa:wg-v2-direct"
	wgSteps(t, c, p.ID, 1)
	row = wgStored(t, c, p.ID)
	if row.Status != "cleanup_pending" || c.realitySubscriptionAllowed("entry") {
		t.Fatal("failed direct command published link")
	}
	now := row.NextRetryAt.Add(time.Second)
	c.now = func() time.Time { return now }
	f.fail = ""
	wgSteps(t, c, p.ID, 1)
	if !c.realitySubscriptionAllowed("entry") {
		t.Fatal("explicit acknowledged direct not restored")
	}
	var count int64
	c.db.Model(&database.WGPairNode{}).Count(&count)
	if count != 0 {
		t.Fatal("explicit disable leaked reservations")
	}
}

func TestWGPairV2ActiveHealthAndSourceDrift(t *testing.T) {
	for _, change := range []string{"route", "reality", "ss"} {
		t.Run(change, func(t *testing.T) {
			c, f := newWGTest(t)
			p := createWG(t, c)
			wgSteps(t, c, p.ID, 8)
			before := len(f.calls)
			wgSteps(t, c, p.ID, 1)
			if fmt.Sprint(f.calls[before:]) != "[bbbbbbbbbbbb:wg-v2-ss bbbbbbbbbbbb:wg-verify aaaaaaaaaaaa:wg-v2-status]" {
				t.Fatal(f.calls[before:])
			}
			switch change {
			case "route":
				f.badRoute = true
			case "reality":
				c.db.Model(&database.NodePool{}).Where("uuid = ?", "entry").Update("links", `{"reality":"invalid"}`)
			case "ss":
				c.db.Model(&database.NodePool{}).Where("uuid = ?", "landing").Update("links", `{"ss":"ss://changed-public-link"}`)
			}
			wgSteps(t, c, p.ID, 1)
			if wgStored(t, c, p.ID).Status != "cleanup_pending" || len(c.subscriptionLinks(0)) != 0 || c.realitySubscriptionAllowed("entry") {
				t.Fatal("lost dependency did not fail closed")
			}
		})
	}
}

func TestWGPairV2SubscriptionsExactlyOnce(t *testing.T) {
	c, _ := newWGTest(t)
	oldDB, oldCoordinator := database.DB, wgDefault
	database.DB = c.db
	wgDefault = c
	t.Cleanup(func() { database.DB = oldDB; wgDefault = oldCoordinator })
	p := createWG(t, c)
	check := func(want int) {
		t.Helper()
		raw, e := GenerateV2RaySubBase64(false)
		if e != nil {
			t.Fatal(e)
		}
		decoded, e := base64.StdEncoding.DecodeString(raw)
		if e != nil {
			t.Fatal(e)
		}
		if count := strings.Count(string(decoded), "vless://"); count != want {
			t.Fatalf("REALITY count %d want %d: %s", count, want, decoded)
		}
	}
	check(0)
	wgSteps(t, c, p.ID, 8)
	check(1)
	var a database.NodePool
	c.db.First(&a, "uuid = ?", "entry")
	if links := c.subscriptionLinks(0); len(links) != 1 || links[0] != a.Links["reality"] {
		t.Fatal("did not preserve A original link")
	}
	if _, e := c.save(context.Background(), WGPairPush{UUID: "entry", Revision: 2}); e != nil {
		t.Fatal(e)
	}
	check(0)
	wgSteps(t, c, p.ID, 4)
	check(1)
}

func TestWGPairLegacyCleanupOnly(t *testing.T) {
	for _, version := range []int{0, 1} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			c, f := newWGTest(t)
			p := createWG(t, c)
			if e := c.db.Model(&database.WGPair{}).Where("id = ?", p.ID).Updates(map[string]interface{}{"topology_version": version, "phase": "active", "status": "active", "applied_revision": 1}).Error; e != nil {
				t.Fatal(e)
			}
			c.confirmed[p.ID] = 1
			if len(c.subscriptionLinks(0)) != 0 {
				t.Fatal("legacy pair published")
			}
			c.ready = func(string) bool { return false }
			c.legacyReady = f.ready
			if e := c.recover(); e != nil {
				t.Fatal(e)
			}
			wgSteps(t, c, p.ID, 2)
			row := wgStored(t, c, p.ID)
			if row.TopologyVersion != version || row.Status != "disabled" {
				t.Fatal("legacy migration reinterpreted topology")
			}
			if fmt.Sprint(f.calls) != "[aaaaaaaaaaaa:wg-remove bbbbbbbbbbbb:wg-remove]" {
				t.Fatal(f.calls)
			}
			if _, e := c.save(context.Background(), WGPairPush{UUID: "entry", PeerUUID: "landing", EntryPort: 8443, Revision: 2, Enabled: true}); e == nil {
				t.Fatal("legacy pair reactivated")
			}
			c.ready = f.ready
			if _, e := c.save(context.Background(), WGPairPush{UUID: "entry", Revision: 2, Enabled: false}); e != nil {
				t.Fatal(e)
			}
			migrated, e := c.save(context.Background(), WGPairPush{UUID: "entry", PeerUUID: "landing", EntryPort: 8443, Revision: 3, Enabled: true})
			if e != nil || migrated.TopologyVersion != 2 || migrated.Phase != "guard_a" {
				t.Fatalf("explicit reconfiguration failed: %+v %v", migrated, e)
			}
		})
	}
}
