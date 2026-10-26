package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"nodectl/internal/agent/wgrelay"
	"nodectl/internal/database"
)

type wgFake struct {
	db          *gorm.DB
	calls       []string
	states      map[string]wgrelay.Status
	offline     map[string]bool
	fail        string
	badRevision bool
}

func (f *wgFake) ready(id string) bool { return !f.offline[id] }
func (f *wgFake) send(ctx context.Context, id, action string, v interface{}) (json.RawMessage, error) {
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("unbounded command")
	}
	p := v.(wgrelay.Payload)
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
	case "wg-prepare":
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
	case "wg-activate":
		s.Phase = "active"
		s.ProxyListening = true
		s.TargetTCPVerified = true
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
	link := "vless://11111111-2222-4333-8444-555555555555@198.51.100.2:443?security=reality&type=tcp&sni=example.com&pbk=" + base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("p", 32))) + "&sid=1234&flow=xtls-rprx-vision#secret"
	for _, n := range []database.NodePool{
		{UUID: "entry", InstallID: "aaaaaaaaaaaa", Name: "Entry", RoutingType: 1, IPV4: "198.51.100.1", LinkPorts: map[string]int{"reality": 8443}},
		{UUID: "landing", InstallID: "bbbbbbbbbbbb", Name: "Landing", RoutingType: 2, IPV4: "198.51.100.2", Links: map[string]string{"reality": link}, LinkPorts: map[string]int{"reality": 443}},
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
	p, e := c.save(context.Background(), WGPairPush{UUID: "entry", PeerUUID: "landing", EntryPort: 1443, Revision: 1, Enabled: true})
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
	wgSteps(t, c, p.ID, 7)
	want := []string{"aaaaaaaaaaaa:wg-prepare", "bbbbbbbbbbbb:wg-prepare", "bbbbbbbbbbbb:wg-configure", "aaaaaaaaaaaa:wg-configure", "aaaaaaaaaaaa:wg-verify", "bbbbbbbbbbbb:wg-verify", "aaaaaaaaaaaa:wg-activate"}
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
	if u.Host != "198.51.100.1:1443" || u.User.Username() != "11111111-2222-4333-8444-555555555555" || u.Query().Get("sni") != "example.com" {
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
	if !strings.Contains(string(decoded), "198.51.100.1:1443") {
		t.Fatal("raw integration missing pair")
	}
	yaml, e := GenerateRawNodesYAML(1, false)
	if e != nil || !strings.Contains(yaml, "198.51.100.1") || !strings.Contains(yaml, "1443") {
		t.Fatalf("clash integration %s %v", yaml, e)
	}
	var count int64
	c.db.Model(&database.CustomNode{}).Count(&count)
	if count != 0 {
		t.Fatal("custom nodes mutated")
	}
	var a database.NodePool
	c.db.First(&a, "uuid = ?", "entry")
	if len(a.Links) != 0 {
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
	stages := []string{"aaaaaaaaaaaa:wg-prepare", "bbbbbbbbbbbb:wg-prepare", "bbbbbbbbbbbb:wg-configure", "aaaaaaaaaaaa:wg-configure", "aaaaaaaaaaaa:wg-verify", "bbbbbbbbbbbb:wg-verify", "aaaaaaaaaaaa:wg-activate"}
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
			wgSteps(t, c, p.ID, 2)
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
			if n != 0 {
				t.Fatal("reservations leaked")
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
	if row.Phase != "remove_a" || row.RetryCount != 1 || row.NextRetryAt.IsZero() {
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
	wgSteps(t, c, p.ID, 1)
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
	for stage := 0; stage <= 7; stage++ {
		t.Run(fmt.Sprint(stage), func(t *testing.T) {
			c, _ := newWGTest(t)
			p := createWG(t, c)
			wgSteps(t, c, p.ID, stage)
			if e := c.recover(); e != nil {
				t.Fatal(e)
			}
			wgSteps(t, c, p.ID, 2)
			if wgStored(t, c, p.ID).Status != "disabled" || len(c.subscriptionLinks(0)) != 0 {
				t.Fatal("restart inferred success")
			}
		})
	}
}
func TestWGPairRevisionReservationsAndDisable(t *testing.T) {
	c, _ := newWGTest(t)
	p := createWG(t, c)
	if _, e := c.save(context.Background(), WGPairPush{UUID: "entry", PeerUUID: "landing", EntryPort: 1443, Revision: 1, Enabled: true}); e != nil {
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
	wgSteps(t, c, p.ID, 7)
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
	wgSteps(t, c, p.ID, 2)
	if WGNodeInUse("entry") || WGNodeMutationAllowed("landing") != nil {
		t.Fatal("guard did not release endpoints")
	}
	if _, e := c.save(context.Background(), WGPairPush{UUID: "entry", PeerUUID: "landing", EntryPort: 2443, Revision: 3, Enabled: true}); e != nil {
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
			db.Model(&database.NodePool{}).Where("uuid = ?", "landing").Update("links", `{"reality":"bad"}`)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newWGTest(t)
			p := createWG(t, c)
			wgSteps(t, c, p.ID, 7)
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
	if _, e := c.save(context.Background(), WGPairPush{UUID: "entry", PeerUUID: "landing", EntryPort: 1443, Revision: 1, Enabled: true}); e == nil {
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
