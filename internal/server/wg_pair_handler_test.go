package server

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"nodectl/internal/database"
	"nodectl/internal/requestmeta"
)

func wgHandlerDB(t *testing.T) {
	t.Helper()
	db, e := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if e != nil {
		t.Fatal(e)
	}
	conn, e := db.DB()
	if e != nil {
		t.Fatal(e)
	}
	conn.SetMaxOpenConns(1)
	if e = db.AutoMigrate(&database.NodePool{}, &database.SysConfig{}, &database.AgentIdentity{}, &database.WGPair{}, &database.WGPairNode{}); e != nil {
		t.Fatal(e)
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old; _ = conn.Close() })
	if e = db.Create(&database.NodePool{UUID: "entry", InstallID: "aaaaaaaaaaaa", Name: "Entry", RoutingType: 1, IPV4: "198.51.100.1"}).Error; e != nil {
		t.Fatal(e)
	}
}
func TestWGPairOptionsContract(t *testing.T) {
	wgHandlerDB(t)
	w := httptest.NewRecorder()
	apiWGPairOptions(w, httptest.NewRequest(http.MethodGet, "https://panel.test/api/wg/options?uuid=entry", nil))
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var result struct {
		Status string `json:"status"`
		Data   struct {
			Pair  any   `json:"pair"`
			Peers []any `json:"peers"`
			Ready bool  `json:"ready"`
		} `json:"data"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	if result.Status != "success" || result.Data.Pair != nil || result.Data.Peers == nil || result.Data.Ready {
		t.Fatal(w.Body.String())
	}
}
func TestWGPairHandlerRejectsInvalidRequests(t *testing.T) {
	wgHandlerDB(t)
	tests := []struct {
		method, body string
		tls, header  bool
		origin       string
		code         int
	}{
		{"GET", "", true, true, "", 405},
		{"POST", `{"uuid":"entry","revision":1}`, false, true, "", 400},
		{"POST", `{"uuid":"entry","revision":1}`, true, false, "", 403},
		{"POST", `{"uuid":"entry","revision":1}`, true, true, "https://evil.test", 403},
		{"POST", `{"uuid":"entry","revision":0}`, true, true, "", 400},
		{"POST", `{"uuid":"entry","revision":1,"unknown":true}`, true, true, "", 400},
		{"POST", `{"uuid":"entry","revision":1} {}`, true, true, "", 400},
		{"POST", `{"uuid":"entry","revision":1,"enabled":true,"peer_uuid":"landing"}`, true, true, "", 409},
		{"POST", `{"uuid":"entry","revision":1,"enabled":true,"peer_uuid":"landing","entry_port":-1}`, true, true, "", 400},
		{"POST", `{"uuid":"entry","revision":1,"enabled":true,"peer_uuid":"landing","entry_port":70000}`, true, true, "", 400},
		{"POST", `{"uuid":"entry","revision":1,"enabled":true,"peer_uuid":"landing","entry_port":1443}`, true, true, "", 409},
	}
	for _, tc := range tests {
		t.Run(tc.method+tc.body+tc.origin, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "https://panel.test/api/wg/push", strings.NewReader(tc.body))
			r.TLS = nil
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			r.Header.Set("Content-Type", "application/json")
			if tc.header {
				r.Header.Set("X-NodeCtl-WG", "1")
			}
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			w := httptest.NewRecorder()
			apiWGPairPush(w, r)
			if w.Code != tc.code {
				t.Fatalf("got %d want %d: %s", w.Code, tc.code, w.Body.String())
			}
		})
	}
}
func TestWGPairPushPersistsDisableWithoutCommands(t *testing.T) {
	wgHandlerDB(t)
	if err := requestmeta.Configure("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = requestmeta.Configure("") })
	p := database.WGPair{ID: "1234567890abcdef12345678", EntryUUID: "entry", PeerUUID: "landing", EntryAddress: "10.64.0.2/32", PeerAddress: "10.64.0.3/32", DesiredRevision: 1, AppliedRevision: 1, Enabled: true, Status: "active", Phase: "active", RealityLink: "vless://SECRET"}
	if e := database.DB.Create(&p).Error; e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("POST", "https://panel.test/api/wg/push", strings.NewReader(`{"uuid":"entry","revision":2,"enabled":false}`))
	r.TLS = nil
	r.RemoteAddr = "127.0.0.1:123"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-NodeCtl-WG", "1")
	w := httptest.NewRecorder()
	apiWGPairPush(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"success"`) || strings.Contains(w.Body.String(), "SECRET") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var got database.WGPair
	database.DB.First(&got, "id = ?", p.ID)
	if got.Enabled || got.Status != "cleanup_pending" || got.Phase != "remove_a" || got.DesiredRevision != 2 {
		t.Fatalf("disable not persisted: %+v", got)
	}
}

func TestWGPairV2HandlerExplicitDisable(t *testing.T) {
	wgHandlerDB(t)
	p := database.WGPair{ID: "1234567890abcdef12345678", TopologyVersion: 2, EntryUUID: "entry", PeerUUID: "landing", EntryPort: 8443, EntryWGPort: 23456, PeerWGPort: 45678, EntryAddress: "10.64.0.2/32", PeerAddress: "10.64.0.3/32", DesiredRevision: 1, Status: "disabled", Phase: "blocked"}
	if e := database.DB.Create(&p).Error; e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("POST", "https://panel.test/api/wg/push", strings.NewReader(`{"uuid":"entry","revision":2,"enabled":false}`))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-NodeCtl-WG", "1")
	w := httptest.NewRecorder()
	apiWGPairPush(w, r)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var got database.WGPair
	database.DB.First(&got, "id = ?", p.ID)
	if !got.RestoreDirect || got.Phase != "block_a" || got.Status != "cleanup_pending" {
		t.Fatalf("explicit intent missing: %+v", got)
	}
	for _, field := range []string{`"topology_version":2`, `"source_protocol":"reality"`, `"target_protocol":"ss"`, `"entry_wg_port":23456`, `"peer_wg_port":45678`} {
		if !strings.Contains(w.Body.String(), field) {
			t.Fatalf("missing %s in %s", field, w.Body.String())
		}
	}
}
