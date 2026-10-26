package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"nodectl/internal/database"
	"nodectl/internal/logger"
	"nodectl/internal/service"
	"nodectl/internal/wgrelay"
)

func wgTestDB(t *testing.T) {
	t.Helper()
	old := database.DB
	oldLog := logger.Log
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "test.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&database.CustomNode{}, &database.NodePool{}, &database.AirportNode{}, &database.SysConfig{}); err != nil {
		t.Fatal(err)
	}
	database.DB = db
	logger.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Cleanup(func() { sql, _ := db.DB(); sql.Close(); database.DB = old; logger.Log = oldLog })
}
func TestWGImportIdempotentAndSubscribed(t *testing.T) {
	wgTestDB(t)
	link := "vless://11111111-1111-4111-8111-111111111111@8.8.8.8:443?security=reality&sni=addons.mozilla.org&pbk=test&sid=1234&type=tcp#A-WG-B"
	first, err := importWGNode(link)
	if err != nil {
		t.Fatal(err)
	}
	second, err := importWGNode(link)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || first.RoutingType != 1 || first.Protocol != "vless" {
		t.Fatal("import not idempotent/active")
	}
	yaml, err := service.GenerateRawNodesYAML(1, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(yaml, "8.8.8.8") || !strings.Contains(yaml, "reality-opts") {
		t.Fatal("WG not in Clash subscription", yaml)
	}
	encoded, err := service.GenerateV2RaySubBase64(false)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || !strings.Contains(string(raw), link) {
		t.Fatal("WG not in V2Ray subscription")
	}
	var n int64
	database.DB.Model(&database.CustomNode{}).Count(&n)
	if n != 1 {
		t.Fatal(n)
	}
}
func TestWGAuthAndCSRF(t *testing.T) {
	wgTestDB(t)
	m, _ := wgrelay.New(t.TempDir(), nil)
	mux := http.NewServeMux()
	registerWGRoutes(mux, m)
	for _, action := range []string{"jobs", "job", "start", "cancel", "import"} {
		req := httptest.NewRequest("GET", "http://panel/api/wg-relay/"+action, nil)
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		if res.Code != http.StatusFound || res.Header().Get("Location") != "/login" {
			t.Fatal("route accessible without login", action, res.Code)
		}
	}
	h := wgHandler(m)
	for _, kind := range []string{"missing-header", "form", "cross-origin", "cross-site"} {
		req := httptest.NewRequest("POST", "http://panel/api/wg-relay/start", strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-NodeCtl-WG", "1")
		switch kind {
		case "missing-header":
			req.Header.Del("X-NodeCtl-WG")
		case "form":
			req.Header.Set("Content-Type", "text/plain")
		case "cross-origin":
			req.Header.Set("Origin", "https://evil.test")
		case "cross-site":
			req.Header.Set("Sec-Fetch-Site", "cross-site")
		}
		res := httptest.NewRecorder()
		h(res, req)
		if res.Code != 403 {
			t.Fatal(kind, res.Code)
		}
	}
}
func TestWGRefusesFailedImport(t *testing.T) {
	m, _ := wgrelay.New(t.TempDir(), func(context.Context, wgrelay.Request, string, io.Writer) (wgrelay.Result, error) {
		return wgrelay.Result{Kind: "check"}, nil
	})
	r := wgrelay.Request{Mode: "check", Architecture: "realm", AIP: "8.8.8.8", BIP: "1.1.1.1", ASSH: 22, BSSH: 22, APort: 443, BPort: 443, AUsername: "root", BUsername: "root", APassword: "secret", BPassword: "secret", SNI: "addons.mozilla.org", MTU: 1280}
	j, err := m.Start(r)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		j, _ = m.Get(j.ID)
		if j.Status == "succeeded" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	b, _ := json.Marshal(map[string]string{"id": j.ID})
	req := httptest.NewRequest("POST", "http://panel/api/wg-relay/import", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NodeCtl-WG", "1")
	res := httptest.NewRecorder()
	wgHandler(m)(res, req)
	if res.Code != 409 {
		t.Fatal(res.Code, res.Body.String())
	}
}
func TestWGTemplatesRender(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err = tmpl.ParseGlob("../../templates/components/*.html")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, "index.html", map[string]any{"Title": "NodeCtl", "Version": "wg-local", "Stats": map[string]int{"Total": 0, "Direct": 0, "Landing": 0, "Blocked": 0}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "WG 中转") || !strings.Contains(b.String(), "/api/wg-relay/") {
		t.Fatal("WG UI not embedded")
	}
}
