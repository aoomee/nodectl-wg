package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"nhooyr.io/websocket"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func enrollmentConfig(t *testing.T, panel string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	data, _ := json.Marshal(&Config{InstallID: "aaaaaaaaaaaa", PanelURL: panel})
	if err := os.WriteFile(p, data, 0644); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestEnrollmentPersistsPrivateCredential(t *testing.T) {
	oneTime := strings.Repeat("a", 64)
	permanent := strings.Repeat("b", 64)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/enroll" || r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("unexpected enrollment request")
		}
		var body struct {
			InstallID string `json:"install_id"`
			Token     string `json:"token"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Token != oneTime || body.InstallID != "aaaaaaaaaaaa" {
			t.Error("wrong enrollment identity")
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": permanent})
	}))
	defer srv.Close()
	path := enrollmentConfig(t, srv.URL)
	if err := enrollAgent(context.Background(), path, oneTime, srv.Client()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentToken != permanent {
		t.Fatal("permanent credential missing")
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), oneTime) {
		t.Fatal("enrollment token persisted")
	}
	if err = validateAgentTransport(cfg); err != nil {
		t.Fatal(err)
	}
	if err = SaveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("later save exposed credential")
	}
}
func TestEnrollmentRejectsUntrustedTLSAndRedirects(t *testing.T) {
	token := strings.Repeat("a", 64)
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("followed credential redirect") }))
	defer destination.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 307) }))
	defer srv.Close()
	path := enrollmentConfig(t, srv.URL)
	if err := EnrollAgent(context.Background(), path, token); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if err := enrollAgent(context.Background(), path, token, srv.Client()); err == nil {
		t.Fatal("redirect accepted")
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentToken != "" {
		t.Fatal("failed enrollment altered credentials")
	}
}
func TestAuthenticatedTransportRejectsInsecureAndCrossHostURLs(t *testing.T) {
	token := strings.Repeat("a", 64)
	for _, tc := range []struct{ panel, ws string }{
		{"http://panel.example", "ws://panel.example/api/callback/traffic/ws"},
		{"https://panel.example", "ws://panel.example/api/callback/traffic/ws"},
		{"https://panel.example", "wss://attacker.example/api/callback/traffic/ws"},
		{"https://user:pass@panel.example", "wss://panel.example/api/callback/traffic/ws"},
		{"https://panel.example", "wss://panel.example/api/callback/traffic/ws?token=secret"},
	} {
		cfg := &Config{InstallID: "aaaaaaaaaaaa", AgentToken: token, PanelURL: tc.panel, WSURL: tc.ws}
		if err := validateAgentTransport(cfg); err == nil {
			t.Errorf("insecure transport accepted: %s", tc.ws)
		}
		if err := NewReporter(cfg).Connect(context.Background()); err == nil {
			t.Fatal("reporter dialed insecure transport")
		}
	}
}
func TestReporterSendsAuthenticatedHeadersAndBoundResults(t *testing.T) {
	token := strings.Repeat("a", 64)
	results := make(chan CommandResult, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("X-NodeCtl-Install-ID") != "aaaaaaaaaaaa" || r.Header.Get("X-NodeCtl-Capabilities") != "wg-relay-v1,wg-reality-ss-v2" {
			t.Error("missing authenticated agent headers")
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"nodectl-agent"}})
		if err != nil {
			return
		}
		defer conn.CloseNow()
		data, _ := json.Marshal(ServerCommand{Type: "command", CommandID: "bound-command", Action: "wg-status"})
		if conn.Write(r.Context(), websocket.MessageText, data) != nil {
			return
		}
		_, data, err = conn.Read(r.Context())
		if err != nil {
			return
		}
		var result CommandResult
		if json.Unmarshal(data, &result) == nil {
			results <- result
		}
	}))
	defer srv.Close()
	// Only the fixture CA is trusted, not InsecureSkipVerify or production TOFU.
	oldTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = oldTransport }()
	cfg := &Config{InstallID: "aaaaaaaaaaaa", PanelURL: srv.URL, WSURL: DeriveWSURL(srv.URL), AgentToken: token}
	reporter := NewReporter(cfg)
	reporter.SetCommandHandler(func(cmd ServerCommand, reply func(CommandResult)) {
		reply(CommandResult{Type: "result", Status: "ok", CommandID: "wrong", InstallID: "wrong", Data: json.RawMessage(`{"ready":true}`)})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := reporter.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer reporter.Close()
	select {
	case result := <-results:
		if result.CommandID != "bound-command" || result.InstallID != "aaaaaaaaaaaa" || string(result.Data) != `{"ready":true}` {
			t.Fatalf("incorrect correlation: %+v", result)
		}
	case <-ctx.Done():
		t.Fatal("no command result")
	}
}

func TestEnrollmentRejectsOversizedResponseWithoutEchoingSecrets(t *testing.T) {
	token := strings.Repeat("a", 64)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(strings.Repeat(token, 100))) }))
	defer srv.Close()
	err := enrollAgent(context.Background(), enrollmentConfig(t, srv.URL), token, srv.Client())
	if err == nil || strings.Contains(err.Error(), token) {
		t.Fatal("invalid response leaked secret or succeeded")
	}
}
