package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"nodectl/internal/requestmeta"
	"strings"
	"testing"
)

func TestAgentIdentityHandlersRejectInsecureAndMalformedRequests(t *testing.T) {
	for _, handler := range []struct {
		name  string
		fn    http.HandlerFunc
		admin bool
	}{{"enroll", apiAgentEnroll, false}, {"issue", apiNodeAgentEnrollment, true}, {"revoke", apiNodeAgentRevoke, true}} {
		for _, tc := range []struct {
			name, method, body string
			secure             bool
			status             int
		}{
			{"plaintext", "POST", `{}`, false, 400},
			{"wrong method", "GET", `{}`, true, 405},
			{"oversized", "POST", `{"token":"` + strings.Repeat("SECRET", 900) + `"}`, true, 400},
			{"unknown field", "POST", `{"secret_field":"SECRET"}`, true, 400},
			{"trailing object", "POST", `{} {}`, true, 400},
		} {
			t.Run(handler.name+"/"+tc.name, func(t *testing.T) {
				r := httptest.NewRequest(tc.method, "https://panel.example/api/agent/enroll", strings.NewReader(tc.body))
				r.TLS = nil
				if tc.secure {
					r.TLS = &tls.ConnectionState{}
				}
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-NodeCtl-WG", "1")
				r.Header.Set("X-Forwarded-Proto", "https")
				w := httptest.NewRecorder()
				handler.fn(w, r)
				if w.Code != tc.status {
					t.Fatalf("status=%d, body=%s", w.Code, w.Body.String())
				}
				if strings.Contains(w.Body.String(), "SECRET") {
					t.Fatal("error echoed request secret")
				}
				if w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("credential response cacheable")
				}
			})
		}
	}
}

func TestAgentIdentityTrustedProxyGuard(t *testing.T) {
	if err := requestmeta.Configure("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = requestmeta.Configure("") })
	for _, tc := range []struct {
		name, peer, proto, origin string
		status                    int
	}{
		{"HTTPS proxy", "127.0.0.1:123", "https", "https://panel.example", 200},
		{"public header spoof", "198.51.100.1:123", "https", "https://panel.example", 400},
		{"HTTP client", "127.0.0.1:123", "http", "http://panel.example", 400},
		{"cross origin", "127.0.0.1:123", "https", "https://other.example", 403},
		{"HTTP origin", "127.0.0.1:123", "https", "http://panel.example", 403},
		{"ambiguous scheme", "127.0.0.1:123", "https,http", "https://panel.example", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://panel.example/api/node/wg/push", strings.NewReader(`{}`))
			r.RemoteAddr = tc.peer
			r.Header.Set("X-Forwarded-Proto", tc.proto)
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-NodeCtl-WG", "1")
			w := httptest.NewRecorder()
			var body struct{}
			accepted := agentIdentityRequest(w, r, true, &body)
			if w.Code != tc.status || accepted != (tc.status == 200) {
				t.Fatalf("accepted=%v status=%d body=%s", accepted, w.Code, w.Body.String())
			}
		})
	}
}

func TestEnrollmentTokenIssuedThroughTrustedProxy(t *testing.T) {
	wgHandlerDB(t)
	if err := requestmeta.Configure("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = requestmeta.Configure("") })
	r := httptest.NewRequest("POST", "http://panel.example/api/node/agent/enrollment", strings.NewReader(`{"node_uuid":"entry","rotate":false}`))
	r.RemoteAddr = "127.0.0.1:123"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Origin", "https://panel.example")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-NodeCtl-WG", "1")
	w := httptest.NewRecorder()
	apiNodeAgentEnrollment(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"token":`) {
		t.Fatalf("enrollment failed: %d %s", w.Code, w.Body.String())
	}
}
func TestAgentIdentityAdminOriginGuard(t *testing.T) {
	for _, origin := range []string{"https://attacker.example", "http://panel.example"} {
		r := httptest.NewRequest("POST", "https://panel.example/api/node/agent/enrollment", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-NodeCtl-WG", "1")
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		apiNodeAgentEnrollment(w, r)
		if w.Code != 403 {
			t.Fatalf("origin accepted: %s", origin)
		}
	}
	r := httptest.NewRequest("POST", "https://panel.example/api/node/agent/enrollment", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	apiNodeAgentEnrollment(w, r)
	if w.Code != 403 {
		t.Fatal("missing custom header accepted")
	}
}
