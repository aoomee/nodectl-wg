package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
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
