package middleware

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wirearc/internal/logger"
)

func TestMissingCookieRedirectAndWarning(t *testing.T) {
	var output bytes.Buffer
	original := logger.Log
	logger.Log = slog.New(slog.NewTextHandler(&output, nil))
	t.Cleanup(func() { logger.Log = original })
	h := Auth(func(http.ResponseWriter, *http.Request) { t.Fatal("anonymous request reached protected handler") })
	for _, tc := range []struct {
		method, path string
		warn         bool
	}{
		{"GET", "/", false},
		{"HEAD", "/index.html", false},
		{"POST", "/", true},
		{"GET", "/api/auth.json", true},
		{"GET", "/api/get-nodes", true},
	} {
		output.Reset()
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != http.StatusFound || w.Header().Get("Location") != "/login" || strings.Contains(output.String(), "level=WARN") != tc.warn {
			t.Errorf("%s %s: status=%d location=%q log=%q", tc.method, tc.path, w.Code, w.Header().Get("Location"), output.String())
		}
	}
}
