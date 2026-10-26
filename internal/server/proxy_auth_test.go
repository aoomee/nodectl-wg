package server

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"nodectl/internal/database"
	"nodectl/internal/logger"
	"nodectl/internal/middleware"
	"nodectl/internal/requestmeta"
)

func TestLoginCookieTransport(t *testing.T) {
	wgHandlerDB(t)
	if err := requestmeta.Configure("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = requestmeta.Configure("") })
	oldLog := logger.Log
	logger.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Cleanup(func() { logger.Log = oldLog })
	hash, err := bcrypt.GenerateFromPassword([]byte("test-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []database.SysConfig{
		{Key: "admin_username", Value: "test-admin"}, {Key: "admin_password", Value: string(hash)},
		{Key: "jwt_secret", Value: strings.Repeat("test-secret", 8)}, {Key: "tg_bot_enabled", Value: "false"},
	} {
		if err := database.DB.Create(&cfg).Error; err != nil {
			t.Fatal(err)
		}
	}
	// Wait for the disabled notification's read before restoring the test DB.
	notified := make(chan struct{}, 4)
	if err := database.DB.Callback().Query().After("gorm:query").Register("test:login-notification", func(tx *gorm.DB) {
		if strings.Contains(tx.Statement.SQL.String(), "key IN") {
			notified <- struct{}{}
		}
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, url, peer, proto string
		secure                 bool
	}{
		{"native TLS", "https://panel.test/login", "198.51.100.8:123", "", true},
		{"trusted proxy", "http://panel.test/login", "127.0.0.1:123", "https", true},
		{"local HTTP", "http://panel.test/login", "127.0.0.1:123", "", false},
		{"untrusted spoof", "http://panel.test/login", "198.51.100.8:123", "https", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", tc.url, strings.NewReader("username=test-admin&password=test-password"))
			r.RemoteAddr = tc.peer
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("X-Forwarded-Proto", tc.proto)
			w := httptest.NewRecorder()
			loginHandler(w, r)
			select {
			case <-notified:
			case <-time.After(3 * time.Second):
				t.Fatal("notification did not finish")
			}
			cookies := w.Result().Cookies()
			if w.Code != 303 || len(cookies) != 1 || cookies[0].Secure != tc.secure || !cookies[0].HttpOnly {
				t.Fatalf("login status=%d cookies=%v", w.Code, cookies)
			}
		})
	}
}

func TestForgedIPDoesNotResetLoginLimit(t *testing.T) {
	if err := requestmeta.Configure("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = requestmeta.Configure(""); middleware.ClearLoginFailureRecord("198.51.100.8") })
	middleware.ClearLoginFailureRecord("198.51.100.8")
	for _, forged := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"} {
		r := httptest.NewRequest("POST", "http://panel.test/login", nil)
		r.RemoteAddr = "198.51.100.8:123"
		r.Header.Set("X-Real-IP", forged)
		r.Header.Set("X-Forwarded-For", forged)
		middleware.RecordLoginFailure(getClientIP(r))
	}
	if allowed, _, _ := middleware.CheckLoginAttemptAllowed("198.51.100.8"); allowed {
		t.Fatal("forged IP headers bypassed login limit")
	}
}

func TestProxySubscriptionBaseURL(t *testing.T) {
	wgHandlerDB(t)
	if err := requestmeta.Configure("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = requestmeta.Configure("") })
	r := httptest.NewRequest("GET", "http://panel.test:8443/sub/clash", nil)
	r.RemoteAddr = "127.0.0.1:123"
	r.Header.Set("X-Forwarded-Proto", "https")
	if got := getBaseURL(r); got != "https://panel.test:8443" {
		t.Fatal(got)
	}
	r.RemoteAddr = "198.51.100.8:123"
	if got := getBaseURL(r); got != "http://panel.test:8443" {
		t.Fatal(got)
	}
}
