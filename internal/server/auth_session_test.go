package server

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"nodectl/internal/database"
	"nodectl/internal/middleware"
)

func seedSessionTest(t *testing.T) string {
	t.Helper()
	wgTestDB(t)
	t.Chdir(t.TempDir())
	oldTemplate := tmpl
	tmpl = template.Must(template.New("login.html").Parse(`{{.Error}}`))
	t.Cleanup(func() { tmpl = oldTemplate })
	secret := strings.Repeat("s", 64)
	hash, err := bcrypt.GenerateFromPassword([]byte("old-password-value"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []database.SysConfig{{Key: "admin_username", Value: "admin"}, {Key: "admin_password", Value: string(hash)}, {Key: "jwt_secret", Value: secret}, {Key: "tg_bot_enabled", Value: "false"}} {
		if err := database.DB.Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
	middleware.ClearLoginFailureRecord("192.0.2.9")
	t.Cleanup(func() { middleware.ClearLoginFailureRecord("192.0.2.9") })
	return secret
}

func sessionToken(t *testing.T, secret string) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"username": "admin", "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func sessionAccepted(token string) bool {
	accepted := false
	r := httptest.NewRequest(http.MethodGet, "https://panel.test/", nil)
	r.AddCookie(&http.Cookie{Name: "nodectl_token", Value: token})
	middleware.Auth(func(http.ResponseWriter, *http.Request) { accepted = true })(httptest.NewRecorder(), r)
	return accepted
}

func TestResetSessionReportsPersistenceFailure(t *testing.T) {
	for _, kind := range []string{"success", "write-failed", "missing", "wrong-method"} {
		t.Run(kind, func(t *testing.T) {
			secret := seedSessionTest(t)
			token := sessionToken(t, secret)
			method := http.MethodPost
			switch kind {
			case "write-failed":
				if err := database.DB.Exec(`CREATE TRIGGER reject_session BEFORE UPDATE ON sys_config WHEN NEW.key='jwt_secret' BEGIN SELECT RAISE(FAIL,'test failure'); END`).Error; err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := database.DB.Delete(&database.SysConfig{}, "key = ?", "jwt_secret").Error; err != nil {
					t.Fatal(err)
				}
			case "wrong-method":
				method = http.MethodGet
			}
			w := httptest.NewRecorder()
			apiResetJWT(w, httptest.NewRequest(method, "https://panel.test/api/reset-jwt", nil))
			if kind == "wrong-method" {
				if w.Code != http.StatusMethodNotAllowed || !sessionAccepted(token) {
					t.Fatal("GET changed sessions")
				}
				return
			}
			var result struct{ Status string }
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if kind == "success" {
				if result.Status != "success" || sessionAccepted(token) {
					t.Fatal("successful reset did not revoke old session")
				}
				var row database.SysConfig
				if err := database.DB.First(&row, "key = ?", "jwt_secret").Error; err != nil {
					t.Fatal(err)
				}
				if len(row.Value) != 64 || row.Value == secret || len(w.Result().Cookies()) != 1 {
					t.Fatal("reset did not persist and expire cookie")
				}
			} else {
				if result.Status != "error" || len(w.Result().Cookies()) != 0 {
					t.Fatal("failed reset reported success or logged out current browser")
				}
				if kind == "write-failed" && !sessionAccepted(token) {
					t.Fatal("failed reset changed sessions")
				}
			}
		})
	}
}

func TestLoginRejectsBrokenCredentials(t *testing.T) {
	for _, kind := range []string{"missing-key", "empty-key", "blank-key", "missing-password", "bad-password-record", "missing-user", "read-failed"} {
		t.Run(kind, func(t *testing.T) {
			seedSessionTest(t)
			var err error
			switch kind {
			case "missing-key":
				err = database.DB.Delete(&database.SysConfig{}, "key = ?", "jwt_secret").Error
			case "empty-key":
				err = database.DB.Model(&database.SysConfig{}).Where("key = ?", "jwt_secret").Update("value", "").Error
			case "blank-key":
				err = database.DB.Model(&database.SysConfig{}).Where("key = ?", "jwt_secret").Update("value", "   ").Error
			case "missing-password":
				err = database.DB.Delete(&database.SysConfig{}, "key = ?", "admin_password").Error
			case "bad-password-record":
				err = database.DB.Model(&database.SysConfig{}).Where("key = ?", "admin_password").Update("value", "broken").Error
			case "missing-user":
				err = database.DB.Delete(&database.SysConfig{}, "key = ?", "admin_username").Error
			case "read-failed":
				err = database.DB.Migrator().DropTable(&database.SysConfig{})
			}
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "https://panel.test/login", strings.NewReader("username=admin&password=old-password-value"))
			r.RemoteAddr = "192.0.2.9:123"
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			loginHandler(w, r)
			if w.Code != http.StatusServiceUnavailable || len(w.Result().Cookies()) != 0 {
				t.Fatal("broken credentials issued a session")
			}
			if sessionAccepted(sessionToken(t, "")) || sessionAccepted(sessionToken(t, "   ")) {
				t.Fatal("empty session key authorized a request")
			}
			if allowed, _, _ := middleware.CheckLoginAttemptAllowed("192.0.2.9"); !allowed {
				t.Fatal("storage failure consumed login attempts")
			}
		})
	}
}

func TestConcurrentRotationCannotIssueSessionWithOldPasswordAndNewKey(t *testing.T) {
	oldSecret := seedSessionTest(t)
	newSecret := strings.Repeat("n", 64)
	newHash, err := bcrypt.GenerateFromPassword([]byte("new-password-value"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	rotated := false
	notified := make(chan struct{}, 1)
	if err := database.DB.Callback().Query().After("gorm:query").Register("test:credential-rotation", func(tx *gorm.DB) {
		for _, value := range tx.Statement.Vars {
			key, ok := value.(string)
			if !ok {
				continue
			}
			if key == "tg_bot_enabled" {
				notified <- struct{}{}
				return
			}
			if key != "admin_password" || rotated {
				continue
			}
			rotated = true
			// Commit a change after the password was read but before login signs.
			if err := database.DB.Transaction(func(update *gorm.DB) error {
				if err := update.Model(&database.SysConfig{}).Where("key = ?", "admin_password").Update("value", string(newHash)).Error; err != nil {
					return err
				}
				return update.Model(&database.SysConfig{}).Where("key = ?", "jwt_secret").Update("value", newSecret).Error
			}); err != nil {
				t.Fatal(err)
			}
			return
		}
	}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "https://panel.test/login", strings.NewReader("username=admin&password=old-password-value"))
	r.RemoteAddr = "192.0.2.9:123"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	loginHandler(w, r)
	select {
	case <-notified:
	case <-time.After(3 * time.Second):
		t.Fatal("login notification unfinished")
	}
	if !rotated || len(w.Result().Cookies()) != 1 {
		t.Fatal("rotation scenario did not execute")
	}
	token := w.Result().Cookies()[0].Value
	if _, err := jwt.Parse(token, func(*jwt.Token) (interface{}, error) { return []byte(oldSecret), nil }); err != nil {
		t.Fatal("login mixed credential versions")
	}
	if sessionAccepted(token) {
		t.Fatal("old-password login survived concurrent rotation")
	}
}
