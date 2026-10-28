package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"nodectl/internal/database"
	"nodectl/internal/middleware"
)

func TestAdminCredentialChangesAreAtomic(t *testing.T) {
	for _, kind := range []string{"success", "username-only", "weak", "whitespace", "wrong-old", "session-write-failure", "missing-session"} {
		t.Run(kind, func(t *testing.T) {
			wgTestDB(t)
			t.Chdir(t.TempDir())
			oldPassword := "random-initial-password"
			hash, err := bcrypt.GenerateFromPassword([]byte(oldPassword), bcrypt.MinCost)
			if err != nil {
				t.Fatal(err)
			}
			oldSecret := strings.Repeat("s", 64)
			for _, row := range []database.SysConfig{{Key: "admin_username", Value: "admin"}, {Key: "admin_password", Value: string(hash)}, {Key: "jwt_secret", Value: oldSecret}} {
				if err := database.DB.Create(&row).Error; err != nil {
					t.Fatal(err)
				}
			}
			if err := os.MkdirAll("data", 0700); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join("data", database.InitialAdminPasswordFile)
			if err := os.WriteFile(file, []byte(oldPassword+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			newPassword, requestOld := "new-private-password", oldPassword
			switch kind {
			case "username-only":
				newPassword = ""
			case "weak":
				newPassword = "admin"
			case "whitespace":
				newPassword = strings.Repeat(" ", 12)
			case "wrong-old":
				requestOld = "incorrect"
			case "session-write-failure":
				if err := database.DB.Exec(`CREATE TRIGGER reject_session BEFORE UPDATE ON sys_config WHEN NEW.key = 'jwt_secret' BEGIN SELECT RAISE(FAIL, 'test failure'); END`).Error; err != nil {
					t.Fatal(err)
				}
			case "missing-session":
				if err := database.DB.Delete(&database.SysConfig{}, "key = ?", "jwt_secret").Error; err != nil {
					t.Fatal(err)
				}
			}
			body, _ := json.Marshal(map[string]string{"old_username": "admin", "new_username": "renamed-admin", "old_password": requestOld, "new_password": newPassword, "confirm_password": newPassword})
			r := httptest.NewRequest(http.MethodPost, "https://panel.test/api/change-password", strings.NewReader(string(body)))
			w := httptest.NewRecorder()
			apiChangePassword(w, r)
			var result struct{ Status string }
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			var username, password, secret database.SysConfig
			database.DB.First(&username, "key = ?", "admin_username")
			database.DB.First(&password, "key = ?", "admin_password")
			database.DB.First(&secret, "key = ?", "jwt_secret")
			if kind != "success" && kind != "username-only" {
				if result.Status != "error" || username.Value != "admin" || password.Value != string(hash) {
					t.Fatal("failed change persisted credentials", kind, result)
				}
				if kind != "missing-session" && secret.Value != oldSecret {
					t.Fatal("failed change rotated session")
				}
				if _, err := os.Stat(file); err != nil {
					t.Fatal("failed change deleted initial password")
				}
				return
			}
			if result.Status != "success" || username.Value != "renamed-admin" || len(secret.Value) != 64 || secret.Value == oldSecret {
				t.Fatal("change not committed together", result)
			}
			if kind == "success" {
				if bcrypt.CompareHashAndPassword([]byte(password.Value), []byte(newPassword)) != nil {
					t.Fatal("new password unusable")
				}
				if _, err := os.Stat(file); !os.IsNotExist(err) {
					t.Fatal("initial password file not removed")
				}
			} else if password.Value != string(hash) {
				t.Fatal("username-only change reset password")
			}
			// A previously issued cookie can no longer authorize a protected endpoint.
			token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte(oldSecret))
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "https://panel.test/", nil)
			request.AddCookie(&http.Cookie{Name: "nodectl_token", Value: token})
			response := httptest.NewRecorder()
			middleware.Auth(func(http.ResponseWriter, *http.Request) { t.Fatal("old session survived password change") })(response, request)
			if response.Code != http.StatusFound {
				t.Fatal(response.Code)
			}
		})
	}
}
