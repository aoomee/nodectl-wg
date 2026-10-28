package database

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func bootstrapDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "auth.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&SysConfig{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqlDB, _ := db.DB(); _ = sqlDB.Close() })
	return db
}
func authValue(t *testing.T, db *gorm.DB, key string) string {
	t.Helper()
	var row SysConfig
	if err := db.First(&row, "key = ?", key).Error; err != nil {
		t.Fatal(err)
	}
	return row.Value
}

func TestBootstrapRandomPasswordAndRestart(t *testing.T) {
	db, dir := bootstrapDB(t), t.TempDir()
	created, err := initializeAuth(db, dir, "")
	if err != nil || !created {
		t.Fatal(created, err)
	}
	path := filepath.Join(dir, InitialAdminPasswordFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	password := strings.TrimSuffix(string(data), "\n")
	if len(password) != 32 || ValidateAdminPassword(password) != nil {
		t.Fatal("invalid generated password")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("password permissions=%v", info.Mode())
	}
	hash := authValue(t, db, "admin_password")
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte("admin")) == nil {
		t.Fatal("password hash does not match the private file")
	}
	jwt := authValue(t, db, "jwt_secret")
	if len(jwt) != 64 {
		t.Fatal("invalid session key")
	}
	created, err = initializeAuth(db, dir, "ignored-invalid-override")
	if created || err != nil || authValue(t, db, "admin_password") != hash || authValue(t, db, "jwt_secret") != jwt {
		t.Fatal("restart reset credentials", err)
	}
	again, _ := os.ReadFile(path)
	if string(again) != string(data) {
		t.Fatal("restart replaced password file")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := initializeAuth(db, dir, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("restart recreated a removed password file")
	}
	otherDB, otherDir := bootstrapDB(t), t.TempDir()
	if _, err := initializeAuth(otherDB, otherDir, ""); err != nil {
		t.Fatal(err)
	}
	other, _ := os.ReadFile(filepath.Join(otherDir, InitialAdminPasswordFile))
	if string(other) == string(data) {
		t.Fatal("installations share a password")
	}
}

func TestBootstrapExplicitAndLegacyCredentials(t *testing.T) {
	db, dir := bootstrapDB(t), t.TempDir()
	password := "provided-password-123"
	if created, err := initializeAuth(db, dir, password); err != nil || !created {
		t.Fatal(created, err)
	}
	if bcrypt.CompareHashAndPassword([]byte(authValue(t, db, "admin_password")), []byte(password)) != nil {
		t.Fatal("configured password not applied")
	}
	if _, err := os.Stat(filepath.Join(dir, InitialAdminPasswordFile)); !os.IsNotExist(err) {
		t.Fatal("explicit password written to disk")
	}
	legacy := bootstrapDB(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.MinCost)
	for _, row := range []SysConfig{{Key: "admin_username", Value: "custom-admin"}, {Key: "admin_password", Value: string(hash)}} {
		if err := legacy.Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
	if created, err := initializeAuth(legacy, dir, "weak"); err != nil || created {
		t.Fatal(created, err)
	}
	if authValue(t, legacy, "admin_username") != "custom-admin" || authValue(t, legacy, "admin_password") != string(hash) {
		t.Fatal("legacy account was reset")
	}
}

func TestBootstrapFailuresRollback(t *testing.T) {
	for _, kind := range []string{"weak-password", "file-unwritable", "password-write-failed"} {
		t.Run(kind, func(t *testing.T) {
			db, dir, password := bootstrapDB(t), t.TempDir(), ""
			switch kind {
			case "weak-password":
				password = "admin"
			case "file-unwritable":
				dir = filepath.Join(dir, "not-a-directory")
				if err := os.WriteFile(dir, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "password-write-failed":
				if err := db.Exec(`CREATE TRIGGER reject_password BEFORE INSERT ON sys_config WHEN NEW.key = 'admin_password' BEGIN SELECT RAISE(FAIL, 'test failure'); END`).Error; err != nil {
					t.Fatal(err)
				}
			}
			if created, err := initializeAuth(db, dir, password); err == nil || created {
				t.Fatal("failed bootstrap reported success")
			}
			var count int64
			db.Model(&SysConfig{}).Count(&count)
			if count != 0 {
				t.Fatal("partial security settings persisted")
			}
		})
	}
	for _, rows := range [][]SysConfig{
		{{Key: "admin_username", Value: "admin"}},
		{{Key: "admin_password", Value: "damaged"}},
		{{Key: "admin_username", Value: "admin"}, {Key: "admin_password", Value: "damaged"}},
		{{Key: "jwt_secret", Value: ""}},
	} {
		db := bootstrapDB(t)
		if err := db.Create(&rows).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := initializeAuth(db, t.TempDir(), ""); err == nil {
			t.Fatal("incomplete security data replaced")
		}
		for _, row := range rows {
			if authValue(t, db, row.Key) != row.Value {
				t.Fatal("damaged record silently reset")
			}
		}
	}
}

func TestBootstrapFileReplacementAndCleanup(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, InitialAdminPasswordFile)
	if err := os.Symlink(target, file); err != nil {
		t.Fatal(err)
	}
	db := bootstrapDB(t)
	if _, err := initializeAuth(db, dir, ""); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(target)
	if string(data) != "untouched" {
		t.Fatal("bootstrap followed symlink")
	}
	hash := authValue(t, db, "admin_password")
	wrong, _ := bcrypt.GenerateFromPassword([]byte("different-password"), bcrypt.MinCost)
	if err := RemoveInitialAdminPassword(dir, string(wrong)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal("another database's file removed")
	}
	if err := RemoveInitialAdminPassword(dir, hash); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("old bootstrap password remains")
	}
}

func TestAdminPasswordValidation(t *testing.T) {
	for _, password := range []string{"admin", strings.Repeat("a", 73), strings.Repeat("界", 25), " leading-spaces-password", "trailing-spaces-password ", "new-password\nline"} {
		if ValidateAdminPassword(password) == nil {
			t.Fatal("invalid password accepted")
		}
	}
	for _, password := range []string{"long-password-value", strings.Repeat("界", 12), strings.Repeat("a", 72)} {
		if err := ValidateAdminPassword(password); err != nil {
			t.Fatal(err)
		}
	}
}
