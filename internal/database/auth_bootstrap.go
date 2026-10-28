package database

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const InitialAdminPasswordFile = "initial-admin-password"
const InitialAdminPasswordEnv = "NODECTL_INITIAL_ADMIN_PASSWORD"

// ValidateAdminPassword also guards bcrypt's 72-byte limit without truncation.
func ValidateAdminPassword(password string) error {
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 12 || len(password) > 72 {
		return errors.New("密码至少需要 12 个字符，且不能超过 72 字节")
	}
	if strings.TrimSpace(password) != password || strings.ContainsAny(password, "\r\n\x00") {
		return errors.New("密码不能以空白开头或结尾，也不能包含换行")
	}
	return nil
}

// Account creation and JWT initialization are atomic. Existing credentials are
// never replaced, including when a deployment changes its bootstrap environment.
func initializeAuth(db *gorm.DB, dataDir, configuredPassword string) (created bool, err error) {
	err = db.Transaction(func(tx *gorm.DB) error {
		var rows []SysConfig
		if err := tx.Where("key IN ?", []string{"admin_username", "admin_password", "jwt_secret"}).Find(&rows).Error; err != nil {
			return err
		}
		settings := make(map[string]string, len(rows))
		for _, row := range rows {
			settings[row.Key] = row.Value
		}
		username, hasUsername := settings["admin_username"]
		passwordHash, hasPassword := settings["admin_password"]
		if hasUsername != hasPassword || (hasUsername && (strings.TrimSpace(username) == "" || passwordHash == "")) {
			return errors.New("管理员配置不完整，请恢复数据库备份；不会自动重置账号")
		}
		if hasPassword {
			if _, err := bcrypt.Cost([]byte(passwordHash)); err != nil {
				return errors.New("管理员密码记录损坏，请恢复数据库备份")
			}
		}
		if secret, exists := settings["jwt_secret"]; exists && secret == "" {
			return errors.New("会话密钥为空，请恢复数据库备份")
		} else if !exists {
			secretBytes := make([]byte, 32)
			if _, err := rand.Read(secretBytes); err != nil {
				return err
			}
			if err := tx.Create(&SysConfig{Key: "jwt_secret", Value: hex.EncodeToString(secretBytes), Description: "系统核心加密密钥 (请勿泄露)"}).Error; err != nil {
				return err
			}
		}
		if hasUsername {
			return nil
		}
		password := configuredPassword
		generated := password == ""
		if generated {
			secretBytes := make([]byte, 24)
			if _, err := rand.Read(secretBytes); err != nil {
				return err
			}
			password = base64.RawURLEncoding.EncodeToString(secretBytes)
		}
		if err := ValidateAdminPassword(password); err != nil {
			return err
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		// Unique keys decide which concurrent initializer owns account creation
		// before it writes the recovery file. A losing transaction writes no file.
		if err := tx.Create(&SysConfig{Key: "admin_username", Value: "admin", Description: "管理员登录账号"}).Error; err != nil {
			return err
		}
		if err := tx.Create(&SysConfig{Key: "admin_password", Value: string(hash), Description: "管理员密码(Bcrypt加密)"}).Error; err != nil {
			return err
		}
		if generated {
			if err := writeInitialPassword(dataDir, password); err != nil {
				return err
			}
		}
		created = true
		return nil
	})
	return created && err == nil, err
}

func writeInitialPassword(dir, password string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".initial-admin-password-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.WriteString(password + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Rename replaces a stale file or symlink, never follows it to another file.
	return os.Rename(f.Name(), filepath.Join(dir, InitialAdminPasswordFile))
}

// Remove only the file belonging to the credential that was actually changed.
// A file left by a different database must not be removed after a database switch.
func RemoveInitialAdminPassword(dataDir, oldHash string) error {
	path := filepath.Join(dataDir, InitialAdminPasswordFile)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("初始密码文件不是普通文件，请手动检查")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	password := strings.TrimSuffix(string(data), "\n")
	if bcrypt.CompareHashAndPassword([]byte(oldHash), []byte(password)) != nil {
		return nil
	}
	return os.Remove(path)
}
