package database

import (
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// AdminCredentials is internal authentication material, never an API response.
type AdminCredentials struct {
	Username      string `json:"-"`
	PasswordHash  string `json:"-"`
	SessionSecret string `json:"-"`
}

// A single SELECT sees either side of a committed credential change. Separate
// queries can combine the old password hash with the newly rotated session key.
func LoadAdminCredentials(db *gorm.DB) (AdminCredentials, error) {
	var out AdminCredentials
	var rows []SysConfig
	if err := db.Where("key IN ?", []string{"admin_username", "admin_password", "jwt_secret"}).Find(&rows).Error; err != nil {
		return out, err
	}
	for _, row := range rows {
		switch row.Key {
		case "admin_username":
			out.Username = row.Value
		case "admin_password":
			out.PasswordHash = row.Value
		case "jwt_secret":
			out.SessionSecret = row.Value
		}
	}
	if strings.TrimSpace(out.Username) == "" || strings.TrimSpace(out.SessionSecret) == "" {
		return AdminCredentials{}, errors.New("管理员账号或会话密钥缺失")
	}
	if _, err := bcrypt.Cost([]byte(out.PasswordHash)); err != nil {
		return AdminCredentials{}, errors.New("管理员密码记录缺失或损坏")
	}
	return out, nil
}
