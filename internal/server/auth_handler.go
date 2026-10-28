package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nodectl/internal/database"
	"nodectl/internal/logger"
	"nodectl/internal/middleware"
	"nodectl/internal/requestmeta"
	"nodectl/internal/service"
	"nodectl/internal/version"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// ------------------- [认证与页面渲染] -------------------

func loginHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	reqPath := r.URL.Path

	if r.Method == http.MethodGet {
		tmpl.ExecuteTemplate(w, "login.html", nil)
		return
	}

	if r.Method == http.MethodPost {
		username := strings.TrimSpace(r.FormValue("username"))
		allowed, _, retryAfter := middleware.CheckLoginAttemptAllowed(clientIP)
		if !allowed {
			logger.Log.Warn("登录拦截: IP短期限流生效",
				"ip", clientIP,
				"path", reqPath,
				"retry_after_sec", int(retryAfter.Seconds()),
			)
			go service.SendAdminLoginNotification(username, clientIP, time.Now(), false, "登录尝试次数过多（限流）")
			tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "登录尝试次数过多，请稍后再试"})
			return
		}

		password := r.FormValue("password")

		// Read one database snapshot: an in-flight old-password login must never
		// pick up the new signing key after a concurrent credential rotation.
		credentials, err := database.LoadAdminCredentials(database.DB)
		if err != nil {
			logger.Log.Error("登录凭据读取失败", "error", err, "ip", clientIP)
			w.WriteHeader(http.StatusServiceUnavailable)
			tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "登录暂不可用，请稍后重试或检查服务器日志"})
			return
		}
		if credentials.Username != username {
			blocked, remaining, blockAfter := middleware.RecordLoginFailure(clientIP)
			if blocked {
				logger.Log.Warn("登录拦截: 用户名不存在且IP已短期封禁",
					"username", username,
					"ip", clientIP,
					"path", reqPath,
					"retry_after_sec", int(blockAfter.Seconds()),
				)
				go service.SendAdminLoginNotification(username, clientIP, time.Now(), false, "用户名错误且触发短期封禁")
				tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "登录尝试次数过多，请稍后再试"})
				return
			}
			logger.Log.Warn("登录拦截: 用户名不存在", "username", username, "ip", clientIP, "path", reqPath, "remaining_attempts", remaining)
			go service.SendAdminLoginNotification(username, clientIP, time.Now(), false, "用户名或密码错误")
			tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "用户名或密码错误"})
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(credentials.PasswordHash), []byte(password))
		if err != nil {
			blocked, remaining, blockAfter := middleware.RecordLoginFailure(clientIP)
			if blocked {
				logger.Log.Warn("登录拦截: 密码错误且IP已短期封禁",
					"username", username,
					"ip", clientIP,
					"path", reqPath,
					"retry_after_sec", int(blockAfter.Seconds()),
				)
				go service.SendAdminLoginNotification(username, clientIP, time.Now(), false, "密码错误且触发短期封禁")
				tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "登录尝试次数过多，请稍后再试"})
				return
			}
			logger.Log.Warn("登录拦截: 密码错误", "username", username, "ip", clientIP, "path", reqPath, "remaining_attempts", remaining)
			go service.SendAdminLoginNotification(username, clientIP, time.Now(), false, "用户名或密码错误")
			tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "用户名或密码错误"})
			return
		}

		middleware.ClearLoginFailureRecord(clientIP)

		ttlMode := loadAuthCookieTTLMode()
		expireAt, maxAge, persistent := resolveAuthCookieTTL(ttlMode)

		claims := jwt.MapClaims{
			"username": username,
			"iat":      time.Now().Unix(),
		}
		if persistent {
			claims["exp"] = expireAt.Unix()
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(credentials.SessionSecret))
		if err != nil {
			logger.Log.Error("签发 Token 失败", "error", err, "ip", clientIP, "path", reqPath)
			tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "系统内部错误"})
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "nodectl_token",
			Value:    tokenString,
			Path:     "/",
			HttpOnly: true,
			Secure:   requestmeta.IsSecure(r),
			MaxAge:   maxAge,
			Expires:  expireAt,
			SameSite: http.SameSiteLaxMode,
		})

		logger.Log.Info("管理员登录成功", "username", username, "ip", clientIP, "path", reqPath)
		go service.SendAdminLoginNotification(username, clientIP, time.Now(), true, "")
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// indexHandler 处理主控制台界面渲染
func indexHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	var nodes []database.NodePool
	if err := database.DB.Find(&nodes).Error; err != nil {
		logger.Log.Error("获取节点统计失败", "error", err, "ip", clientIP, "path", reqPath)
	}

	stats := map[string]int{
		"Total":   0,
		"Direct":  0,
		"Landing": 0,
		"Blocked": 0,
	}
	stats["Total"] = len(nodes)

	rawProtoCounts := make(map[string]int)

	for _, node := range nodes {
		if node.IsBlocked {
			stats["Blocked"]++
		} else {
			if node.RoutingType == 1 {
				stats["Direct"]++
			} else if node.RoutingType == 2 {
				stats["Landing"]++
			}
		}

		for protoKey := range node.Links {
			rawProtoCounts[protoKey]++
		}
	}

	type ProtoStatItem struct {
		Name  string
		Count int
	}
	var displayProtoStats []ProtoStatItem

	for _, proto := range database.SupportedProtocols {
		count := rawProtoCounts[proto]
		if count > 0 {
			displayName := strings.ToUpper(proto)
			switch proto {
			case "reality":
				displayName = "Reality"
			case "ss":
				displayName = "Shadowsocks"
			case "hy2":
				displayName = "Hysteria2"
			case "socks5":
				displayName = "Socks5"
			case "trojan":
				displayName = "Trojan"
			case "vmess_tcp":
				displayName = "VMess-TCP"
			case "vmess_ws":
				displayName = "VMess-WS"
			case "vmess_http":
				displayName = "VMess-HTTP"
			case "vmess_quic":
				displayName = "VMess-QUIC"
			case "vmess_wst":
				displayName = "VMess-WS-TLS"
			case "vmess_hut":
				displayName = "VMess-HU-TLS"
			case "vless_wst":
				displayName = "VLESS-WS-TLS"
			case "vless_hut":
				displayName = "VLESS-HU-TLS"
			case "trojan_wst":
				displayName = "Trojan-WS-TLS"
			case "trojan_hut":
				displayName = "Trojan-HU-TLS"
			}
			displayProtoStats = append(displayProtoStats, ProtoStatItem{
				Name:  displayName,
				Count: count,
			})
		}
	}

	data := map[string]interface{}{
		"Title":      "Nodectl控制台",
		"Protocols":  database.SupportedProtocols,
		"Version":    version.Version,
		"Stats":      stats,
		"ProtoStats": displayProtoStats,
	}
	tmpl.ExecuteTemplate(w, "index.html", data)
}

// logoutHandler 处理安全退出逻辑
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	http.SetCookie(w, &http.Cookie{
		Name:     "nodectl_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		Expires:  time.Now().Add(-1 * time.Hour),
	})

	logger.Log.Info("管理员已安全退出", "ip", clientIP, "path", reqPath)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ------------------- [密码与安全 API] -------------------

func apiChangePassword(w http.ResponseWriter, r *http.Request) {

	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	demoPath := filepath.Join("data", "debug", "demo")
	if _, err := os.Stat(demoPath); err == nil {
		// 如果 demo 文件存在 (不报 err)，说明开启了演示模式
		logger.Log.Warn("尝试在演示模式下修改密码，已被拦截", "ip", r.RemoteAddr)
		sendJSON(w, "error", "演示模式已开启，禁止修改密码")
		return
	}

	if r.Method != http.MethodPost {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		OldUsername     string `json:"old_username"`
		NewUsername     string `json:"new_username"`
		OldPassword     string `json:"old_password"`
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Log.Warn("解析 JSON 失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "请求数据格式错误")
		return
	}

	req.OldUsername = strings.TrimSpace(req.OldUsername)
	req.NewUsername = strings.TrimSpace(req.NewUsername)

	if req.OldPassword == "" {
		logger.Log.Warn("修改账号/密码失败: 未输入当前密码", "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "请输入当前密码")
		return
	}

	if req.NewUsername != "" {
		if strings.Contains(req.NewUsername, " ") {
			logger.Log.Warn("修改账号失败: 新账号包含空格", "ip", clientIP, "path", reqPath)
			sendJSON(w, "error", "新账号不能包含空格")
			return
		}
		if len(req.NewUsername) < 3 || len(req.NewUsername) > 64 {
			logger.Log.Warn("修改账号失败: 新账号长度非法", "ip", clientIP, "path", reqPath)
			sendJSON(w, "error", "新账号长度需在 3-64 位之间")
			return
		}
	}

	wantPasswordChange := req.NewPassword != "" || req.ConfirmPassword != ""
	if wantPasswordChange {
		if req.NewPassword != req.ConfirmPassword {
			logger.Log.Warn("修改密码失败: 两次密码不一致", "ip", clientIP, "path", reqPath)
			sendJSON(w, "error", "两次输入的新密码不一致")
			return
		}
		if err := database.ValidateAdminPassword(req.NewPassword); err != nil {
			logger.Log.Warn("修改密码失败: 密码格式不符合要求", "ip", clientIP, "path", reqPath)
			sendJSON(w, "error", err.Error())
			return
		}
	}

	db := database.DB
	var userConfig database.SysConfig
	if err := db.Where("key = ?", "admin_username").First(&userConfig).Error; err != nil {
		logger.Log.Error("修改账号/密码失败: 找不到账号配置", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "系统错误，找不到管理员账号")
		return
	}

	currentUsername := strings.TrimSpace(userConfig.Value)
	if req.OldUsername == "" {
		req.OldUsername = currentUsername
	}
	if req.OldUsername != currentUsername {
		logger.Log.Warn("修改账号拦截: 当前账号验证失败", "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "当前账号输入错误")
		return
	}

	wantUsernameChange := req.NewUsername != "" && req.NewUsername != currentUsername
	if !wantUsernameChange && !wantPasswordChange {
		sendJSON(w, "error", "请至少修改账号或密码中的一项")
		return
	}

	var passConfig database.SysConfig
	if err := db.Where("key = ?", "admin_password").First(&passConfig).Error; err != nil {
		logger.Log.Error("修改密码失败: 找不到密码配置", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "系统错误，找不到管理员账号")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passConfig.Value), []byte(req.OldPassword)); err != nil {
		logger.Log.Warn("修改密码拦截: 旧密码验证失败", "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "当前密码输入错误")
		return
	}

	newHash := passConfig.Value
	if wantPasswordChange {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			sendJSON(w, "error", "密码加密失败，请稍后重试")
			return
		}
		newHash = string(hashedPassword)
	}
	secureBytes := make([]byte, 32)
	if _, err := rand.Read(secureBytes); err != nil {
		sendJSON(w, "error", "生成会话密钥失败，请稍后重试")
		return
	}
	err := db.Transaction(func(tx *gorm.DB) error {
		// Compare-and-swap fences concurrent changes authenticated with the old password.
		result := tx.Model(&database.SysConfig{}).Where("key = ? AND value = ?", "admin_password", passConfig.Value).Update("value", newHash)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return errors.New("管理员密码已变化，请重新登录")
		}
		if wantUsernameChange {
			result = tx.Model(&database.SysConfig{}).Where("key = ? AND value = ?", "admin_username", userConfig.Value).Update("value", req.NewUsername)
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				return errors.New("管理员账号已变化，请重新登录")
			}
		}
		result = tx.Model(&database.SysConfig{}).Where("key = ?", "jwt_secret").Update("value", hex.EncodeToString(secureBytes))
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return errors.New("会话密钥记录缺失")
		}
		return nil
	})
	if err != nil {
		logger.Log.Error("更新管理员凭据失败，已回滚", "error", err, "ip", clientIP)
		sendJSON(w, "error", "更新账号或密码失败，请刷新后重试")
		return
	}
	if wantPasswordChange {
		if err := database.RemoveInitialAdminPassword("data", passConfig.Value); err != nil {
			logger.Log.Warn("密码已修改，但初始密码文件清理失败，请在服务器终端检查", "error", err)
		}
	}

	logger.Log.Info("管理员账号/密码修改成功", "username_changed", wantUsernameChange, "password_changed", wantPasswordChange, "ip", clientIP, "path", reqPath)

	http.SetCookie(w, &http.Cookie{
		Name:     "nodectl_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	sendJSON(w, "success", "账号/密码修改成功！1.5秒后将重新跳转到登录页")
}

func apiResetJWT(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	demoPath := filepath.Join("data", "debug", "demo")
	if _, err := os.Stat(demoPath); err == nil {
		logger.Log.Warn("尝试在演示模式下重置JWT密钥，已被拦截", "ip", r.RemoteAddr)
		sendJSON(w, "error", "演示模式已开启，禁止重置密钥")
		return
	}

	if r.Method != http.MethodPost {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	secureBytes := make([]byte, 32)
	if _, err := rand.Read(secureBytes); err == nil {
		newSecret := hex.EncodeToString(secureBytes)
		result := database.DB.Model(&database.SysConfig{}).Where("key = ?", "jwt_secret").Update("value", newSecret)
		if result.Error != nil || result.RowsAffected != 1 {
			logger.Log.Error("重置会话密钥未成功写入", "error", result.Error, "rows", result.RowsAffected, "ip", clientIP)
			sendJSON(w, "error", "会话密钥重置失败，未确认设备下线，请稍后重试或检查服务器日志")
			return
		}
		logger.Log.Info("系统级密钥 (JWT Secret) 已手动重置", "ip", clientIP, "path", reqPath)
	} else {
		logger.Log.Error("生成新密钥失败", "error", err, "ip", clientIP, "path", reqPath)
		sendJSON(w, "error", "生成新密钥失败，请稍后重试")
		return
	}

	// 清除当前用户的 Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "nodectl_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	sendJSON(w, "success", "JWT 密钥重置成功！所有设备已下线，请重新登录")
}
