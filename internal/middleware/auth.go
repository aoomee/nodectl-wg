package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"nodectl/internal/database"
	"nodectl/internal/logger"
	"nodectl/internal/requestmeta"

	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultLoginRetryWindowSec = 600
	defaultMaxLoginRetries     = 5
	defaultLoginBlockTTLSec    = 900
)

type ipLoginAttemptState struct {
	FailedCount  int
	WindowStart  time.Time
	BlockedUntil time.Time
	LastSeen     time.Time
}

var (
	loginAttemptMu    sync.Mutex
	ipLoginAttemptMap = make(map[string]*ipLoginAttemptState)
	loginRetryWindow  = time.Duration(defaultLoginRetryWindowSec) * time.Second
	maxLoginRetries   = defaultMaxLoginRetries
	loginBlockTTL     = time.Duration(defaultLoginBlockTTLSec) * time.Second
)

func sanitizeLoginLimitConfig(retryWindowSec, maxRetries, blockTTLSec int) (int, int, int) {
	if retryWindowSec < 30 {
		retryWindowSec = 30
	}
	if retryWindowSec > 86400 {
		retryWindowSec = 86400
	}

	if maxRetries < 1 {
		maxRetries = 1
	}
	if maxRetries > 100 {
		maxRetries = 100
	}

	if blockTTLSec < 30 {
		blockTTLSec = 30
	}
	if blockTTLSec > 86400 {
		blockTTLSec = 86400
	}

	return retryWindowSec, maxRetries, blockTTLSec
}

// UpdateLoginRateLimitConfig 更新登录 IP 限流参数（秒/次数）。
func UpdateLoginRateLimitConfig(retryWindowSec, maxRetries, blockTTLSec int) {
	retryWindowSec, maxRetries, blockTTLSec = sanitizeLoginLimitConfig(retryWindowSec, maxRetries, blockTTLSec)

	loginAttemptMu.Lock()
	defer loginAttemptMu.Unlock()

	loginRetryWindow = time.Duration(retryWindowSec) * time.Second
	maxLoginRetries = maxRetries
	loginBlockTTL = time.Duration(blockTTLSec) * time.Second

	// 配置变更后清空历史计数，避免旧窗口参数影响新策略。
	ipLoginAttemptMap = make(map[string]*ipLoginAttemptState)
}

// ReloadLoginRateLimitConfigFromDB 从数据库读取登录 IP 限流配置并应用到内存。
func ReloadLoginRateLimitConfigFromDB() error {
	keys := []string{
		"login_ip_retry_window_sec",
		"login_ip_max_retries",
		"login_ip_block_ttl_sec",
	}

	var cfgList []database.SysConfig
	if err := database.DB.Where("key IN ?", keys).Find(&cfgList).Error; err != nil {
		return err
	}

	raw := map[string]string{}
	for _, c := range cfgList {
		raw[c.Key] = strings.TrimSpace(c.Value)
	}

	retryWindowSec := defaultLoginRetryWindowSec
	maxRetries := defaultMaxLoginRetries
	blockTTLSec := defaultLoginBlockTTLSec

	if v, ok := raw["login_ip_retry_window_sec"]; ok && v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			retryWindowSec = parsed
		} else {
			logger.Log.Warn("登录限流配置解析失败，回退默认值", "key", "login_ip_retry_window_sec", "value", v, "error", err)
		}
	}
	if v, ok := raw["login_ip_max_retries"]; ok && v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			maxRetries = parsed
		} else {
			logger.Log.Warn("登录限流配置解析失败，回退默认值", "key", "login_ip_max_retries", "value", v, "error", err)
		}
	}
	if v, ok := raw["login_ip_block_ttl_sec"]; ok && v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			blockTTLSec = parsed
		} else {
			logger.Log.Warn("登录限流配置解析失败，回退默认值", "key", "login_ip_block_ttl_sec", "value", v, "error", err)
		}
	}

	UpdateLoginRateLimitConfig(retryWindowSec, maxRetries, blockTTLSec)
	return nil
}

// CheckLoginAttemptAllowed 检查指定 IP 当前是否允许继续尝试登录。
// 返回值: 允许登录、剩余尝试次数、若被封禁则剩余等待时长。
func CheckLoginAttemptAllowed(ip string) (bool, int, time.Duration) {
	now := time.Now()
	loginAttemptMu.Lock()
	defer loginAttemptMu.Unlock()

	cleanupExpiredLoginAttemptsLocked(now)

	state, ok := ipLoginAttemptMap[ip]
	if !ok {
		return true, maxLoginRetries, 0
	}

	state.LastSeen = now

	if state.BlockedUntil.After(now) {
		return false, 0, state.BlockedUntil.Sub(now)
	}

	if now.Sub(state.WindowStart) >= loginRetryWindow {
		state.FailedCount = 0
		state.WindowStart = now
	}

	remaining := maxLoginRetries - state.FailedCount
	if remaining < 0 {
		remaining = 0
	}

	return true, remaining, 0
}

// RecordLoginFailure 记录指定 IP 的一次登录失败。
// 返回值: 是否已触发封禁、剩余可尝试次数、若封禁则封禁剩余时长。
func RecordLoginFailure(ip string) (bool, int, time.Duration) {
	now := time.Now()
	loginAttemptMu.Lock()
	defer loginAttemptMu.Unlock()

	cleanupExpiredLoginAttemptsLocked(now)

	state, ok := ipLoginAttemptMap[ip]
	if !ok {
		state = &ipLoginAttemptState{
			WindowStart: now,
			LastSeen:    now,
		}
		ipLoginAttemptMap[ip] = state
	}

	state.LastSeen = now

	if state.BlockedUntil.After(now) {
		return true, 0, state.BlockedUntil.Sub(now)
	}

	if now.Sub(state.WindowStart) >= loginRetryWindow {
		state.FailedCount = 0
		state.WindowStart = now
	}

	state.FailedCount++
	remaining := maxLoginRetries - state.FailedCount
	if remaining <= 0 {
		state.BlockedUntil = now.Add(loginBlockTTL)
		state.FailedCount = maxLoginRetries
		return true, 0, loginBlockTTL
	}

	return false, remaining, 0
}

// ClearLoginFailureRecord 在登录成功后清理指定 IP 的失败计数。
func ClearLoginFailureRecord(ip string) {
	loginAttemptMu.Lock()
	defer loginAttemptMu.Unlock()
	delete(ipLoginAttemptMap, ip)
}

func cleanupExpiredLoginAttemptsLocked(now time.Time) {
	for ip, state := range ipLoginAttemptMap {
		if state == nil {
			delete(ipLoginAttemptMap, ip)
			continue
		}

		if state.BlockedUntil.After(now) {
			continue
		}

		if now.Sub(state.LastSeen) > loginRetryWindow+loginBlockTTL {
			delete(ipLoginAttemptMap, ip)
		}
	}
}

func compactUserAgent(ua string) string {
	ua = strings.TrimSpace(ua)
	if len(ua) > 160 {
		return ua[:160] + "..."
	}
	return ua
}

// getClientIP 从请求中提取真实客户端 IP（支持反向代理场景）
func getClientIP(r *http.Request) string {
	return requestmeta.ClientIP(r)
}

// Auth 鉴权中间件，用于保护需要登录才能访问的路由
func Auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		reqPath := r.URL.Path

		// 1. 尝试从请求中获取名为 nodectl_token 的 Cookie
		cookie, err := r.Cookie("nodectl_token")
		if err != nil {
			// 没有带 Cookie，说明未登录，重定向到登录页。
			if reqPath == "/" || reqPath == "/index.html" || strings.HasPrefix(reqPath, "/api/") {
				logger.Log.Warn("未授权访问拦截",
					"reason", "请求缺少 nodectl_token Cookie",
					"ip", clientIP,
					"path", reqPath,
					"method", r.Method,
					"user_agent", compactUserAgent(r.UserAgent()),
				)
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// 2. 从数据库获取系统加密密钥 (JWT Secret)
		var secretConfig database.SysConfig
		if err := database.DB.Where("key = ?", "jwt_secret").First(&secretConfig).Error; err != nil {
			logger.Log.Error("鉴权系统异常",
				"reason", "无法从数据库读取 jwt_secret",
				"error", err,
				"ip", clientIP,
				"path", reqPath,
				"method", r.Method,
			)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// 3. 解析并校验 JWT
		tokenString := cookie.Value
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {

			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				algoErr := fmt.Errorf("非法的签名算法: %v", token.Header["alg"])
				logger.Log.Warn("Token 校验警告",
					"reason", "尝试使用伪造的签名算法",
					"error", algoErr,
					"ip", clientIP,
				)
				return nil, algoErr
			}
			return []byte(secretConfig.Value), nil
		})

		if err != nil || !token.Valid {
			logger.Log.Warn("Token 校验失败",
				"reason", "Token无效或已过期",
				"error", err,
				"ip", clientIP,
				"path", reqPath,
				"method", r.Method,
				"user_agent", compactUserAgent(r.UserAgent()),
			)

			http.SetCookie(w, &http.Cookie{
				Name:     "nodectl_token",
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
			})
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// 4. Token 校验通过，放行请求。
		next.ServeHTTP(w, r)
	}
}

// ForceHTTPS 强制 HTTPS 重定向中间件 (已废弃网络层重定向)
// 功能：在单端口热切换架构下，不再执行 HTTP 到 HTTPS 的强制跳转。
// 真正的安全保护由 handlers.go 内部根据 sys_force_http 动态脱敏敏感数据来实现。
func ForceHTTPS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 直接放行，保证用户在 HTTP 模式下也能打开后台面板上传证书
		next.ServeHTTP(w, r)
	}
}
