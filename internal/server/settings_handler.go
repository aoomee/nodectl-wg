package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	"nodectl/internal/database"
	"nodectl/internal/logger"
	"nodectl/internal/middleware"
	"nodectl/internal/service"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	gormlogger "gorm.io/gorm/logger"
)

// Serialize persistence and synchronous runtime changes in commit order.
var settingsUpdateMu sync.Mutex

// ------------------- [系统设置 API] -------------------

func apiGetSettings(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodGet {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var configs []database.SysConfig
	w.Header().Set("Cache-Control", "no-store")
	if err := database.DB.Session(&gorm.Session{Logger: database.DB.Logger.LogMode(gormlogger.Silent)}).Where("key IN ?", []string{
		"panel_url", "sub_token", "proxy_port_ss", "proxy_port_hy2", "proxy_port_tuic",
		"proxy_port_reality", "proxy_ss_method",
		"sys_force_http", "login_ip_retry_window_sec", "login_ip_max_retries", "login_ip_block_ttl_sec",
		"proxy_port_socks5", "proxy_socks5_user", "proxy_socks5_pass", "proxy_socks5_random_auth", "pref_use_emoji_flag", "pref_force_protocol_prefix", "sub_custom_name", "pref_ip_strategy", "pref_default_install_protocols",
		"sys_log_level", "airport_filter_invalid", "pref_speed_test_file_size", "pref_traffic_stats_retention_days", "pref_traffic_point_persist_interval_sec",
		"auth_cookie_ttl_mode",
		"tg_bot_enabled", "tg_bot_token", "tg_bot_whitelist", "tg_bot_register_commands", "tg_bot_socks5_enabled", "tg_bot_socks5_addr", "tg_bot_socks5_user", "tg_bot_socks5_pass", "tg_login_notify_mode", "tg_speedtest_notify_enabled", "tg_threshold_stop_notify_enabled", "clash_proxies_update_interval", "clash_rules_update_interval", "clash_public_rules_update_interval",
		"geo_auto_update", "mihomo_auto_update", "agent_startup_silent_update_enabled",
		"cf_tunnel_auto_update", "cf_ipopt_auto_update",
		// 新增协议与内核优化配置
		"proxy_port_trojan", "proxy_hy2_sni", "proxy_tuic_sni", "proxy_enable_bbr",
		// VMess 族
		"proxy_port_vmess_tcp", "proxy_port_vmess_ws", "proxy_port_vmess_http", "proxy_port_vmess_quic",
		"proxy_port_vmess_wst", "proxy_port_vmess_hut",
		// VLESS-TLS 族
		"proxy_port_vless_wst", "proxy_port_vless_hut",
		// Trojan-TLS 族
		"proxy_port_trojan_wst", "proxy_port_trojan_hut",
		"proxy_tls_transport_path", "proxy_vmess_tls_sni", "proxy_vless_tls_sni", "proxy_trojan_tls_sni",
		// AnyTLS
		"proxy_port_anytls", "proxy_anytls_sni",
	}).Find(&configs).Error; err != nil {
		logger.Log.Error("读取系统配置失败", "error_type", fmt.Sprintf("%T", err), "ip", clientIP, "path", reqPath)
		settingsError(w, http.StatusServiceUnavailable, "设置读取失败，请稍后重试")
		return
	}

	data := make(map[string]string)
	for _, c := range configs {
		if (c.Key == "cf_api_key" || c.Key == "tg_bot_token" || c.Key == "tg_bot_socks5_pass") && c.Value != "" {
			data[c.Key] = "********"
		} else {
			data[c.Key] = c.Value
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   data,
	})
}

func apiUpdateSettings(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	reqPath := r.URL.Path

	if r.Method != http.MethodPost {
		logger.Log.Warn("非法请求方法", "method", r.Method, "ip", clientIP, "path", reqPath)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Log.Warn("设置 JSON 解析失败", "ip", clientIP, "path", reqPath)
		settingsError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	validKeys := map[string]bool{
		"panel_url": true, "sub_token": true, "proxy_port_ss": true, "proxy_port_hy2": true,
		"proxy_port_tuic": true, "proxy_port_reality": true,
		"sys_force_http": true, "login_ip_retry_window_sec": true, "login_ip_max_retries": true, "login_ip_block_ttl_sec": true,
		"proxy_ss_method": true, "proxy_port_socks5": true, "proxy_socks5_user": true, "proxy_socks5_pass": true, "proxy_socks5_random_auth": true, "pref_use_emoji_flag": true, "pref_force_protocol_prefix": true,
		"sub_custom_name": true, "pref_ip_strategy": true, "pref_default_install_protocols": true,
		"sys_log_level":          true,
		"airport_filter_invalid": true, "pref_speed_test_file_size": true, "pref_traffic_stats_retention_days": true, "pref_traffic_point_persist_interval_sec": true,
		"auth_cookie_ttl_mode": true,
		"tg_bot_enabled":       true, "tg_bot_token": true, "tg_bot_whitelist": true, "tg_bot_register_commands": true,
		"tg_bot_socks5_enabled": true, "tg_bot_socks5_addr": true, "tg_bot_socks5_user": true, "tg_bot_socks5_pass": true,
		"tg_login_notify_mode": true, "tg_speedtest_notify_enabled": true, "tg_threshold_stop_notify_enabled": true,
		"clash_proxies_update_interval": true, "clash_rules_update_interval": true, "clash_public_rules_update_interval": true,
		"geo_auto_update": true, "mihomo_auto_update": true, "agent_startup_silent_update_enabled": true,
		"cf_tunnel_auto_update": true, "cf_ipopt_auto_update": true,
		// 新增协议与内核优化配置
		"proxy_port_trojan": true,
		"proxy_hy2_sni":     true, "proxy_tuic_sni": true, "proxy_enable_bbr": true,
		// VMess 族
		"proxy_port_vmess_tcp": true, "proxy_port_vmess_ws": true, "proxy_port_vmess_http": true, "proxy_port_vmess_quic": true,
		"proxy_port_vmess_wst": true, "proxy_port_vmess_hut": true,
		// VLESS-TLS 族
		"proxy_port_vless_wst": true, "proxy_port_vless_hut": true,
		// Trojan-TLS 族
		"proxy_port_trojan_wst": true, "proxy_port_trojan_hut": true,
		"proxy_tls_transport_path": true,
		"proxy_vmess_tls_sni":      true, "proxy_vless_tls_sni": true, "proxy_trojan_tls_sni": true,
		// AnyTLS
		"proxy_port_anytls": true, "proxy_anytls_sni": true,
	}

	// Validate the entire request before touching either storage or live services.
	normalized := make(map[string]string)
	keys := make([]string, 0, len(req))
	for k, v := range req {
		if !validKeys[k] {
			continue
		}
		if (k == "tg_bot_token" || k == "tg_bot_socks5_pass") && v == "********" {
			continue
		}
		value, err := normalizeSettingValue(k, v)
		if err != nil {
			settingsError(w, http.StatusBadRequest, err.Error())
			return
		}
		normalized[k] = value
		keys = append(keys, k)
	}
	sort.Strings(keys)
	settingsUpdateMu.Lock()
	defer settingsUpdateMu.Unlock()
	// SQL errors and slow-query traces can include bound credentials. Only log
	// whitelisted key names and error types for this sensitive settings operation.
	db := database.DB.Session(&gorm.Session{Logger: database.DB.Logger.LogMode(gormlogger.Silent)})
	changed := make([]string, 0, len(keys))
	err := db.Transaction(func(tx *gorm.DB) error {
		if len(keys) == 0 {
			return nil
		}
		var rows []database.SysConfig
		if err := tx.Where("key IN ?", keys).Find(&rows).Error; err != nil {
			return err
		}
		old := make(map[string]string, len(rows))
		for _, row := range rows {
			old[row.Key] = row.Value
		}
		for _, k := range keys {
			v := normalized[k]
			if previous, exists := old[k]; exists && previous == v {
				continue
			}
			row := database.SysConfig{Key: k, Value: v}
			result := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "key"}}, DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"})}).Create(&row)
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				return errors.New("settings update affected no row")
			}
			changed = append(changed, k)
		}
		return nil
	})
	if err != nil {
		logger.Log.Error("系统设置未确认提交", "error_type", fmt.Sprintf("%T", err), "ip", clientIP, "path", reqPath)
		settingsError(w, http.StatusInternalServerError, "设置保存失败，未确认生效，请重新加载后重试")
		return
	}
	if len(changed) == 0 {
		sendJSON(w, "success", "设置无变化")
		return
	}
	needRestartTgBot, needReloadLoginRateLimit := false, false
	for _, k := range changed {
		v := normalized[k]
		switch k {
		case "sys_log_level":
			logger.SetLevel(v)
		case "login_ip_retry_window_sec", "login_ip_max_retries", "login_ip_block_ttl_sec":
			needReloadLoginRateLimit = true
		case "tg_bot_enabled", "tg_bot_token", "tg_bot_whitelist", "tg_bot_register_commands", "tg_bot_socks5_enabled", "tg_bot_socks5_addr", "tg_bot_socks5_user", "tg_bot_socks5_pass":
			needRestartTgBot = true
		case "geo_auto_update":
			if strings.EqualFold(strings.TrimSpace(v), "true") {
				service.TriggerGeoAutoUpdateCheckNow()
			}
		case "mihomo_auto_update":
			if strings.EqualFold(strings.TrimSpace(v), "true") {
				service.TriggerMihomoAutoUpdateCheckNow()
			}
		case "cf_tunnel_auto_update":
			if strings.EqualFold(strings.TrimSpace(v), "true") {
				service.TriggerCFTunnelAutoUpdateCheckNow()
			}
		case "cf_ipopt_auto_update":
			if strings.EqualFold(strings.TrimSpace(v), "true") {
				service.TriggerCFIPOptAutoUpdateCheckNow()
			}
		}
	}
	logger.Log.Info("系统全局配置已更新", "changed_count", len(changed), "keys", strings.Join(changed, ","), "ip", clientIP, "path", reqPath)
	if needRestartTgBot {
		go service.RestartTelegramBot()
	}
	if needReloadLoginRateLimit {
		if err := middleware.ReloadLoginRateLimitConfigFromDB(); err != nil {
			logger.Log.Error("已保存设置，但登录限制刷新失败", "error_type", fmt.Sprintf("%T", err))
			settingsError(w, http.StatusServiceUnavailable, "设置已保存，但登录限制未刷新，请重启面板后检查")
			return
		}
	}
	sendJSON(w, "success", "设置已保存")
}

func settingsError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	sendJSON(w, "error", message)
}

func normalizeSettingValue(key, value string) (string, error) {
	integer := func(min, max int, message string) (string, error) {
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || n < min || n > max {
			return "", errors.New(message)
		}
		return strconv.Itoa(n), nil
	}
	switch key {
	case "sys_log_level":
		v := strings.ToLower(strings.TrimSpace(value))
		if v == "" {
			v = "info"
		}
		if v == "warning" {
			v = "warn"
		}
		switch v {
		case "debug", "info", "warn", "error":
			return v, nil
		}
		return "", errors.New("日志等级无效，仅支持: debug / info / warn / error")
	case "pref_traffic_stats_retention_days":
		return integer(1, 3650, "流量记录保留天数无效，仅支持 1-3650 天")
	case "pref_traffic_point_persist_interval_sec":
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || n < 0 || (n > 0 && n < 10) || n > 3600 {
			return "", errors.New("实时流量点数据落库间隔无效，仅支持 0 (关闭) 或 10-3600 秒")
		}
		return strconv.Itoa(n), nil
	case "auth_cookie_ttl_mode":
		return normalizeAuthCookieTTLMode(value), nil
	case "login_ip_retry_window_sec":
		return integer(30, 86400, "登录失败计数窗口无效，仅支持 30-86400 秒")
	case "login_ip_max_retries":
		return integer(1, 100, "登录最大重试次数无效，仅支持 1-100 次")
	case "login_ip_block_ttl_sec":
		return integer(30, 86400, "登录封禁时长无效，仅支持 30-86400 秒")
	case "tg_login_notify_mode":
		v := strings.TrimSpace(value)
		switch v {
		case "off", "success_only", "failure_only", "all":
			return v, nil
		}
		return "", errors.New("登录通知模式无效")
	case "clash_public_rules_update_interval":
		n, err := strconv.Atoi(value)
		if err != nil || n < 86400 {
			return "86400", nil
		}
	}
	return value, nil
}
