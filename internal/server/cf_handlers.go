// 路径: internal/server/cf_handlers.go
// Cloudflare 相关 API Handler
package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"nodectl/internal/database"
	"nodectl/internal/logger"
	"nodectl/internal/service"
)

// apiCFTunnelTest POST /api/cf/tunnel/test
func apiCFTunnelTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	msg, err := service.TestCFCredentials()
	if err != nil {
		logger.Log.Warn("CF 凭据测试失败", "error", err, "ip", getClientIP(r))
		sendJSON(w, "error", err.Error())
		return
	}

	logger.Log.Info("CF 凭据测试成功", "ip", getClientIP(r))
	sendJSON(w, "success", msg)
}

// ------------------- [CF Token 权限管理] -------------------

// apiCFTokenVerify POST /api/cf/token/verify
func apiCFTokenVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}
	req.Token = strings.TrimSpace(req.Token)

	result, err := service.VerifyCFTokenPermissions(req.Token)
	if err != nil {
		logger.Log.Warn("Token 权限验证失败", "error", err, "ip", getClientIP(r))
		sendJSON(w, "error", err.Error())
		return
	}

	// 持久化保存最近一次校验记录
	service.SaveTokenVerifyRecord(result)
	if email := service.PickBestCFEmail(result.Email, result.AccountName); email != "" {
		service.SetCFConfigPublic("cf_email", email)
	}

	logger.Log.Info("Token 权限验证完成", "valid", result.Valid, "all_required", result.AllRequired, "ip", getClientIP(r))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   result,
	})
}

// apiCFTokenSave POST /api/cf/token/save
func apiCFTokenSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}
	req.Token = strings.TrimSpace(req.Token)

	if req.Token == "" {
		sendJSON(w, "error", "Token 不能为空")
		return
	}

	// 先校验 Token 有效性
	result, err := service.VerifyCFTokenPermissions(req.Token)
	if err != nil {
		sendJSON(w, "error", "Token 验证失败: "+err.Error())
		return
	}
	if !result.Valid {
		sendJSON(w, "error", "Token 无效或已过期")
		return
	}

	// 保存 Token 和自动发现的信息
	service.SetCFConfigPublic("cf_api_key", req.Token)
	if result.AccountID != "" {
		service.SetCFConfigPublic("cf_account_id", result.AccountID)
	}
	if email := service.PickBestCFEmail(result.Email, result.AccountName); email != "" {
		service.SetCFConfigPublic("cf_email", email)
	}
	if len(result.Zones) > 0 {
		service.SetCFConfigPublic("cf_domain", result.Zones[0])
	}
	service.SaveTokenVerifyRecord(result)

	logger.Log.Info("CF Token 已保存", "account_id", result.AccountID, "ip", getClientIP(r))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Token 已保存",
		"data":    result,
	})
}

// ------------------- [CF Tunnel 配置管理] -------------------

// apiCFTunnelSettings GET/POST /api/cf/tunnel/settings
// GET: 读取配置（token 脱敏）
// POST: 保存配置
func apiCFTunnelSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		settings := service.GetCFTunnelSettings()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"data":   settings,
		})

	case http.MethodPost:
		var data map[string]string
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			sendJSON(w, "error", "请求格式错误")
			return
		}

		if err := service.SaveCFTunnelSettings(data); err != nil {
			logger.Log.Warn("保存 CF Tunnel 配置失败", "error", err, "ip", getClientIP(r))
			sendJSON(w, "error", err.Error())
			return
		}

		logger.Log.Info("CF Tunnel 配置已保存", "ip", getClientIP(r))
		sendJSON(w, "success", "配置保存成功")

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// apiCFCertSettings GET/POST /api/cf/cert/settings
func apiCFCertSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		keys := []string{
			"cf_domain", "cf_auto_renew", "cf_cert_enabled",
		}
		var configs []database.SysConfig
		database.DB.Where("key IN ?", keys).Find(&configs)

		data := make(map[string]string)
		for _, c := range configs {
			data[c.Key] = c.Value
		}
		if _, ok := data["cf_cert_enabled"]; !ok {
			data["cf_cert_enabled"] = "false"
		}

		zones := make([]string, 0)
		if rec := service.GetLastTokenVerifyRecord(); rec != nil && rec.Result != nil && len(rec.Result.Zones) > 0 {
			zones = rec.Result.Zones
		}
		if len(zones) == 0 {
			if domain := strings.TrimSpace(data["cf_domain"]); domain != "" {
				zones = append(zones, domain)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":          "success",
			"data":            data,
			"cert_info":       service.GetCurrentCertInfo(),
			"available_zones": zones,
		})

	case http.MethodPost:
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSON(w, "error", "请求格式错误")
			return
		}

		validKeys := map[string]bool{
			"cf_domain":       true,
			"cf_auto_renew":   true,
			"cf_cert_enabled": true,
		}

		for k, v := range req {
			if !validKeys[k] {
				continue
			}

			if k == "cf_cert_enabled" {
				v = strings.ToLower(strings.TrimSpace(v))
				if v == "true" || v == "1" {
					if !service.HasValidLocalCertificate() {
						sendJSON(w, "error", "无有效证书，请先申请证书后再启用")
						return
					}
					v = "true"
				} else {
					v = "false"
				}
			}

			if err := database.DB.Model(&database.SysConfig{}).Where("key = ?", k).Update("value", v).Error; err != nil {
				logger.Log.Error("保存 CF 安全配置失败", "key", k, "error", err, "ip", getClientIP(r))
				sendJSON(w, "error", "保存配置失败: "+k)
				return
			}
		}

		sendJSON(w, "success", "配置保存成功")

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// apiCFCertApply POST /api/cf/cert/apply
func apiCFCertApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain string `json:"domain"`
		Token  string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "参数解析失败")
		return
	}
	req.Domain = strings.TrimSpace(req.Domain)
	req.Token = strings.TrimSpace(req.Token)

	email := strings.TrimSpace(service.GetCFConfigPublic("cf_email"))
	apiKey := strings.TrimSpace(service.GetCFConfigPublic("cf_api_key"))
	if apiKey == "" && req.Token != "" {
		apiKey = req.Token
	}
	domain := req.Domain
	if domain == "" {
		domain = strings.TrimSpace(service.GetCFConfigPublic("cf_domain"))
	}

	if email == "" && req.Token != "" {
		if result, err := service.VerifyCFTokenPermissions(req.Token); err == nil && result != nil {
			email = service.PickBestCFEmail(result.Email, result.AccountName)
			if domain == "" && len(result.Zones) > 0 {
				domain = strings.TrimSpace(result.Zones[0])
			}
		}
	}

	// 兜底：若未显式选择域名，则尝试使用最近一次 Token 校验结果中的首个 Zone
	if domain == "" {
		if rec := service.GetLastTokenVerifyRecord(); rec != nil && rec.Result != nil {
			if email == "" {
				email = service.PickBestCFEmail(rec.Result.Email, rec.Result.AccountName)
			}
			if len(rec.Result.Zones) > 0 {
				domain = strings.TrimSpace(rec.Result.Zones[0])
			}
		}
	}

	if email == "" || apiKey == "" || domain == "" {
		missing := make([]string, 0, 3)
		if email == "" {
			missing = append(missing, "邮箱")
		}
		if apiKey == "" {
			missing = append(missing, "API Token")
		}
		if domain == "" {
			missing = append(missing, "证书域名")
		}
		sendJSON(w, "error", "Cloudflare 信息不完整，缺少: "+strings.Join(missing, "、"))
		return
	}

	// SSE 流式返回申请过程日志
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		sendJSON(w, "error", "服务器不支持 SSE 流式响应")
		return
	}

	sendSSE := func(eventType string, payload map[string]interface{}) {
		b, _ := json.Marshal(payload)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, string(b))
		flusher.Flush()
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- service.ApplyCloudflareCert(email, apiKey, domain)
	}()

	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	logIndex := 0
	flushLogs := func() {
		logs := service.GetCertLogs()
		for logIndex < len(logs) {
			msg := logs[logIndex]
			logIndex++
			sendSSE("progress", map[string]interface{}{
				"percent": certLogProgressPercent(msg, logIndex),
				"message": msg,
				"step":    logIndex,
			})
		}
	}

	for {
		select {
		case <-ticker.C:
			flushLogs()
		case err := <-errCh:
			flushLogs()
			if err != nil {
				logger.Log.Error("证书申请失败", "error", err, "ip", getClientIP(r))
				sendSSE("error", map[string]interface{}{
					"message": "申请失败: " + err.Error(),
				})
				return
			}

			sendSSE("done", map[string]interface{}{
				"percent": 100,
				"message": "证书申请成功",
				"domain":  domain,
			})
			return
		}
	}
}

func certLogProgressPercent(msg string, step int) int {
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "开始申请证书"):
		return 5
	case strings.Contains(lower, "注册 acme") || strings.Contains(lower, "账号注册"):
		return 15
	case strings.Contains(lower, "dns-01"):
		return 35
	case strings.Contains(lower, "检查 dns") || strings.Contains(lower, "等待 dns"):
		return 55
	case strings.Contains(lower, "验证成功") || strings.Contains(lower, "请求签发"):
		return 75
	case strings.Contains(lower, "下发证书"):
		return 88
	case strings.Contains(lower, "写入系统") || strings.Contains(lower, "热加载"):
		return 95
	case strings.Contains(lower, "申请 [") && strings.Contains(lower, "成功"):
		return 100
	default:
		p := 8 + step*3
		if p > 96 {
			p = 96
		}
		return p
	}
}

// ------------------- [cloudflared 二进制管理] -------------------

// apiCFTunnelPrepare POST /api/cf/tunnel/cloudflared/prepare
// [FIX-13] SSE 流式返回下载进度
func apiCFTunnelPrepare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 检查是否已存在
	exists, ver := service.CheckCloudflaredBinary()
	if exists {
		sendJSON(w, "success", map[string]interface{}{
			"message": "cloudflared 已就绪",
			"version": ver,
			"exists":  true,
		})
		return
	}

	// 设置 SSE 流式响应
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		sendJSON(w, "error", "服务器不支持 SSE 流式响应")
		return
	}

	// 发送进度事件
	sendSSE := func(eventType, data string) {
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, data)
		flusher.Flush()
	}

	sendSSE("progress", `{"percent": 0, "message": "开始下载 cloudflared..."}`)

	err := service.DownloadCloudflared(func(downloaded, total int64, percent int) {
		var msg string
		if total > 0 {
			msg = fmt.Sprintf("已下载 %.1f / %.1f MB (%d%%)",
				float64(downloaded)/1024/1024, float64(total)/1024/1024, percent)
		} else {
			msg = fmt.Sprintf("已下载 %.1f MB", float64(downloaded)/1024/1024)
		}
		data, _ := json.Marshal(map[string]interface{}{
			"percent":    percent,
			"message":    msg,
			"downloaded": downloaded,
			"total":      total,
		})
		sendSSE("progress", string(data))
	})

	if err != nil {
		logger.Log.Error("下载 cloudflared 失败", "error", err)
		data, _ := json.Marshal(map[string]interface{}{
			"message": "下载失败: " + err.Error(),
		})
		sendSSE("error", string(data))
		return
	}

	_, ver = service.CheckCloudflaredBinary()
	data, _ := json.Marshal(map[string]interface{}{
		"percent": 100,
		"message": "下载完成",
		"version": ver,
	})
	sendSSE("done", string(data))

	logger.Log.Info("cloudflared 下载完成", "version", ver, "ip", getClientIP(r))
}

// ------------------- [Tunnel CRUD] -------------------

// apiCFTunnelCreate POST /api/cf/tunnel/create
// [FIX-03] 幂等创建 Tunnel
func apiCFTunnelCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tunnelID, err := service.CreateCFTunnel()
	if err != nil {
		logger.Log.Error("创建 Tunnel 失败", "error", err, "ip", getClientIP(r))
		sendJSON(w, "error", err.Error())
		return
	}

	logger.Log.Info("Tunnel 创建/复用成功", "tunnel_id", tunnelID, "ip", getClientIP(r))
	sendJSON(w, "success", map[string]interface{}{
		"message":   "Tunnel 创建成功",
		"tunnel_id": tunnelID,
	})
}

// apiCFTunnelDNS POST /api/cf/tunnel/dns
// 绑定子域名 CNAME
func apiCFTunnelDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := service.BindTunnelDNS(); err != nil {
		logger.Log.Error("绑定 DNS 失败", "error", err, "ip", getClientIP(r))
		sendJSON(w, "error", err.Error())
		return
	}

	// 同步更新远程 Ingress 规则（Token 模式下 cloudflared 依赖此配置路由流量）
	if err := service.ConfigureTunnelRemoteIngress(); err != nil {
		logger.Log.Warn("更新远程 Ingress 规则失败（非致命）", "error", err, "ip", getClientIP(r))
	}

	logger.Log.Info("Tunnel DNS 绑定成功", "ip", getClientIP(r))
	sendJSON(w, "success", "DNS 绑定成功")
}

// apiCFTunnelDelete DELETE /api/cf/tunnel/delete
// [FIX-04] 删除 Tunnel + DNS + 本地文件
func apiCFTunnelDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := service.DeleteCFTunnel(); err != nil {
		logger.Log.Error("删除 Tunnel 失败", "error", err, "ip", getClientIP(r))
		sendJSON(w, "error", err.Error())
		return
	}

	logger.Log.Info("Tunnel 已删除", "ip", getClientIP(r))
	sendJSON(w, "success", "Tunnel 已删除")
}

// ------------------- [配置文件生成] -------------------

// apiCFTunnelConfigRender POST /api/cf/tunnel/config/render
func apiCFTunnelConfigRender(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := service.RenderTunnelConfig(); err != nil {
		logger.Log.Error("生成 Tunnel 配置失败", "error", err, "ip", getClientIP(r))
		sendJSON(w, "error", err.Error())
		return
	}

	logger.Log.Info("Tunnel 配置文件已生成", "ip", getClientIP(r))
	sendJSON(w, "success", "配置文件已生成")
}

// ------------------- [运行控制] -------------------

// apiCFTunnelRun POST /api/cf/tunnel/run
func apiCFTunnelRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := service.StartCFTunnel(); err != nil {
		logger.Log.Error("启动 Tunnel 失败", "error", err, "ip", getClientIP(r))
		sendJSON(w, "error", err.Error())
		return
	}

	// [FIX-08] panel_url 智能回写
	handlePanelURLWriteback(r)

	logger.Log.Info("Tunnel 已启动", "ip", getClientIP(r))
	sendJSON(w, "success", "Tunnel 已启动")
}

// apiCFTunnelStop POST /api/cf/tunnel/stop
func apiCFTunnelStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	service.StopCFTunnel()
	logger.Log.Info("Tunnel 已停止", "ip", getClientIP(r))
	sendJSON(w, "success", "Tunnel 已停止")
}

// ------------------- [状态查询] -------------------

// apiCFTunnelStatus GET /api/cf/tunnel/status
func apiCFTunnelStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	status := service.GetCFTunnelStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   status,
	})
}

// apiCFTunnelList GET /api/cf/tunnel/list
// 按前缀查询 Tunnel 列表（默认 prefix=wirearc）
func apiCFTunnelList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	prefix := strings.TrimSpace(r.URL.Query().Get("prefix"))
	if prefix == "" {
		prefix = "wirearc"
	}

	items, err := service.ListCFTunnelsByPrefix(prefix)
	if err != nil {
		logger.Log.Warn("查询 Tunnel 列表失败", "error", err, "prefix", prefix, "ip", getClientIP(r))
		sendJSON(w, "error", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   items,
	})
}

// apiCFTunnelDeleteByID POST /api/cf/tunnel/delete-by-id
func apiCFTunnelDeleteByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		TunnelID string `json:"tunnel_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}
	req.TunnelID = strings.TrimSpace(req.TunnelID)
	if req.TunnelID == "" {
		sendJSON(w, "error", "tunnel_id 不能为空")
		return
	}

	if err := service.DeleteCFTunnelByID(req.TunnelID); err != nil {
		logger.Log.Warn("删除指定 Tunnel 失败", "error", err, "tunnel_id", req.TunnelID, "ip", getClientIP(r))
		sendJSON(w, "error", err.Error())
		return
	}

	sendJSON(w, "success", "Tunnel 已删除")
}

// ------------------- [辅助函数] -------------------

// handlePanelURLWriteback [FIX-08] panel_url 智能回写
// 仅当 panel_url 为空时自动填写
func handlePanelURLWriteback(r *http.Request) {
	settings := service.GetCFTunnelSettings()
	subdomain := settings.TunnelSubdomain
	if subdomain == "" {
		return
	}

	currentPanelURL := service.GetCFConfigPublic("panel_url")
	if currentPanelURL == "" {
		newURL := "https://" + subdomain
		service.SetCFConfigPublic("panel_url", newURL)
		logger.Log.Info("panel_url 已自动回填", "value", newURL, "ip", getClientIP(r))
	}
}

// ------------------- [懒人模式: 自动发现] -------------------

// apiCFTunnelDetect POST /api/cf/tunnel/detect
// 通过 Token 自动发现 Account ID、域名列表等信息
func apiCFTunnelDetect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}

	if req.Token == "" {
		req.Token = service.GetCFConfigPublic("cf_api_key")
	}

	if req.Token == "" {
		sendJSON(w, "error", "Token 不能为空")
		return
	}

	result, err := service.AutoDiscoverCFAccount(req.Token)
	if err != nil {
		logger.Log.Warn("CF 自动发现失败", "error", err, "ip", getClientIP(r))
		sendJSON(w, "error", err.Error())
		return
	}

	logger.Log.Info("CF 自动发现成功", "account_id", result.AccountID, "ip", getClientIP(r))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   result,
	})
}

// ------------------- [懒人模式: 一键部署] -------------------

// apiCFTunnelOneClick POST /api/cf/tunnel/oneclick
// SSE 流式返回一键部署进度
func apiCFTunnelOneClick(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Token      string `json:"token"`
		Subdomain  string `json:"subdomain"`
		Domain     string `json:"domain"`
		TunnelName string `json:"tunnel_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}

	if req.Token == "" {
		req.Token = service.GetCFConfigPublic("cf_api_key")
	}

	if req.Token == "" {
		sendJSON(w, "error", "Token 不能为空")
		return
	}

	// 设置 SSE 流式响应
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		sendJSON(w, "error", "服务器不支持 SSE 流式响应")
		return
	}

	sendSSE := func(eventType, data string) {
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, data)
		flusher.Flush()
	}

	err := service.OneClickSetupCFTunnel(req.Token, req.Subdomain, req.Domain, req.TunnelName,
		func(p service.OneClickSetupProgress) {
			data, _ := json.Marshal(p)
			sendSSE("progress", string(data))
		},
	)

	if err != nil {
		logger.Log.Error("一键部署失败", "error", err, "ip", getClientIP(r))
		errData, _ := json.Marshal(map[string]interface{}{
			"message": "部署失败: " + err.Error(),
		})
		sendSSE("error", string(errData))
		return
	}

	// 部署成功
	settings := service.GetCFTunnelSettings()
	doneData, _ := json.Marshal(map[string]interface{}{
		"message":   "🎉 一键部署完成！",
		"panel_url": "https://" + settings.TunnelSubdomain,
		"tunnel_id": settings.TunnelID,
		"subdomain": settings.TunnelSubdomain,
	})
	sendSSE("done", string(doneData))

	logger.Log.Info("一键部署成功", "subdomain", settings.TunnelSubdomain, "ip", getClientIP(r))
}

// ------------------- [Token 校验记录] -------------------

// ------------------- [cloudflared 版本检查与更新] -------------------

// apiCFTunnelVersionStatus GET /api/cf/tunnel/version-status
// 获取 cloudflared 版本状态（本地版本、远程版本、是否需要更新）
func apiCFTunnelVersionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	localVer, remoteVer, state := service.GetCloudflaredVersionStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"local_version":  localVer,
			"remote_version": remoteVer,
			"state":          state,
		},
	})
}

// apiCFTunnelForceUpdate POST /api/cf/tunnel/force-update
// 强制更新 cloudflared 到最新版本
func apiCFTunnelForceUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	go func() {
		if err := service.ForceUpdateCloudflared(); err != nil {
			logger.Log.Error("cloudflared 手动更新失败", "error", err)
		}
	}()

	logger.Log.Info("cloudflared 手动更新已触发", "ip", getClientIP(r))
	sendJSON(w, "success", "已开始更新 cloudflared")
}

// apiCFGetLastTokenVerify GET /api/cf/token/last-verify
// 获取最近一次 Token 权限校验记录（持久化，跨会话有效）
func apiCFGetLastTokenVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	record := service.GetLastTokenVerifyRecord()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   record,
	})
}
