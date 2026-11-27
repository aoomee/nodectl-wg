// 路径: internal/server/cf_ipopt_handlers.go
// Cloudflare IP 优选 API Handler
package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"wirearc/internal/logger"
	"wirearc/internal/service"
)

// ===================== 设置类 API =====================

// apiCFIPOptSettings GET/POST /api/cf/ipopt/settings
// 获取或保存优选设置
func apiCFIPOptSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// 获取设置
		settings := service.GetCFIPOptSettings()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"data":   settings,
		})
		return
	}

	if r.Method == http.MethodPost {
		// 保存设置
		var req struct {
			ScheduleInterval     int    `json:"schedule_interval"`
			ApplyToTunnelNodes   bool   `json:"apply_to_tunnel_nodes"`
			SpeedTestURL         string `json:"speed_test_url"`
			ScheduleSpeedTestURL string `json:"schedule_speed_test_url"`
			DebugMode            bool   `json:"debug_mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSON(w, "error", "请求格式错误")
			return
		}

		// 验证间隔值
		if req.ScheduleInterval != 0 && req.ScheduleInterval != 6 && req.ScheduleInterval != 12 && req.ScheduleInterval != 24 {
			sendJSON(w, "error", "间隔值无效，可选值：0（关闭）、6、12、24 小时")
			return
		}

		// 验证测速地址格式（如果不为空）
		speedURL := strings.TrimSpace(req.SpeedTestURL)
		if speedURL != "" {
			// 基本验证：必须以 http:// 或 https:// 开头
			if !strings.HasPrefix(speedURL, "http://") && !strings.HasPrefix(speedURL, "https://") {
				sendJSON(w, "error", "测速地址格式错误，必须以 http:// 或 https:// 开头")
				return
			}
		}

		// 验证定时优选测速地址格式（如果不为空）
		scheduleSpeedURL := strings.TrimSpace(req.ScheduleSpeedTestURL)
		if scheduleSpeedURL != "" {
			if !strings.HasPrefix(scheduleSpeedURL, "http://") && !strings.HasPrefix(scheduleSpeedURL, "https://") {
				sendJSON(w, "error", "定时优选测速地址格式错误，必须以 http:// 或 https:// 开头")
				return
			}
		}

		// 如果要开启应用到 Tunnel 节点，检查是否有可用的优选结果
		if req.ApplyToTunnelNodes && !service.HasValidIPOptResult() {
			sendJSON(w, "error", "无可用的优选结果，请先执行一次优选任务")
			return
		}

		service.SetCFIPOptSettings(req.ScheduleInterval, req.ApplyToTunnelNodes)
		service.SetCFIPOptSpeedTestURL(speedURL)
		service.SetCFIPOptScheduleSpeedTestURL(scheduleSpeedURL)
		service.SetCFIPOptDebugMode(req.DebugMode)

		// 更新定时调度器
		if req.ScheduleInterval > 0 {
			service.StartCFIPOptScheduler()
		} else {
			service.StopCFIPOptScheduler()
		}

		logger.Log.Info("CF 优选设置已更新", "ip", getClientIP(r), "interval", req.ScheduleInterval, "apply", req.ApplyToTunnelNodes, "speed_url", speedURL, "schedule_speed_url", scheduleSpeedURL, "debug", req.DebugMode)
		sendJSON(w, "success", "设置已保存")
		return
	}

	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

// ===================== 二进制管理 API =====================

// apiCFIPOptBinaryStatus GET /api/cf/ipopt/binary/status
// 获取二进制状态
func apiCFIPOptBinaryStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	status := service.GetCFIPOptBinaryStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   status,
	})
}

// apiCFIPOptBinaryDownload POST /api/cf/ipopt/binary/download
// 触发自动下载 CloudflareST 二进制（SSE 推送进度）
func apiCFIPOptBinaryDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 启动下载，获取进度通道
	progressChan, err := service.DownloadCFIPOptBinary()
	if err != nil {
		sendJSON(w, "error", err.Error())
		return
	}

	// 设置 SSE 响应头
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		sendJSON(w, "error", "不支持 SSE")
		return
	}

	// 推送进度
	for progress := range progressChan {
		data, _ := json.Marshal(progress)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}

	// 发送完成事件
	fmt.Fprintf(w, "data: {\"status\":\"stream_end\"}\n\n")
	flusher.Flush()

	logger.Log.Info("CloudflareST 二进制下载流程完成", "ip", getClientIP(r))
}

// ===================== 任务控制 API =====================

// apiCFIPOptStart POST /api/cf/ipopt/start
// 启动优选任务
func apiCFIPOptStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	taskID, err := service.StartCFIPOptTask()
	if err != nil {
		sendJSON(w, "error", err.Error())
		return
	}

	logger.Log.Info("CF 优选任务已启动", "ip", getClientIP(r), "task_id", taskID)
	sendJSON(w, "success", map[string]string{"task_id": taskID})
}

// apiCFIPOptStop POST /api/cf/ipopt/stop
// 停止当前任务
func apiCFIPOptStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := service.StopCFIPOptTask(); err != nil {
		sendJSON(w, "error", err.Error())
		return
	}

	logger.Log.Info("CF 优选任务已停止", "ip", getClientIP(r))
	sendJSON(w, "success", "任务已停止")
}

// ===================== 进度推送 API（SSE） =====================

// apiCFIPOptProgressStream GET /api/cf/ipopt/progress/stream
// SSE 实时进度推送
func apiCFIPOptProgressStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 设置 SSE 响应头
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		sendJSON(w, "error", "不支持 SSE")
		return
	}

	// 发送初始状态
	initialState := service.GetCFIPOptProgress()
	data, _ := json.Marshal(initialState)
	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()

	// 如果不是 running 状态，直接返回
	if initialState.Status != "running" {
		fmt.Fprintf(w, "data: {\"status\":\"stream_end\"}\n\n")
		flusher.Flush()
		return
	}

	// 轮询状态变化
	ctx := r.Context()

	lastProgress := initialState.Progress
	lastLogVer := initialState.LogVer

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(300 * time.Millisecond):
			// 每 300ms 轮询一次状态（加快响应速度）
		}

		state := service.GetCFIPOptProgress()

		// 检查状态变化或日志版本号变化
		if state.Progress != lastProgress || state.LogVer != lastLogVer || state.Status != "running" {
			data, _ := json.Marshal(state)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()

			lastProgress = state.Progress
			lastLogVer = state.LogVer
		}

		// 如果任务完成或失败，发送结束事件
		if state.Status != "running" {
			fmt.Fprintf(w, "data: {\"status\":\"stream_end\"}\n\n")
			flusher.Flush()
			return
		}
	}
}

// ===================== 结果查询 API =====================

// apiCFIPOptResult GET /api/cf/ipopt/result
// 获取最近一次优选结果
func apiCFIPOptResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	result, err := service.GetCFIPOptResult()
	if err != nil {
		sendJSON(w, "error", err.Error())
		return
	}

	if result == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "success",
			"data":    nil,
			"message": "暂无优选结果",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   result,
	})
}

// ===================== 应用开关 API =====================

// apiCFIPOptApply POST /api/cf/ipopt/apply
// 切换优选应用到 Tunnel 节点的开关
func apiCFIPOptApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}

	// 如果要开启，检查是否有可用的优选结果
	if req.Enabled && !service.HasValidIPOptResult() {
		sendJSON(w, "error", "无可用的优选结果，请先执行一次优选任务")
		return
	}

	// 获取当前设置
	settings := service.GetCFIPOptSettings()
	service.SetCFIPOptSettings(settings.ScheduleInterval, req.Enabled)

	logger.Log.Info("CF 优选应用开关已更新", "ip", getClientIP(r), "enabled", req.Enabled)

	action := "关闭"
	if req.Enabled {
		action = "开启"
	}
	sendJSON(w, "success", fmt.Sprintf("已%s优选 IP 应用到 Tunnel 节点", action))
}

// ===================== 辅助函数 =====================

// apiCFIPOptToggleApply 切换应用开关（简化版）
func apiCFIPOptToggleApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 检查是否有可用的优选结果
	if !service.HasValidIPOptResult() {
		sendJSON(w, "error", "无可用的优选结果，请先执行一次优选任务")
		return
	}

	// 获取当前设置并切换
	settings := service.GetCFIPOptSettings()
	newValue := !settings.ApplyToTunnelNodes
	service.SetCFIPOptSettings(settings.ScheduleInterval, newValue)

	logger.Log.Info("CF 优选应用开关已切换", "ip", getClientIP(r), "enabled", newValue)

	status := "已关闭"
	if newValue {
		status = "已开启"
	}
	sendJSON(w, "success", map[string]interface{}{
		"enabled": newValue,
		"message": status,
	})
}

// ===================== 测速地址管理 API =====================

// apiCFIPOptSpeedURLs GET /api/cf/ipopt/speed-urls
// 获取所有测速地址列表
func apiCFIPOptSpeedURLs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	urls := service.GetSpeedTestURLs()
	defaultID := service.GetDefaultSpeedTestURLID()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "success",
		"urls":       urls,
		"default_id": defaultID,
	})
}

// apiCFIPOptSpeedURLAdd POST /api/cf/ipopt/speed-urls/add
// 添加测速地址
func apiCFIPOptSpeedURLAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.URL = strings.TrimSpace(req.URL)

	item, err := service.AddSpeedTestURL(req.Name, req.URL)
	if err != nil {
		sendJSON(w, "error", err.Error())
		return
	}

	logger.Log.Info("添加测速地址", "ip", getClientIP(r), "name", req.Name, "url", req.URL)
	sendJSON(w, "success", map[string]interface{}{
		"message": "添加成功",
		"item":    item,
	})
}

// apiCFIPOptSpeedURLUpdate POST /api/cf/ipopt/speed-urls/update
// 更新测速地址
func apiCFIPOptSpeedURLUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.URL = strings.TrimSpace(req.URL)

	if err := service.UpdateSpeedTestURL(req.ID, req.Name, req.URL); err != nil {
		sendJSON(w, "error", err.Error())
		return
	}

	logger.Log.Info("更新测速地址", "ip", getClientIP(r), "id", req.ID, "name", req.Name, "url", req.URL)
	sendJSON(w, "success", "更新成功")
}

// apiCFIPOptSpeedURLDelete POST /api/cf/ipopt/speed-urls/delete
// 删除测速地址
func apiCFIPOptSpeedURLDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}

	if err := service.DeleteSpeedTestURL(req.ID); err != nil {
		sendJSON(w, "error", err.Error())
		return
	}

	logger.Log.Info("删除测速地址", "ip", getClientIP(r), "id", req.ID)
	sendJSON(w, "success", "删除成功")
}

// apiCFIPOptSpeedURLSetDefault POST /api/cf/ipopt/speed-urls/set-default
// 设置定时优选默认测速地址
func apiCFIPOptSpeedURLSetDefault(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}

	if err := service.SetDefaultSpeedTestURL(req.ID); err != nil {
		sendJSON(w, "error", err.Error())
		return
	}

	logger.Log.Info("设置定时优选默认测速地址", "ip", getClientIP(r), "id", req.ID)
	sendJSON(w, "success", "设置成功")
}

// ===================== 手动优选列表 API =====================

// apiCFIPOptManualList GET /api/cf/ipopt/manual/list
// 获取手动优选IP列表
func apiCFIPOptManualList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	ips := service.GetManualIPOptList()
	priority := service.GetManualIPOptPriority()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "success",
		"ips":      ips,
		"priority": priority,
	})
}

// apiCFIPOptManualAdd POST /api/cf/ipopt/manual/add
// 添加手动优选IP
func apiCFIPOptManualAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Remark string `json:"remark"`
		IP     string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}

	req.Remark = strings.TrimSpace(req.Remark)
	req.IP = strings.TrimSpace(req.IP)

	if req.IP == "" {
		sendJSON(w, "error", "IP地址不能为空")
		return
	}

	item, err := service.AddManualIPOpt(req.Remark, req.IP)
	if err != nil {
		sendJSON(w, "error", err.Error())
		return
	}

	logger.Log.Info("添加手动优选IP", "ip", getClientIP(r), "remark", req.Remark, "target_ip", req.IP)
	sendJSON(w, "success", map[string]interface{}{
		"message": "添加成功",
		"item":    item,
	})
}

// apiCFIPOptManualUpdate POST /api/cf/ipopt/manual/update
// 更新手动优选IP
func apiCFIPOptManualUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID     string `json:"id"`
		Remark string `json:"remark"`
		IP     string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}

	req.Remark = strings.TrimSpace(req.Remark)
	req.IP = strings.TrimSpace(req.IP)

	if err := service.UpdateManualIPOpt(req.ID, req.Remark, req.IP); err != nil {
		sendJSON(w, "error", err.Error())
		return
	}

	logger.Log.Info("更新手动优选IP", "ip", getClientIP(r), "id", req.ID, "remark", req.Remark, "target_ip", req.IP)
	sendJSON(w, "success", "更新成功")
}

// apiCFIPOptManualDelete POST /api/cf/ipopt/manual/delete
// 删除手动优选IP
func apiCFIPOptManualDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}

	if err := service.DeleteManualIPOpt(req.ID); err != nil {
		sendJSON(w, "error", err.Error())
		return
	}

	logger.Log.Info("删除手动优选IP", "ip", getClientIP(r), "id", req.ID)
	sendJSON(w, "success", "删除成功")
}

// apiCFIPOptManualToggle POST /api/cf/ipopt/manual/toggle
// 切换手动优选IP启用状态
func apiCFIPOptManualToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}

	if err := service.ToggleManualIPOpt(req.ID, req.Enabled); err != nil {
		sendJSON(w, "error", err.Error())
		return
	}

	logger.Log.Info("切换手动优选IP启用状态", "ip", getClientIP(r), "id", req.ID, "enabled", req.Enabled)
	sendJSON(w, "success", "操作成功")
}

// apiCFIPOptManualPriority POST /api/cf/ipopt/manual/priority
// 设置手动优选IP优先级
func apiCFIPOptManualPriority(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Priority string `json:"priority"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}

	// 验证优先级值
	if req.Priority != "disabled" && req.Priority != "preferred" {
		sendJSON(w, "error", "无效的优先级值，可选值：disabled、preferred")
		return
	}

	if err := service.SetManualIPOptPriority(req.Priority); err != nil {
		sendJSON(w, "error", err.Error())
		return
	}

	// 如果设置为首选，停用定时优选
	if req.Priority == "preferred" {
		service.StopCFIPOptScheduler()
		logger.Log.Info("手动优选IP设为首选，定时优选功能已停用", "ip", getClientIP(r))
	}

	logger.Log.Info("设置手动优选IP优先级", "ip", getClientIP(r), "priority", req.Priority)
	sendJSON(w, "success", "设置成功")
}

// ===================== CloudflareST 版本检查与更新 API =====================

// apiCFIPOptVersionStatus GET /api/cf/ipopt/version-status
// 获取 CloudflareST 版本状态（本地版本、远程版本、是否需要更新）
func apiCFIPOptVersionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	localVer, remoteVer, state := service.GetCFIPOptVersionStatus()
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

// apiCFIPOptForceUpdate POST /api/cf/ipopt/force-update
// 强制更新 CloudflareST 到最新版本
func apiCFIPOptForceUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	go func() {
		if err := service.ForceUpdateCFIPOpt(); err != nil {
			logger.Log.Error("CloudflareST 手动更新失败", "error", err)
		}
	}()

	logger.Log.Info("CloudflareST 手动更新已触发", "ip", getClientIP(r))
	sendJSON(w, "success", "已开始更新 CloudflareST")
}
