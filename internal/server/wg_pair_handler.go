package server

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"

	"nodectl/internal/logger"
	"nodectl/internal/service"
)

func wgPairDecodeRequest(w http.ResponseWriter, r *http.Request, body any) bool {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		wgPairError(w, http.StatusMethodNotAllowed, "请求方法不支持")
		return false
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		wgPairError(w, http.StatusUnsupportedMediaType, "请求必须为 JSON")
		return false
	}
	if r.Header.Get("X-NodeCtl-WG") != "1" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		wgPairError(w, http.StatusForbidden, "请求来源校验失败，请从面板操作")
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, parseErr := url.Parse(origin)
		if parseErr != nil || u.Host != r.Host || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
			wgPairError(w, http.StatusForbidden, "请求来源不匹配")
			return false
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(body) != nil {
		wgPairError(w, http.StatusBadRequest, "请求格式不正确或内容过大")
		return false
	}
	if d.Decode(&struct{}{}) != io.EOF {
		wgPairError(w, http.StatusBadRequest, "请求必须是单个 JSON 对象")
		return false
	}
	return true
}

// Register both handlers behind withAuthAndSecure.
func apiWGPairOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		wgPairError(w, http.StatusMethodNotAllowed, "请求方法不支持")
		return
	}
	id := r.URL.Query().Get("uuid")
	if id == "" || len(id) > 36 {
		wgPairError(w, 400, "无效的节点标识")
		return
	}
	data, err := service.WGPairOptions(id)
	if err != nil {
		if logger.Log != nil {
			logger.Log.Warn("读取 WG 配对选项失败", "node_uuid", id, "error", err)
		}
		wgPairError(w, 409, "暂时无法读取 WG 配对状态，请刷新重试")
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "data": data})
}
func apiWGPairPush(w http.ResponseWriter, r *http.Request) {
	var request service.WGPairPush
	if !wgPairDecodeRequest(w, r, &request) {
		return
	}
	if request.UUID == "" || len(request.UUID) > 36 || request.Revision < 1 || (request.Enabled && (request.PeerUUID == "" || len(request.PeerUUID) > 36 || request.EntryPort < 0 || request.EntryPort > 65535)) {
		wgPairError(w, 400, "无效的 WG 配对参数")
		return
	}
	data, err := service.SaveWGPair(r.Context(), request)
	if err != nil {
		if logger.Log != nil {
			logger.Log.Warn("保存 WG 配对配置失败", "node_uuid", request.UUID, "peer_uuid", request.PeerUUID, "enabled", request.Enabled, "error", err)
		}
		msg := "配对冲突或前置条件未满足；请确认两端协议与 Agent 就绪，或先停用并完成清理"
		if errors.Is(err, service.ErrWGConflict) {
			msg = "配对版本冲突或目标节点已被其他 WG 配对占用，请刷新状态后重试"
		}
		wgPairError(w, 409, msg)
		return
	}
	// The transaction is committed, but activation is solely reconciler-owned.
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "data": map[string]interface{}{"pair": data}})
}
func wgPairError(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": message})
}
