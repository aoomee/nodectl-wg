package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"nodectl/internal/database"
	"nodectl/internal/logger"
	"nodectl/internal/service"
)

// ------------------- [流量统计 API] -------------------

// apiGetTrafficLandingNodes 返回用于流量统计的落地节点列表
func apiGetTrafficLandingNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	nodes, err := service.GetTrafficLandingNodes()
	if err != nil {
		logger.Log.Error("查询流量统计节点列表失败", "error", err)
		sendJSON(w, "error", "读取节点列表失败")
		return
	}

	sendJSON(w, "success", map[string]interface{}{
		"nodes": nodes,
	})
}

// apiGetTrafficSeries 查询节点流量时序统计（支持总量/增量、1h/2h）
func apiGetTrafficSeries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	nodeUUID := strings.TrimSpace(r.URL.Query().Get("node_uuid"))
	hours := 24
	if raw := strings.TrimSpace(r.URL.Query().Get("hours")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			hours = parsed
		}
	}

	intervalHours := 1
	if raw := strings.TrimSpace(r.URL.Query().Get("interval_hours")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			intervalHours = parsed
		}
	}

	mode := strings.TrimSpace(r.URL.Query().Get("mode"))
	rankDate := strings.TrimSpace(r.URL.Query().Get("date"))
	rawPoints := false
	if raw := strings.TrimSpace(r.URL.Query().Get("raw")); raw != "" {
		rawPoints = raw == "1" || strings.EqualFold(raw, "true")
	}

	result, err := service.QueryTrafficSeries(service.TrafficSeriesOptions{
		NodeUUID:      nodeUUID,
		Hours:         hours,
		IntervalHours: intervalHours,
		Mode:          mode,
		Date:          rankDate,
		Raw:           rawPoints,
	})
	if err != nil {
		logger.Log.Warn("查询流量统计数据失败", "error", err, "node_uuid", nodeUUID, "date", rankDate)
		sendJSON(w, "error", "查询流量统计失败")
		return
	}

	sendJSON(w, "success", map[string]interface{}{
		"series":                     result,
		"point_persist_interval_sec": service.GetTrafficPointPersistIntervalSec(),
	})
}

// apiGetTrafficConsumptionRank 返回节点流量消耗排行榜（支持按日期查询）
func apiGetTrafficConsumptionRank(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	limit := 30
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	rankDate := strings.TrimSpace(r.URL.Query().Get("date"))

	rank, err := service.GetTrafficConsumptionRank(limit, rankDate)
	if err != nil {
		logger.Log.Warn("查询流量消耗排行失败", "error", err, "date", rankDate)
		sendJSON(w, "error", "读取流量消耗排行失败")
		return
	}

	sendJSON(w, "success", map[string]interface{}{
		"rank": rank,
	})
}

// apiCallbackTrafficWS Agent WebSocket 统一上报通道
// 路由: /api/callback/traffic/ws
// 无需登录鉴权 (Agent 通过 install_id 身份识别)
func apiCallbackTrafficWS(w http.ResponseWriter, r *http.Request) {
	service.HandleAgentWS(w, r)
}

// apiTrafficLive 前端实时流量订阅 (WebSocket)
// 路由: /api/traffic/live?node_uuid=...
// 需要登录鉴权
func apiTrafficLive(w http.ResponseWriter, r *http.Request) {
	service.HandleTrafficLive(w, r)
}

// apiClearNodeTrafficHistory 清除指定节点的历史流量统计数据
// 路由: POST /api/traffic/clear-history
// 请求体: { "uuid": "节点UUID" }
// 注意：仅清除历史采样点数据（node_traffic_stats），不影响累计流量（traffic_up/traffic_down）
func apiClearNodeTrafficHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		UUID string `json:"uuid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}
	req.UUID = strings.TrimSpace(req.UUID)
	if req.UUID == "" {
		sendJSON(w, "error", "缺少节点 UUID")
		return
	}

	// 校验节点是否存在
	var node database.NodePool
	if err := database.DB.Select("uuid", "name").Where("uuid = ?", req.UUID).First(&node).Error; err != nil {
		sendJSON(w, "error", "节点不存在")
		return
	}

	deleted, err := service.ClearNodeTrafficHistory(req.UUID)
	if err != nil {
		logger.Log.Error("清除节点历史流量数据失败", "uuid", req.UUID, "name", node.Name, "error", err)
		sendJSON(w, "error", "清除失败: "+err.Error())
		return
	}

	logger.Log.Info("节点历史流量数据已清除", "uuid", req.UUID, "name", node.Name, "deleted", deleted)
	sendJSON(w, "success", map[string]interface{}{
		"message": fmt.Sprintf("已清除 %d 条历史流量记录", deleted),
		"deleted": deleted,
	})
}

// apiGetNodeTrafficHistoryCount 获取指定节点的历史流量记录条数
// 路由: GET /api/traffic/history-count?uuid=...
func apiGetNodeTrafficHistoryCount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	nodeUUID := strings.TrimSpace(r.URL.Query().Get("uuid"))
	if nodeUUID == "" {
		sendJSON(w, "error", "缺少节点 UUID")
		return
	}

	count := service.GetNodeTrafficHistoryCount(nodeUUID)
	sendJSON(w, "success", map[string]interface{}{
		"uuid":  nodeUUID,
		"count": count,
	})
}
