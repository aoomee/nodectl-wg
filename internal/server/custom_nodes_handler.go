package server

import (
	"encoding/json"
	"net/http"

	"wirearc/internal/logger"
	"wirearc/internal/service"
)

// ------------------- [自定义节点 API] -------------------

// apiCustomNodesList 获取所有自定义节点
func apiCustomNodesList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	nodes, err := service.ListCustomNodes()
	if err != nil {
		logger.Log.Error("获取自定义节点列表失败", "error", err)
		sendJSON(w, "error", "获取列表失败")
		return
	}

	sendJSON(w, "success", map[string]interface{}{
		"nodes": nodes,
	})
}

// apiCustomNodesAdd 添加自定义节点
func apiCustomNodesAdd(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Link        string `json:"link"`
		RoutingType int    `json:"routing_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Log.Warn("添加自定义节点: JSON 解析失败", "error", err, "ip", clientIP)
		sendJSON(w, "error", "请求格式错误")
		return
	}

	if req.Link == "" {
		sendJSON(w, "error", "协议链接不能为空")
		return
	}

	node, err := service.AddCustomNode(req.Link, req.RoutingType)
	if err != nil {
		sendJSON(w, "error", "添加失败: "+err.Error())
		return
	}

	logger.Log.Info("自定义节点添加成功", "id", node.ID, "name", node.Name, "ip", clientIP)
	sendJSON(w, "success", map[string]interface{}{
		"message": "添加成功",
		"node":    node,
	})
}

// apiCustomNodesUpdate 更新自定义节点
func apiCustomNodesUpdate(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID          string `json:"id"`
		Link        string `json:"link"`
		RoutingType int    `json:"routing_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Log.Warn("更新自定义节点: JSON 解析失败", "error", err, "ip", clientIP)
		sendJSON(w, "error", "请求格式错误")
		return
	}

	if req.ID == "" {
		sendJSON(w, "error", "缺少节点 ID")
		return
	}
	if req.Link == "" {
		sendJSON(w, "error", "协议链接不能为空")
		return
	}

	if err := service.UpdateCustomNode(req.ID, req.Link, req.RoutingType); err != nil {
		sendJSON(w, "error", "更新失败: "+err.Error())
		return
	}

	logger.Log.Info("自定义节点更新成功", "id", req.ID, "ip", clientIP)
	sendJSON(w, "success", "更新成功")
}

// apiCustomNodesDelete 删除自定义节点
func apiCustomNodesDelete(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Log.Warn("删除自定义节点: JSON 解析失败", "error", err, "ip", clientIP)
		sendJSON(w, "error", "请求格式错误")
		return
	}

	if req.ID == "" {
		sendJSON(w, "error", "缺少节点 ID")
		return
	}

	if err := service.DeleteCustomNode(req.ID); err != nil {
		sendJSON(w, "error", "删除失败: "+err.Error())
		return
	}

	logger.Log.Info("自定义节点删除成功", "id", req.ID, "ip", clientIP)
	sendJSON(w, "success", "删除成功")
}
