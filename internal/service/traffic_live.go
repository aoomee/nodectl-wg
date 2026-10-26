// 路径: internal/service/traffic_live.go
// WebSocket 实时流量中枢：Agent 上报 + 前端订阅
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"nodectl/internal/database"
	"nodectl/internal/logger"

	"nhooyr.io/websocket"
)

const (
	agentWSPushIntervalSec   = 2
	recentTrafficOnlineGrace = 2 * time.Second
	liveSnapshotInterval     = 1 * time.Second
)

// getAgentReadTimeout 根据固定 2 秒上报间隔计算 WS 读超时。
// 规则：timeout = max(15s, interval*4+5s)，并限制最大 10 分钟。
func getAgentReadTimeout() time.Duration {
	const (
		minTimeout = 15 * time.Second
		maxTimeout = 10 * time.Minute
	)

	sec := agentWSPushIntervalSec

	timeout := time.Duration(sec*4+5) * time.Second
	if timeout < minTimeout {
		return minTimeout
	}
	if timeout > maxTimeout {
		return maxTimeout
	}
	return timeout
}

func hasRecentTrafficSignal(lastLiveAt, now time.Time) bool {
	if lastLiveAt.IsZero() {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	return now.Sub(lastLiveAt) <= recentTrafficOnlineGrace
}

// ============================================================
//  通用辅助函数
// ============================================================

// getClientIP 从请求中提取真实客户端 IP（支持反向代理场景）
func getClientIP(r *http.Request) string {
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ip := strings.TrimSpace(strings.Split(xff, ",")[0]); ip != "" {
			return ip
		}
	}
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		if bracketIdx := strings.LastIndex(ip, "]"); bracketIdx != -1 {
			return strings.Trim(ip[:bracketIdx+1], "[]")
		}
		return ip[:idx]
	}
	return ip
}

// ============================================================
//  数据结构
// ============================================================

// AgentTrafficMsg Agent 上报的动态 JSON 消息
type AgentTrafficMsg struct {
	InstallID    string `json:"install_id"`
	TS           int64  `json:"ts"`
	RXRateBps    int64  `json:"rx_rate_bps"`
	TXRateBps    int64  `json:"tx_rate_bps"`
	CounterRX    int64  `json:"counter_rx_bytes"`
	CounterTX    int64  `json:"counter_tx_bytes"`
	BootID       string `json:"boot_id"`
	AgentVersion string `json:"agent_version,omitempty"`
}

// NodeLiveState 节点实时内存态
type NodeLiveState struct {
	InstallID     string    `json:"install_id"`
	NodeUUID      string    `json:"node_uuid"`
	RXRateBps     int64     `json:"rx_rate_bps"`
	TXRateBps     int64     `json:"tx_rate_bps"`
	LastLiveAt    time.Time `json:"last_live_at"`
	AgentVersion  string    `json:"agent_version,omitempty"` // Agent 上报的版本号
	TotalRXBytes  int64     `json:"total_rx_bytes"`
	TotalTXBytes  int64     `json:"total_tx_bytes"`
	LastCounterRX int64
	LastCounterTX int64
	CounterBootID string
	CounterSeen   bool
	Dirty         bool
}

// FrontendPushMsg 推送给前端的实时消息
type FrontendPushMsg struct {
	InstallID    string `json:"install_id"`
	NodeUUID     string `json:"node_uuid"`
	RXRateBps    int64  `json:"rx_rate_bps"`
	TXRateBps    int64  `json:"tx_rate_bps"`
	TotalRXBytes int64  `json:"total_rx_bytes"`
	TotalTXBytes int64  `json:"total_tx_bytes"`
	LastLiveAt   int64  `json:"last_live_at"` // Unix 秒
	Offline      bool   `json:"offline"`
}

// ============================================================
//  全局 Hub（生命周期在路由器外，热重启不丢失）
// ============================================================

// AgentCommand 后端→Agent 下发命令结构
type AgentCommand struct {
	Type      string      `json:"type"`       // 固定 "command"
	CommandID string      `json:"command_id"` // 幂等键
	Action    string      `json:"action"`     // "reset-links" / "reinstall-singbox" / "check-agent-update"
	Payload   interface{} `json:"payload,omitempty"`
}

// AgentCommandResult Agent 回传命令执行结果
type AgentCommandResult struct {
	Data      json.RawMessage `json:"data,omitempty"`
	Type      string          `json:"type"` // "accepted" / "progress" / "result"
	CommandID string          `json:"command_id"`
	Status    string          `json:"status,omitempty"` // "ok" / "error"
	Message   string          `json:"message,omitempty"`
	Stage     string          `json:"stage,omitempty"` // 执行阶段描述
}

// TrafficHub 实时流量中枢：管理 Agent 连接与前端订阅
// CommandLogEntry 命令日志条目
type CommandLogEntry struct {
	Type    string `json:"type"`              // "progress" / "result"
	Message string `json:"message,omitempty"` // 日志内容
	Status  string `json:"status,omitempty"`  // result 时: "ok" / "error"
}

// CommandLog 单个命令的日志记录
type CommandLog struct {
	mu      sync.Mutex
	entries []CommandLogEntry
	done    bool                              // 是否已收到 result
	subs    map[chan CommandLogEntry]struct{} // SSE 订阅者
}

type TrafficHub struct {
	mu sync.RWMutex

	// install_id → 实时内存态
	nodes map[string]*NodeLiveState

	// install_id → install_id 到 node_uuid 的映射缓存
	idCache map[string]string

	// 前端订阅者：node_uuid → [subscriber channels]
	subscribers map[string]map[chan FrontendPushMsg]struct{}
	subMu       sync.Mutex

	// Agent 活跃连接：install_id → websocket.Conn（用于命令下发）
	agentConns    map[string]*websocket.Conn
	agentMu       sync.RWMutex
	agentSessions map[*websocket.Conn]agentSession

	// 命令结果回调通道：command_id → channel
	cmdResults map[string]chan AgentCommandResult
	cmdMu      sync.Mutex
	cmdOwners  map[string]commandOwner

	// 命令日志：command_id → CommandLog（供 SSE 流式推送）
	cmdLogs map[string]*CommandLog
	logMu   sync.Mutex
}

// globalHub 全局单例（在 for 循环外持有生命周期）
var globalHub *TrafficHub
var hubOnce sync.Once

// GetTrafficHub 返回全局 TrafficHub 单例
func GetTrafficHub() *TrafficHub {
	hubOnce.Do(func() {
		globalHub = &TrafficHub{
			nodes:         make(map[string]*NodeLiveState),
			idCache:       make(map[string]string),
			subscribers:   make(map[string]map[chan FrontendPushMsg]struct{}),
			agentConns:    make(map[string]*websocket.Conn),
			agentSessions: make(map[*websocket.Conn]agentSession),
			cmdOwners:     make(map[string]commandOwner),
			cmdResults:    make(map[string]chan AgentCommandResult),
			cmdLogs:       make(map[string]*CommandLog),
		}
		go globalHub.runTotalPersistLoop()
		go globalHub.runPointPersistLoop()
	})
	return globalHub
}

func normalizeTrafficPersistIntervalSec(v int) int {
	if v == 0 {
		return 0 // 0 表示关闭历史点落库
	}
	if v < 10 {
		return 10
	}
	if v > 3600 {
		return 3600
	}
	return v
}

// loadTrafficTotalPersistIntervalSec 按数据库类型返回固定累计落库间隔：
// - SQLite: 30s
// - PostgreSQL: 10s
func loadTrafficTotalPersistIntervalSec() int {
	cfg := database.LoadDBConfig()
	if strings.EqualFold(strings.TrimSpace(cfg.Type), "postgres") {
		return 10
	}
	return 30
}

func loadTrafficPointPersistIntervalSec() int {
	var cfg database.SysConfig
	if err := database.DB.Where("key = ?", "pref_traffic_point_persist_interval_sec").First(&cfg).Error; err != nil {
		return 0 // 默认关闭
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(cfg.Value))
	if err != nil {
		return 0 // 默认关闭
	}
	return normalizeTrafficPersistIntervalSec(parsed)
}

func loadNodeTrafficBase(installID string) (rxBase, txBase int64) {
	var node database.NodePool
	if err := database.DB.Select("traffic_down", "traffic_up").Where("install_id = ?", installID).First(&node).Error; err != nil {
		return 0, 0
	}
	return node.TrafficDown, node.TrafficUp
}

func (h *TrafficHub) runTotalPersistLoop() {
	for {
		interval := loadTrafficTotalPersistIntervalSec()
		now := time.Now()
		intervalDur := time.Duration(interval) * time.Second
		next := now.Truncate(intervalDur).Add(intervalDur)
		sleepDur := next.Sub(now)
		if sleepDur <= 0 {
			sleepDur = intervalDur
		}
		time.Sleep(sleepDur)
		h.flushDirtyNodeTrafficTotal()
	}
}

func (h *TrafficHub) runPointPersistLoop() {
	for {
		interval := loadTrafficPointPersistIntervalSec()
		if interval == 0 {
			// 落库已关闭，每 30 秒重新检查配置是否变更
			time.Sleep(30 * time.Second)
			continue
		}
		now := time.Now()
		intervalDur := time.Duration(interval) * time.Second
		next := now.Truncate(intervalDur).Add(intervalDur)
		sleepDur := next.Sub(now)
		if sleepDur <= 0 {
			sleepDur = intervalDur
		}
		time.Sleep(sleepDur)
		h.flushNodeTrafficPoint()
	}
}

type dirtyTrafficItem struct {
	installID string
	rx        int64
	tx        int64
}

func (h *TrafficHub) collectDirtyNodeTrafficAndClear() []dirtyTrafficItem {
	items := make([]dirtyTrafficItem, 0, 64)

	h.mu.Lock()
	for iid, st := range h.nodes {
		if st == nil || !st.Dirty {
			continue
		}
		items = append(items, dirtyTrafficItem{installID: iid, rx: st.TotalRXBytes, tx: st.TotalTXBytes})
		st.Dirty = false
	}
	h.mu.Unlock()

	return items
}

func (h *TrafficHub) flushDirtyNodeTrafficTotal() {
	items := h.collectDirtyNodeTrafficAndClear()
	now := time.Now()
	for _, item := range items {
		if _, err := SaveNodeTrafficTotalOnly(item.installID, item.rx, item.tx, now); err != nil {
			logger.Log.Error("实时累计流量写库失败", "install_id", item.installID, "error", err)
			h.mu.Lock()
			if st, ok := h.nodes[item.installID]; ok && st != nil {
				st.Dirty = true
			}
			h.mu.Unlock()
		}
	}
}

func (h *TrafficHub) flushNodeTrafficPoint() {
	type pointItem struct {
		installID string
		rx        int64
		tx        int64
	}
	items := make([]pointItem, 0, 64)

	h.mu.RLock()
	for iid, st := range h.nodes {
		if st == nil {
			continue
		}
		// 离线节点不写入历史点数据，避免浪费存储
		if !IsNodeOnline(iid) {
			continue
		}
		items = append(items, pointItem{installID: iid, rx: st.TotalRXBytes, tx: st.TotalTXBytes})
	}
	h.mu.RUnlock()

	now := time.Now()
	for _, item := range items {
		if _, err := SaveNodeTrafficPointOnly(item.installID, item.rx, item.tx, now); err != nil {
			logger.Log.Error("实时流量点数据写库失败", "install_id", item.installID, "error", err)
		}
	}
}

// ============================================================
//  install_id → node_uuid 缓存
// ============================================================

func (h *TrafficHub) resolveNodeUUID(installID string) string {
	h.mu.RLock()
	if uuid, ok := h.idCache[installID]; ok {
		h.mu.RUnlock()
		return uuid
	}
	h.mu.RUnlock()

	// 查库
	var node database.NodePool
	if err := database.DB.Where("install_id = ?", installID).First(&node).Error; err != nil {
		return ""
	}

	h.mu.Lock()
	h.idCache[installID] = node.UUID
	h.mu.Unlock()

	return node.UUID
}

func (h *TrafficHub) resolveNodeNameByInstallID(installID string) string {
	installID = strings.TrimSpace(installID)
	if installID == "" {
		return ""
	}

	var node database.NodePool
	if err := database.DB.Select("name").Where("install_id = ?", installID).First(&node).Error; err != nil {
		return ""
	}

	return strings.TrimSpace(node.Name)
}

func (h *TrafficHub) resolveNodeNameByIP(ip string) string {
	ip = strings.TrimSpace(strings.Trim(ip, "[]"))
	if ip == "" {
		return ""
	}

	var node database.NodePool
	if err := database.DB.Select("name").Where("ipv4 = ? OR ipv6 = ?", ip, ip).First(&node).Error; err != nil {
		return ""
	}

	return strings.TrimSpace(node.Name)
}

func (h *TrafficHub) ensureNodeLiveState(installID string) {
	installID = strings.TrimSpace(installID)
	if installID == "" {
		return
	}

	nodeUUID := h.resolveNodeUUID(installID)

	h.mu.Lock()
	defer h.mu.Unlock()

	if st, ok := h.nodes[installID]; ok && st != nil {
		if st.InstallID == "" {
			st.InstallID = installID
		}
		if st.NodeUUID == "" {
			st.NodeUUID = nodeUUID
		}
		return
	}

	baseRX, baseTX := loadNodeTrafficBase(installID)
	h.nodes[installID] = &NodeLiveState{
		InstallID:    installID,
		NodeUUID:     nodeUUID,
		TotalRXBytes: baseRX,
		TotalTXBytes: baseTX,
	}
}

func (h *TrafficHub) bindAgentConnection(conn *websocket.Conn, installID, clientIP string, agentInstallID *string) bool {
	installID = strings.TrimSpace(installID)
	if installID == "" {
		return false
	}

	// One WS connection can only map to one install_id.
	if *agentInstallID != "" && *agentInstallID != installID {
		logger.Log.Warn("Agent WS install_id mismatch，连接已拒绝",
			"ip", clientIP,
			"current_install_id", *agentInstallID,
			"incoming_install_id", installID,
		)
		_ = conn.Close(websocket.StatusPolicyViolation, "install_id mismatch")
		return false
	}

	agentIdentityMu.Lock()
	defer agentIdentityMu.Unlock()
	h.agentMu.RLock()
	session := h.agentSessions[conn]
	current := h.agentConns[installID]
	h.agentMu.RUnlock()
	if (session.installID != "" && session.installID != installID) || !validAgentSession(installID, session) || (*agentInstallID != "" && current != conn) {
		_ = conn.Close(websocket.StatusPolicyViolation, "invalid agent identity")
		return false
	}
	if *agentInstallID != "" {
		return true
	}

	if !IsValidInstallID(installID) {
		logger.Log.Debug("Agent WS install_id 无效，连接已拒绝", "ip", clientIP, "install_id", installID)
		_ = conn.Close(websocket.StatusPolicyViolation, "unknown node")
		return false
	}

	*agentInstallID = installID
	h.agentMu.Lock()
	prevConn := h.agentConns[installID]
	h.agentConns[installID] = conn
	h.agentMu.Unlock()

	// 如果同一节点已有旧连接，主动关闭旧连接，避免并发双连接导致状态抖动。
	if prevConn != nil && prevConn != conn {
		h.failAgentCommands(prevConn)
		_ = prevConn.Close(websocket.StatusPolicyViolation, "superseded by newer connection")
	}
	h.ensureNodeLiveState(installID)
	OnNodeConnectionStatusChanged(installID, true)

	nodeName := h.resolveNodeNameByInstallID(installID)
	if nodeName == "" {
		nodeName = h.resolveNodeNameByIP(clientIP)
	}
	if nodeName == "" {
		nodeName = installID
	}

	logger.Log.Info(fmt.Sprintf("Agent WS 握手成功，节点 %s Agent WS 已连接", nodeName),
		"ip", clientIP,
		"install_id", installID,
		"node_name", nodeName,
	)
	return true
}

func (h *TrafficHub) unbindAgentConnectionIfCurrent(conn *websocket.Conn, installID string) bool {
	installID = strings.TrimSpace(installID)
	if installID == "" || conn == nil {
		return false
	}

	h.agentMu.Lock()
	defer h.agentMu.Unlock()

	curr, ok := h.agentConns[installID]
	if !ok || curr != conn {
		return false
	}

	delete(h.agentConns, installID)
	delete(h.agentSessions, conn)
	h.failAgentCommands(conn)
	return true
}

// ============================================================
//  Agent 上报处理 (WS Server Handler)
// ============================================================

// HandleAgentWS 处理 Agent 的 WebSocket 上报连接
// 路由: /api/callback/traffic/ws
// 支持双向通信：Agent→后端上报流量，后端→Agent下发命令
func HandleAgentWS(w http.ResponseWriter, r *http.Request) {
	hub := GetTrafficHub()
	clientIP := getClientIP(r)
	agentIdentityMu.Lock()
	session, authErr := authenticateAgentRequest(r)
	agentIdentityMu.Unlock()
	if authErr != nil {
		http.Error(w, "invalid agent credentials", http.StatusUnauthorized)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:   []string{"nodectl-agent"},
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		logger.Log.Error("Agent WS 握手失败", "error", err, "ip", clientIP)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "connection closed")
	conn.SetReadLimit(1 << 20)

	ctx := r.Context()

	// 按系统配置动态设置读超时，避免当上报间隔较大时被误判离线。
	agentReadTimeout := getAgentReadTimeout()

	// 首个消息用于识别 install_id 并注册连接
	var agentInstallID string
	hub.agentMu.Lock()
	hub.agentSessions[conn] = session
	hub.agentMu.Unlock()
	defer func() {
		if hub.unbindAgentConnectionIfCurrent(conn, agentInstallID) {
			OnNodeConnectionStatusChanged(agentInstallID, false)
		}
		hub.agentMu.Lock()
		delete(hub.agentSessions, conn)
		hub.agentMu.Unlock()
		hub.failAgentCommands(conn)
	}()
	if session.installID != "" && !hub.bindAgentConnection(conn, session.installID, clientIP, &agentInstallID) {
		return
	}

	for {
		readCtx, readCancel := context.WithTimeout(ctx, agentReadTimeout)
		_, data, err := conn.Read(readCtx)
		readCancel()
		if err != nil {
			nodeName := ""
			if agentInstallID != "" {
				nodeName = hub.resolveNodeNameByInstallID(agentInstallID)
			}
			closeStatus := websocket.CloseStatus(err)
			// 正常关闭或网络断开
			if closeStatus == websocket.StatusNormalClosure || closeStatus == websocket.StatusGoingAway {
				logger.Log.Info("Agent WS 正常断开", "ip", clientIP, "install_id", agentInstallID, "node_name", nodeName)
			} else if ctx.Err() != nil {
				logger.Log.Info("Agent WS 连接随请求上下文关闭", "ip", clientIP, "install_id", agentInstallID, "node_name", nodeName)
			} else if errors.Is(err, context.DeadlineExceeded) || strings.Contains(strings.ToLower(err.Error()), "context deadline exceeded") {
				logger.Log.Info("Agent WS 读超时，判定离线", "error", err, "ip", clientIP, "install_id", agentInstallID, "node_name", nodeName, "read_timeout", agentReadTimeout.String())
			} else {
				logger.Log.Debug("Agent WS 读取异常，连接已断开", "error", err, "ip", clientIP, "install_id", agentInstallID, "node_name", nodeName)
			}
			// 注销 Agent 连接（仅当当前连接仍是 install_id 的活跃连接时才执行）。
			if agentInstallID != "" {
				if hub.unbindAgentConnectionIfCurrent(conn, agentInstallID) {
					OnNodeConnectionStatusChanged(agentInstallID, false)
				} else {
					logger.Log.Debug("Agent WS 断开为过期连接，忽略离线事件",
						"ip", clientIP,
						"install_id", agentInstallID,
						"node_name", nodeName,
					)
				}
			}
			return
		}

		// 使用轻量 peek 结构体替代 map[string]interface{} 判断消息类型（P2-server 优化）
		var peek struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(data, &peek); err != nil {
			logger.Log.Warn("Agent WS 消息解析失败", "error", err, "ip", clientIP)
			continue
		}

		// 如果包含 type 字段且为命令结果类型，按命令结果处理
		if peek.Type == "accepted" || peek.Type == "progress" || peek.Type == "result" {
			var cmdResult AgentCommandResult
			json.Unmarshal(data, &cmdResult)

			var resultIdentity struct {
				InstallID string `json:"install_id"`
			}
			if json.Unmarshal(data, &resultIdentity) != nil || (resultIdentity.InstallID != "" && resultIdentity.InstallID != agentInstallID) {
				return
			}
			hub.acceptAgentResult(conn, agentInstallID, cmdResult)
			continue
		}

		// 🆕 处理新增的消息类型（node_online / links_update）
		if peek.Type == "node_online" || peek.Type == "links_update" || peek.Type == "protocol_change" {
			hub.handleNewMessageType(data, peek.Type, clientIP, &agentInstallID, conn)
			continue
		}

		// 否则按流量上报处理（原有 flat 结构，保持兼容）
		var msg AgentTrafficMsg
		if err := json.Unmarshal(data, &msg); err != nil {
			logger.Log.Warn("Agent WS 流量消息解析失败", "error", err, "ip", clientIP)
			continue
		}

		installID := strings.TrimSpace(msg.InstallID)
		if installID == "" {
			continue
		}

		// 硬核校验：如果内存名单里根本没有这个节点（被删的孤儿），直接挂断不接客，并且不刷屏
		if !hub.bindAgentConnection(conn, installID, clientIP, &agentInstallID) {
			return
		}

		// install_id 绑定与连接注册由 bindAgentConnection 统一处理

		// 解析 node_uuid，因为前边硬核校验过了，此时必定有缓存或能查到数据库
		nodeUUID := hub.resolveNodeUUID(installID)

		// 更新内存态
		hub.mu.Lock()
		state, exists := hub.nodes[installID]
		if !exists {
			baseRX, baseTX := loadNodeTrafficBase(installID)
			state = &NodeLiveState{
				InstallID:    installID,
				NodeUUID:     nodeUUID,
				TotalRXBytes: baseRX,
				TotalTXBytes: baseTX,
			}
			hub.nodes[installID] = state
		}
		state.RXRateBps = msg.RXRateBps
		state.TXRateBps = msg.TXRateBps
		state.LastLiveAt = time.Now()
		// 更新 agent 版本
		if msg.AgentVersion != "" {
			state.AgentVersion = msg.AgentVersion
		}

		if strings.TrimSpace(msg.BootID) != "" {
			currRX := msg.CounterRX
			currTX := msg.CounterTX
			if !state.CounterSeen {
				// 首次收到该节点的计数器数据：仅建立基线，不产生增量
				state.LastCounterRX = currRX
				state.LastCounterTX = currTX
				state.CounterBootID = msg.BootID
				state.CounterSeen = true
			} else if state.CounterBootID != msg.BootID {
				// BootID 变更（机器重启 / Agent 重启导致 boot_id 变化）：
				// 仅重置基线，不产生增量。
				// 修复：旧逻辑将整个计数器值当作增量，导致一次性加入几百GB~几TB。
				logger.Log.Info("Agent BootID 变更，重置计数器基线（不计入增量）",
					"install_id", installID,
					"old_boot_id", state.CounterBootID,
					"new_boot_id", msg.BootID,
					"old_counter_rx", state.LastCounterRX,
					"old_counter_tx", state.LastCounterTX,
					"new_counter_rx", currRX,
					"new_counter_tx", currTX,
				)
				state.LastCounterRX = currRX
				state.LastCounterTX = currTX
				state.CounterBootID = msg.BootID
			} else {
				// 同一 BootID 下的正常增量计算
				deltaRX := currRX - state.LastCounterRX
				deltaTX := currTX - state.LastCounterTX

				// 计数器回绕/重置检测：当前值 < 上次值，跳过本次增量（仅更新基线）
				if deltaRX < 0 || deltaTX < 0 {
					logger.Log.Warn("Agent 计数器回绕/重置，跳过本次增量",
						"install_id", installID,
						"delta_rx", deltaRX,
						"delta_tx", deltaTX,
						"counter_rx", currRX,
						"counter_tx", currTX,
						"last_counter_rx", state.LastCounterRX,
						"last_counter_tx", state.LastCounterTX,
					)
					deltaRX = 0
					deltaTX = 0
				}

				// 单次增量合理性检测：单次增量超过 100GB 视为异常，跳过并告警
				// 即使网卡速率 100Gbps，5秒间隔最多约 62.5GB，100GB 已是极端上限
				const maxSingleDelta = 100 * 1024 * 1024 * 1024 // 100 GB
				if deltaRX > maxSingleDelta || deltaTX > maxSingleDelta {
					logger.Log.Warn("Agent 单次流量增量异常过大，已丢弃",
						"install_id", installID,
						"delta_rx_bytes", deltaRX,
						"delta_tx_bytes", deltaTX,
						"counter_rx", currRX,
						"counter_tx", currTX,
						"last_counter_rx", state.LastCounterRX,
						"last_counter_tx", state.LastCounterTX,
						"boot_id", msg.BootID,
					)
					deltaRX = 0
					deltaTX = 0
				}

				if deltaRX > 0 || deltaTX > 0 {
					state.TotalRXBytes += deltaRX
					state.TotalTXBytes += deltaTX
					state.Dirty = true
				}
				state.LastCounterRX = currRX
				state.LastCounterTX = currTX
			}
		} else {
			logger.Log.Warn("Agent WS 消息缺少 boot_id，忽略累计", "install_id", installID)
		}
		totalRX := state.TotalRXBytes
		totalTX := state.TotalTXBytes
		hub.mu.Unlock()

		_ = CheckAndHandleNodeTrafficThresholdRealtime(installID, totalTX, totalRX)

		// 持久化 agent_version 到 NodePool（仅版本变更时更新，避免重复写库）
		if msg.AgentVersion != "" {
			go func(iid, newVer string) {
				var node database.NodePool
				if err := database.DB.Select("name", "agent_version").Where("install_id = ?", iid).First(&node).Error; err != nil {
					return
				}
				oldVer := node.AgentVersion
				nodeName := strings.TrimSpace(node.Name)
				if nodeName == "" {
					nodeName = "unknown"
				}
				if oldVer != newVer {
					database.DB.Model(&database.NodePool{}).Where("install_id = ?", iid).Update("agent_version", newVer)
					if oldVer == "" {
						logger.Log.Info("Agent 版本已记录",
							"event", "agent_version_init",
							"install_id", iid,
							"node_name", nodeName,
							"agent_version", newVer)
					} else {
						logger.Log.Info("Agent 版本已更新",
							"event", "agent_auto_updated",
							"install_id", iid,
							"node_name", nodeName,
							"old_version", oldVer,
							"new_version", newVer)
					}
				}
			}(installID, msg.AgentVersion)
		}

		// 转发给前端订阅者
		pushMsg := FrontendPushMsg{
			InstallID:    installID,
			NodeUUID:     nodeUUID,
			RXRateBps:    msg.RXRateBps,
			TXRateBps:    msg.TXRateBps,
			TotalRXBytes: totalRX,
			TotalTXBytes: totalTX,
			LastLiveAt:   time.Now().Unix(),
			Offline:      false,
		}
		hub.broadcast(nodeUUID, pushMsg)
	}
}

// ============================================================
//  前端订阅 (WS Server Handler)
// ============================================================

// HandleTrafficLive 处理前端的实时流量订阅连接
// 路由: /api/traffic/live?node_uuid=...
// 若不传 node_uuid，则订阅所有节点
func HandleTrafficLive(w http.ResponseWriter, r *http.Request) {
	hub := GetTrafficHub()

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		logger.Log.Error("前端 Live WS 握手失败", "error", err, "ip", r.RemoteAddr)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "connection closed")

	ctx := r.Context()

	// 必须持续读取以处理客户端 close / ping 帧
	go func() {
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
		}
	}()

	nodeUUID := strings.TrimSpace(r.URL.Query().Get("node_uuid"))

	// 订阅 key：空字符串表示订阅全部
	subKey := nodeUUID
	if subKey == "" {
		subKey = "__all__"
	}

	// 创建订阅通道
	ch := make(chan FrontendPushMsg, 64)
	hub.subscribe(subKey, ch)
	defer hub.unsubscribe(subKey, ch)

	sendSnapshot := func() error {
		hub.mu.RLock()
		defer hub.mu.RUnlock()

		now := time.Now()
		for _, state := range hub.nodes {
			if state == nil {
				continue
			}
			if nodeUUID != "" && state.NodeUUID != nodeUUID {
				continue
			}
			wsOnline := IsNodeOnline(state.InstallID)
			hasRecentLive := hasRecentTrafficSignal(state.LastLiveAt, now)
			// 状态判定以“最近是否收到实时流量消息”为准，WS 仅用于辅助速率呈现。
			online := hasRecentLive

			outRX := int64(0)
			outTX := int64(0)
			if online && wsOnline && hasRecentLive {
				outRX = state.RXRateBps
				outTX = state.TXRateBps
			}

			initMsg := FrontendPushMsg{
				InstallID:    state.InstallID,
				NodeUUID:     state.NodeUUID,
				RXRateBps:    outRX,
				TXRateBps:    outTX,
				TotalRXBytes: state.TotalRXBytes,
				TotalTXBytes: state.TotalTXBytes,
				LastLiveAt:   state.LastLiveAt.Unix(),
				Offline:      !online,
			}

			data, _ := json.Marshal(initMsg)
			if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
				return err
			}
		}

		return nil
	}

	// 先推送当前快照（让前端立即看到最新状态）
	if err := sendSnapshot(); err != nil {
		return
	}

	// 周期推送快照：1 秒一拍，保证前端离线状态及时更新。
	ticker := time.NewTicker(liveSnapshotInterval)
	defer ticker.Stop()

	// 持续推送
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := sendSnapshot(); err != nil {
				return
			}
		case msg, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(msg)
			if err != nil {
				continue
			}
			writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			if err := conn.Write(writeCtx, websocket.MessageText, data); err != nil {
				cancel()
				return
			}
			cancel()
		}
	}
}

// ============================================================
//  Hub 内部方法
// ============================================================

// subscribe 注册前端订阅
func (h *TrafficHub) subscribe(key string, ch chan FrontendPushMsg) {
	h.subMu.Lock()
	defer h.subMu.Unlock()

	if h.subscribers[key] == nil {
		h.subscribers[key] = make(map[chan FrontendPushMsg]struct{})
	}
	h.subscribers[key][ch] = struct{}{}
}

// unsubscribe 注销前端订阅
func (h *TrafficHub) unsubscribe(key string, ch chan FrontendPushMsg) {
	h.subMu.Lock()
	defer h.subMu.Unlock()

	if subs, ok := h.subscribers[key]; ok {
		delete(subs, ch)
		if len(subs) == 0 {
			delete(h.subscribers, key)
		}
	}
	close(ch)
}

// broadcast 向对应节点的前端订阅者广播消息
func (h *TrafficHub) broadcast(nodeUUID string, msg FrontendPushMsg) {
	h.subMu.Lock()
	defer h.subMu.Unlock()

	// 推送给订阅了具体节点的前端
	if subs, ok := h.subscribers[nodeUUID]; ok {
		for ch := range subs {
			select {
			case ch <- msg:
			default:
				// 通道满了，跳过（避免阻塞）
			}
		}
	}

	// 推送给订阅了全部节点的前端
	if subs, ok := h.subscribers["__all__"]; ok {
		for ch := range subs {
			select {
			case ch <- msg:
			default:
			}
		}
	}
}

// GetNodeLiveState 获取节点实时状态（供其他模块使用）
func GetNodeLiveState(installID string) *NodeLiveState {
	hub := GetTrafficHub()
	hub.mu.RLock()
	defer hub.mu.RUnlock()

	if state, ok := hub.nodes[installID]; ok {
		copied := *state
		return &copied
	}
	return nil
}

// GetAllNodeLiveStates 获取所有节点实时状态
func GetAllNodeLiveStates() map[string]*NodeLiveState {
	hub := GetTrafficHub()
	hub.mu.RLock()
	defer hub.mu.RUnlock()

	result := make(map[string]*NodeLiveState, len(hub.nodes))
	for k, v := range hub.nodes {
		copied := *v
		result[k] = &copied
	}
	return result
}

// ============================================================
//  命令下发
// ============================================================

// DispatchCommandToNode 向指定节点下发命令，等待结果（带超时）
// 返回执行结果；若节点不在线或超时返回 error
// ResetNodeTrafficLiveState resets in-memory traffic totals for a node.
// This avoids old in-memory totals writing back to DB after a periodic reset.
func ResetNodeTrafficLiveState(installID string, nodeUUID string, resetAt time.Time) {
	installID = strings.TrimSpace(installID)
	nodeUUID = strings.TrimSpace(nodeUUID)
	if installID == "" {
		return
	}
	if resetAt.IsZero() {
		resetAt = time.Now()
	}

	hub := GetTrafficHub()

	hub.mu.Lock()
	if st, ok := hub.nodes[installID]; ok && st != nil {
		st.TotalRXBytes = 0
		st.TotalTXBytes = 0
		st.RXRateBps = 0
		st.TXRateBps = 0
		st.Dirty = true

		// Reset counter baseline and rebuild on next agent report.
		st.CounterSeen = false
		st.CounterBootID = ""
		st.LastCounterRX = 0
		st.LastCounterTX = 0

		if nodeUUID == "" && strings.TrimSpace(st.NodeUUID) != "" {
			nodeUUID = strings.TrimSpace(st.NodeUUID)
		} else if nodeUUID != "" && strings.TrimSpace(st.NodeUUID) == "" {
			st.NodeUUID = nodeUUID
		}
	}
	if nodeUUID != "" {
		hub.idCache[installID] = nodeUUID
	}
	hub.mu.Unlock()

	if nodeUUID == "" {
		nodeUUID = strings.TrimSpace(hub.resolveNodeUUID(installID))
	}
	if nodeUUID == "" {
		return
	}

	hub.broadcast(nodeUUID, FrontendPushMsg{
		InstallID:    installID,
		NodeUUID:     nodeUUID,
		RXRateBps:    0,
		TXRateBps:    0,
		TotalRXBytes: 0,
		TotalTXBytes: 0,
		LastLiveAt:   resetAt.Unix(),
		Offline:      !IsNodeOnlineForStatus(installID),
	})
}

func DispatchCommandToNode(installID string, action string, payload interface{}, timeout time.Duration) (*AgentCommandResult, error) {
	hub := GetTrafficHub()

	// 检查 Agent 是否在线
	hub.agentMu.RLock()
	conn, online := hub.agentConns[installID]
	hub.agentMu.RUnlock()
	if !online || conn == nil {
		return nil, fmt.Errorf("节点 %s 不在线", installID)
	}

	// 生成唯一命令 ID
	commandID := fmt.Sprintf("cmd-%s-%d", installID, time.Now().UnixNano())

	cmd := AgentCommand{
		Type:      "command",
		CommandID: commandID,
		Action:    action,
		Payload:   payload,
	}

	// 注册结果通道
	resultCh := make(chan AgentCommandResult, 8)
	hub.cmdMu.Lock()
	hub.cmdResults[commandID] = resultCh
	if hub.cmdOwners == nil {
		hub.cmdOwners = make(map[string]commandOwner)
	}
	hub.cmdOwners[commandID] = commandOwner{installID: installID, conn: conn}
	hub.cmdMu.Unlock()

	// 清理函数
	defer func() {
		hub.cmdMu.Lock()
		delete(hub.cmdResults, commandID)
		delete(hub.cmdOwners, commandID)
		hub.cmdMu.Unlock()
	}()

	// 发送命令到 Agent
	data, err := json.Marshal(cmd)
	if err != nil {
		return nil, fmt.Errorf("命令序列化失败: %w", err)
	}

	writeCtx, writeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer writeCancel()
	if err := conn.Write(writeCtx, websocket.MessageText, data); err != nil {
		return nil, fmt.Errorf("命令发送失败: %w", err)
	}

	logger.Log.Info("命令已下发", "install_id", installID, "action", action, "command_id", commandID)

	// 等待最终结果（type=result）或超时
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case result := <-resultCh:
			if result.Type == "result" {
				return &result, nil
			}
			// accepted / progress 类型继续等待
			logger.Log.Info("命令执行中", "command_id", commandID, "type", result.Type, "stage", result.Stage)
		case <-timer.C:
			return nil, fmt.Errorf("命令执行超时 (%v)", timeout)
		}
	}
}

// IsNodeOnline 检查节点是否有活跃 Agent 连接
func IsNodeOnline(installID string) bool {
	hub := GetTrafficHub()
	hub.agentMu.RLock()
	defer hub.agentMu.RUnlock()
	_, ok := hub.agentConns[installID]
	return ok
}

func HasRecentNodeTrafficSignal(installID string) bool {
	installID = strings.TrimSpace(installID)
	if installID == "" {
		return false
	}

	hub := GetTrafficHub()
	hub.mu.RLock()
	st, ok := hub.nodes[installID]
	hub.mu.RUnlock()
	if !ok || st == nil {
		return false
	}

	return hasRecentTrafficSignal(st.LastLiveAt, time.Now())
}

// IsNodeOnlineForStatus 使用“最近是否收到实时流量消息”判定节点在线状态。
func IsNodeOnlineForStatus(installID string) bool {
	return HasRecentNodeTrafficSignal(installID)
}

// CleanupNodeState 删除节点时清理内存中的所有关联状态
func CleanupNodeState(installID string, nodeUUID string) {
	hub := GetTrafficHub()

	// 清理实时流量状态 + ID缓存
	hub.mu.Lock()
	delete(hub.nodes, installID)
	delete(hub.idCache, installID)
	hub.mu.Unlock()

	// 关闭并清理 Agent WS 连接
	hub.agentMu.Lock()
	if conn, ok := hub.agentConns[installID]; ok && conn != nil {
		conn.Close(websocket.StatusGoingAway, "节点已删除")
		delete(hub.agentConns, installID)
	}
	hub.agentMu.Unlock()

	// 关闭该节点的所有前端订阅者
	hub.subMu.Lock()
	if subs, ok := hub.subscribers[nodeUUID]; ok {
		for ch := range subs {
			close(ch)
		}
		delete(hub.subscribers, nodeUUID)
	}
	hub.subMu.Unlock()

	logger.Log.Info("已清理节点内存状态", "install_id", installID, "node_uuid", nodeUUID)
}

// ============================================================
//  命令日志 & SSE 流式推送
// ============================================================

// FireCommandToNode 异步下发命令，立即返回 commandID（不等待结果）
func FireCommandToNode(installID string, action string, payload interface{}) (string, error) {
	// All normal control paths, including Telegram/automatic operations, must
	// respect relay dependencies. WG uses its authenticated typed transport.
	if database.DB != nil && database.DB.Migrator().HasTable(&database.WGPairNode{}) {
		var node database.NodePool
		if err := database.DB.Select("uuid").Where("install_id = ?", installID).First(&node).Error; err == nil && WGNodeInUse(node.UUID) {
			return "", fmt.Errorf("请先停用 WG 配对并等待清理完成，再执行节点控制")
		}
	}
	hub := GetTrafficHub()

	hub.agentMu.RLock()
	conn, online := hub.agentConns[installID]
	hub.agentMu.RUnlock()
	if !online || conn == nil {
		return "", fmt.Errorf("节点 %s 不在线", installID)
	}

	commandID := fmt.Sprintf("cmd-%s-%d", installID, time.Now().UnixNano())

	cmd := AgentCommand{
		Type:      "command",
		CommandID: commandID,
		Action:    action,
		Payload:   payload,
	}

	hub.cmdMu.Lock()
	if hub.cmdOwners == nil {
		hub.cmdOwners = make(map[string]commandOwner)
	}
	hub.cmdOwners[commandID] = commandOwner{installID: installID, conn: conn}
	hub.cmdMu.Unlock()
	sent := false
	defer func() {
		if !sent {
			hub.cmdMu.Lock()
			delete(hub.cmdOwners, commandID)
			hub.cmdMu.Unlock()
		}
	}()
	// 预创建命令日志（SSE 订阅者可能在命令结果到来之前就连接）
	hub.logMu.Lock()
	hub.cmdLogs[commandID] = &CommandLog{
		entries: make([]CommandLogEntry, 0, 64),
		subs:    make(map[chan CommandLogEntry]struct{}),
	}
	hub.logMu.Unlock()

	data, err := json.Marshal(cmd)
	if err != nil {
		return "", fmt.Errorf("命令序列化失败: %w", err)
	}

	writeCtx, writeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer writeCancel()
	if err := conn.Write(writeCtx, websocket.MessageText, data); err != nil {
		return "", fmt.Errorf("命令发送失败: %w", err)
	}

	nodeName := hub.resolveNodeNameByInstallID(installID)
	if nodeName == "" {
		nodeName = installID
	}
	logger.Log.Debug("命令已异步下发", "install_id", installID, "node_name", nodeName, "action", action, "command_id", commandID)

	sent = true
	// 5 分钟后自动清理日志
	go func() {
		time.Sleep(5 * time.Minute)
		hub.cmdMu.Lock()
		delete(hub.cmdOwners, commandID)
		hub.cmdMu.Unlock()
		hub.logMu.Lock()
		delete(hub.cmdLogs, commandID)
		hub.logMu.Unlock()
	}()

	return commandID, nil
}

// appendCommandLog 将命令结果追加到日志并通知 SSE 订阅者
func (hub *TrafficHub) appendCommandLog(result AgentCommandResult) {
	hub.logMu.Lock()
	cmdLog, exists := hub.cmdLogs[result.CommandID]
	hub.logMu.Unlock()

	if !exists {
		return
	}

	entry := CommandLogEntry{
		Type: result.Type,
	}
	if result.Type == "progress" {
		entry.Message = result.Stage
	} else if result.Type == "result" {
		entry.Status = result.Status
		entry.Message = result.Message
	} else if result.Type == "accepted" {
		entry.Message = "命令已接收"
	}

	cmdLog.mu.Lock()
	cmdLog.entries = append(cmdLog.entries, entry)
	if result.Type == "result" {
		cmdLog.done = true
	}
	// 通知所有 SSE 订阅者
	for ch := range cmdLog.subs {
		select {
		case ch <- entry:
		default:
		}
	}
	cmdLog.mu.Unlock()
}

// SubscribeCommandLog 订阅命令日志流
// 返回: 历史条目切片, 实时通道, 是否已完成, 取消订阅函数
func SubscribeCommandLog(commandID string) ([]CommandLogEntry, chan CommandLogEntry, bool, func()) {
	hub := GetTrafficHub()

	hub.logMu.Lock()
	cmdLog, exists := hub.cmdLogs[commandID]
	hub.logMu.Unlock()

	if !exists {
		return nil, nil, false, func() {}
	}

	ch := make(chan CommandLogEntry, 64)

	cmdLog.mu.Lock()
	history := make([]CommandLogEntry, len(cmdLog.entries))
	copy(history, cmdLog.entries)
	done := cmdLog.done
	if !done {
		cmdLog.subs[ch] = struct{}{}
	}
	cmdLog.mu.Unlock()

	unsub := func() {
		cmdLog.mu.Lock()
		delete(cmdLog.subs, ch)
		cmdLog.mu.Unlock()
	}

	return history, ch, done, unsub
}

// ============================================================
//  🆕 新增消息类型处理（WebSocket 通道复用）
// ============================================================

// wsMessage 🆕 统一消息结构（用于解析 node_online / links_update 等新消息）
type wsMessage struct {
	Type      string          `json:"type"`
	InstallID string          `json:"install_id"`
	Timestamp int64           `json:"timestamp"`
	Payload   json.RawMessage `json:"payload"`
}

// wsNodeOnlinePayload 节点上线载荷
type wsNodeOnlinePayload struct {
	Hostname  string            `json:"hostname"`
	IPv4      string            `json:"ipv4,omitempty"`
	IPv6      string            `json:"ipv6,omitempty"`
	Protocols []string          `json:"protocols"`
	Links     map[string]string `json:"links"`
	AgentVer  string            `json:"agent_version"`
	SBVersion string            `json:"singbox_version,omitempty"`
}

// wsLinksUpdatePayload 链接更新载荷
type wsLinksUpdatePayload struct {
	Action    string            `json:"action"` // reset / add / remove / reinstall
	Protocols []string          `json:"protocols"`
	Links     map[string]string `json:"links"`
	IPv4      string            `json:"ipv4,omitempty"`
	IPv6      string            `json:"ipv6,omitempty"`
}

// handleNewMessageType 🆕 处理新增的 WebSocket 消息类型
func (h *TrafficHub) handleNewMessageType(data []byte, msgType string, clientIP string, agentInstallID *string, conn *websocket.Conn) {
	var msg wsMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		logger.Log.Warn("WS 新消息解析失败", "error", err, "type", msgType, "ip", clientIP)
		return
	}

	installID := strings.TrimSpace(msg.InstallID)
	if installID == "" {
		logger.Log.Warn("WS 新消息缺少 install_id", "type", msgType, "ip", clientIP)
		return
	}

	if !h.bindAgentConnection(conn, installID, clientIP, agentInstallID) {
		return
	}

	// 根据消息类型分发处理
	switch msgType {
	case "node_online":
		h.handleNodeOnline(msg, clientIP)
	case "links_update":
		h.handleLinksUpdate(msg, clientIP)
	case "protocol_change":
		logger.Log.Info("收到协议状态变更消息", "install_id", installID, "ip", clientIP)
		// TODO: 后续实现协议变更处理
	default:
		logger.Log.Warn("未知的 WS 消息类型", "type", msgType, "install_id", installID, "ip", clientIP)
	}
}

// handleNodeOnline 🆕 处理节点上线消息
// 更新数据库中的节点 IP（IPv4+IPv6）、地区（Region）、协议列表、链接、版本等信息
func (h *TrafficHub) handleNodeOnline(msg wsMessage, clientIP string) {
	var payload wsNodeOnlinePayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		logger.Log.Warn("解析 node_online 载荷失败", "error", err, "install_id", msg.InstallID)
		return
	}

	installID := msg.InstallID

	// 获取节点记录
	var node database.NodePool
	if err := database.DB.Where("install_id = ?", installID).First(&node).Error; err != nil {
		logger.Log.Warn("node_online: 节点不存在", "install_id", installID)
		return
	}

	// 更新节点信息
	updates := map[string]interface{}{}

	// 更新 IPv4（去除多余空白和方括号）
	ipv4 := strings.TrimSpace(strings.Trim(payload.IPv4, "[]"))
	if ipv4 != "" && ipv4 != node.IPV4 {
		updates["ipv4"] = ipv4
	}
	// 更新 IPv6（去除多余空白和方括号，防止超长写入）
	ipv6 := strings.TrimSpace(strings.Trim(payload.IPv6, "[]"))
	if len(ipv6) > 45 { // IPv6 最长 45 字符（包含冒号和可能的压缩符号）
		logger.Log.Warn("node_online: IPv6 地址过长，已截断", "install_id", installID, "raw_ipv6_len", len(ipv6))
		ipv6 = ipv6[:45]
	}
	if ipv6 != "" && ipv6 != node.IPV6 {
		updates["ipv6"] = ipv6
	}

	// 使用 GeoIP 解析 Region（国家 ISO Code，如 US、CN）
	// 优先使用 IPv4 查询地区，IPv4 为空时使用 IPv6
	newRegion := ""
	if GlobalGeoIP != nil {
		checkIP := ipv4
		if checkIP == "" {
			checkIP = ipv6
		}
		if checkIP != "" {
			newRegion = GlobalGeoIP.GetCountryIsoCode(checkIP)
		}
	}
	if newRegion != "" && newRegion != node.Region {
		updates["region"] = newRegion
	}

	// 更新 Agent 版本
	if payload.AgentVer != "" && payload.AgentVer != node.AgentVersion {
		updates["agent_version"] = payload.AgentVer
	}

	// 更新链接
	if len(payload.Links) > 0 {
		if node.Links == nil {
			node.Links = make(map[string]string)
		}
		changed := false
		for proto, link := range payload.Links {
			if strings.TrimSpace(link) == "" {
				continue // 跳过空链接
			}
			if node.Links[proto] != link {
				node.Links[proto] = link
				changed = true
			}
		}
		if changed {
			// GORM .Updates(map) 会跳过模型 serializer，需手动序列化为 JSON 字符串
			linksJSON, err := json.Marshal(node.Links)
			if err == nil {
				updates["links"] = string(linksJSON)
			} else {
				logger.Log.Warn("node_online: 序列化 links 失败", "error", err, "install_id", installID)
			}
		}
	}

	// 批量更新
	if len(updates) > 0 {
		if err := database.DB.Model(&database.NodePool{}).Where("install_id = ?", installID).Updates(updates).Error; err != nil {
			logger.Log.Error("node_online: 更新节点信息失败", "error", err, "install_id", installID)
		} else {
			nodeName := strings.TrimSpace(node.Name)
			if nodeName == "" {
				nodeName = installID
			}
		}
	}
}

// handleLinksUpdate 🆕 处理链接更新消息
// 更新数据库中的节点链接，同时更新 IP 和 Region
func (h *TrafficHub) handleLinksUpdate(msg wsMessage, clientIP string) {
	var payload wsLinksUpdatePayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		logger.Log.Warn("解析 links_update 载荷失败", "error", err, "install_id", msg.InstallID)
		return
	}

	installID := msg.InstallID

	// 获取节点记录
	var node database.NodePool
	if err := database.DB.Where("install_id = ?", installID).First(&node).Error; err != nil {
		logger.Log.Warn("links_update: 节点不存在", "install_id", installID)
		return
	}

	updates := map[string]interface{}{}

	// 更新 IPv4 和 IPv6（links_update 也可能携带最新 IP，去除多余空白和方括号）
	luIPv4 := strings.TrimSpace(strings.Trim(payload.IPv4, "[]"))
	if luIPv4 != "" && luIPv4 != node.IPV4 {
		updates["ipv4"] = luIPv4
	}
	luIPv6 := strings.TrimSpace(strings.Trim(payload.IPv6, "[]"))
	if len(luIPv6) > 45 {
		logger.Log.Warn("links_update: IPv6 地址过长，已截断", "install_id", installID, "raw_ipv6_len", len(luIPv6))
		luIPv6 = luIPv6[:45]
	}
	if luIPv6 != "" && luIPv6 != node.IPV6 {
		updates["ipv6"] = luIPv6
	}

	// 使用 GeoIP 解析 Region（国家 ISO Code，如 US、CN）
	if GlobalGeoIP != nil {
		checkIP := luIPv4
		if checkIP == "" {
			checkIP = luIPv6
		}
		if checkIP != "" {
			newRegion := GlobalGeoIP.GetCountryIsoCode(checkIP)
			if newRegion != "" && newRegion != node.Region {
				updates["region"] = newRegion
			}
		}
	}

	// 更新链接
	if len(payload.Links) > 0 {
		if node.Links == nil {
			node.Links = make(map[string]string)
		}
		for proto, link := range payload.Links {
			if strings.TrimSpace(link) == "" {
				continue // 跳过空链接
			}
			node.Links[proto] = link
		}

		// GORM .Update() 对 map 类型不会自动调用 serializer，需手动序列化为 JSON 字符串
		linksJSON, err := json.Marshal(node.Links)
		if err != nil {
			logger.Log.Error("links_update: 序列化 links 失败", "error", err, "install_id", installID)
			return
		}
		updates["links"] = string(linksJSON)
	}

	// 批量更新
	if len(updates) > 0 {
		if err := database.DB.Model(&database.NodePool{}).Where("install_id = ?", installID).Updates(updates).Error; err != nil {
			logger.Log.Error("links_update: 更新失败", "error", err, "install_id", installID)
		} else {
			nodeName := strings.TrimSpace(node.Name)
			if nodeName == "" {
				nodeName = installID
			}
			logger.Log.Info("节点链接已更新",
				"install_id", installID,
				"node_name", nodeName,
				"action", payload.Action,
				"protocols", payload.Protocols,
				"link_count", len(payload.Links),
			)
		}
	}
}
