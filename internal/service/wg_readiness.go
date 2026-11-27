package service

import (
	"errors"
	"strings"

	"gorm.io/gorm"
	"wirearc/internal/database"
)

type WGReadinessCheck struct {
	Code   string `json:"code"`
	Label  string `json:"label"`
	Ready  bool   `json:"ready"`
	Detail string `json:"detail"`
}
type WGReadinessDTO struct {
	Role           string             `json:"role"`
	Ready          bool               `json:"ready"`
	Checks         []WGReadinessCheck `json:"checks"`
	EnrollmentMode string             `json:"enrollment_mode"`
}

func (r *WGReadinessDTO) add(code, label string, ready bool, detail string) {
	r.Checks = append(r.Checks, WGReadinessCheck{code, label, ready, detail})
	r.Ready = r.Ready && ready
}

func (c *wgPairCoordinator) nodeReadiness(db *gorm.DB, n database.NodePool, role string) (WGReadinessDTO, error) {
	r := WGReadinessDTO{Role: role, Ready: true, Checks: []WGReadinessCheck{}}
	var conditions []string
	wantRoute := 1
	if role == "landing" {
		wantRoute = 2
	}
	if n.RoutingType != wantRoute {
		conditions = append(conditions, "请保存正确的入口 / 落地类型")
	}
	if n.IsBlocked {
		conditions = append(conditions, "节点已屏蔽，请先解除屏蔽")
	}
	if n.TrafficThresholdReached {
		conditions = append(conditions, "节点已达到流量阈值，请先处理流量限制")
	}
	if n.TunnelEnabled || n.TunnelID != "" {
		conditions = append(conditions, "节点使用了隧道模式，暂不支持 WG 双机配对")
	}
	if !wgIPv4(n.IPV4) {
		conditions = append(conditions, "请填写可用的 IPv4 地址")
	}
	detail := "节点类型与地址符合配对条件。"
	if len(conditions) > 0 {
		detail = strings.Join(conditions, "；") + "。"
	}
	r.add("node", "节点条件", wgNodeEligible(n, role), detail)
	_, _, err := wgReality(n)
	label := "REALITY 部署"
	if role == "landing" {
		label = "SS 部署"
		_, _, err = wgSS(n)
	}
	detail = "面板已记录启用的协议与端口；部署时会核验机器实际配置。"
	if err != nil {
		detail = "请先启用并推送 " + strings.TrimSuffix(label, " 部署") + "，等待成功；已有协议请检查链接与端口是否一致。"
	}
	r.add("protocol", label, err == nil, detail)
	var identity database.AgentIdentity
	err = db.Where("node_uuid = ? AND install_id = ?", n.UUID, n.InstallID).First(&identity).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return r, err
	}
	revoked := err == nil && identity.Bound && identity.SecretHash == ""
	r.EnrollmentMode = "none"
	status := "offline"
	if revoked {
		status = "revoked"
	} else if c.agentStatus != nil {
		status = c.agentStatus(n.InstallID)
	} else if c.ready != nil && c.ready(n.InstallID) {
		status = "ready"
	}
	detail = "Agent 在线，可直接受管部署 WireGuard 双机中转。"
	switch status {
	case "offline":
		detail = "Agent 未连接；请确认服务器上的 wirearc-agent 服务正在运行。"
	case "revoked", "unauthenticated":
		detail = "当前节点连接凭据已失效或被撤销；请检查 Agent 配置或重新安装 Agent。"
	case "unsupported":
		detail = "当前 Agent 版本不支持 WG 双机中转；请更新 Agent 后重试。"
	case "ready":
	default:
		detail = "Agent 状态未知，请刷新后重试。"
	}
	r.add("agent", "Agent 连接", status == "ready", detail)
	return r, nil
}
