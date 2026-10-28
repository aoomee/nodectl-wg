package service

import (
	"errors"
	"strings"

	"gorm.io/gorm"
	"nodectl/internal/database"
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
	bound := err == nil && identity.Bound && identity.SecretHash != ""
	r.EnrollmentMode = "initial"
	if identity.Bound {
		r.EnrollmentMode = "rotate"
		if bound {
			r.EnrollmentMode = "none"
		}
	}
	detail = "机器已完成授权，无需重复绑定。"
	if !bound {
		detail = "请点击“授权当前机器”，在该服务器终端完成绑定并重启 Agent。"
		if identity.Bound {
			detail = "机器授权已撤销，请点击“重新授权”，在该服务器终端重新绑定并重启 Agent。"
		}
	}
	r.add("identity", "机器授权", bound, detail)
	status := "offline"
	if c.agentStatus != nil {
		status = c.agentStatus(n.InstallID)
	} else if c.ready != nil && c.ready(n.InstallID) {
		status = "ready"
	}
	detail = "已连接支持 WG 双机中转的 Agent。"
	switch status {
	case "offline":
		detail = "Agent 未连接；请检查服务是否运行，以及到面板的 HTTPS/WSS 连接。"
	case "unauthenticated":
		detail = "当前连接未通过机器身份验证；请检查授权状态和 Agent 使用的配置，然后重启 Agent。"
	case "unsupported":
		detail = "当前 Agent 未声明 WG 双机中转能力；请更新 Agent 并重启。"
	case "ready":
	default:
		detail = "Agent 状态未知，请刷新后重试。"
	}
	r.add("agent", "Agent 连接", status == "ready", detail)
	return r, nil
}
