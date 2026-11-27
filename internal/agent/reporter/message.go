// 路径: internal/agent/reporter/message.go
// WebSocket 通道复用消息类型定义
// 所有消息通过统一的 WebSocket 连接传输，使用 type 字段区分消息类型
package reporter

// MessageType 消息类型枚举
type MessageType string

const (
	// MessageTypeTraffic 流量上报（原有，保持兼容）
	// 注意：流量消息保持原有的 flat 结构（不使用 Message 包装），确保向下兼容
	MessageTypeTraffic MessageType = "traffic"

	// MessageTypeNodeOnline 节点上线（首次连接，含IP信息）
	// 注意：IP信息仅在首次启动时随节点上线消息上报一次，之后不再定时检测
	MessageTypeNodeOnline MessageType = "node_online"

	// MessageTypeLinksUpdate 链接更新（重置/重装后）
	MessageTypeLinksUpdate MessageType = "links_update"

	// MessageTypeProtocolChange 协议状态变更
	MessageTypeProtocolChange MessageType = "protocol_change"
)

// Message 统一消息结构（用于新增的消息类型）
type Message struct {
	Type      MessageType `json:"type"`
	InstallID string      `json:"install_id"`
	Timestamp int64       `json:"timestamp"`
	Payload   interface{} `json:"payload"`
}

// NodeOnlinePayload 节点上线载荷
type NodeOnlinePayload struct {
	Hostname  string            `json:"hostname"`
	IPv4      string            `json:"ipv4,omitempty"`
	IPv6      string            `json:"ipv6,omitempty"`
	Protocols []string          `json:"protocols"`
	Links     map[string]string `json:"links"`
	AgentVer  string            `json:"agent_version"`
	SBVersion string            `json:"singbox_version,omitempty"`
}

// LinksUpdatePayload 链接更新载荷
type LinksUpdatePayload struct {
	Action    string            `json:"action"` // reset / add / remove / reinstall
	Protocols []string          `json:"protocols"`
	Links     map[string]string `json:"links"`
	IPv4      string            `json:"ipv4,omitempty"`
	IPv6      string            `json:"ipv6,omitempty"`
}

// TrafficPayload 流量数据载荷（原有，保持兼容）
// 注意：为了兼容性，流量消息仍然使用原有的 flat 结构，不经过 Message 包装
type TrafficPayload struct {
	Upload   uint64 `json:"upload"`
	Download uint64 `json:"download"`
}
