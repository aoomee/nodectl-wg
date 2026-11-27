// 路径: internal/agent/agentversion.go
// Agent 独立版本变量，与主程序 internal/version 解耦
// 通过 -ldflags 注入:
//
//	-X wirearc/internal/agent.AgentVersion=...
//	-X wirearc/internal/agent.GitCommit=...
//	-X wirearc/internal/agent.BuildTime=...
package agent

import "strings"

var (
	// AgentVersion agent 语义化版本号（由 CI 注入）
	AgentVersion = "dev"
	// GitCommit 构建时的 git commit SHA（短）
	GitCommit = "unknown"
	// BuildTime 构建时间 (RFC3339)
	BuildTime = "unknown"
)

// ReleaseChannel 发布渠道类型
type ReleaseChannel string

const (
	ChannelStable ReleaseChannel = "stable" // 正式版（main 分支）
	ChannelAlpha  ReleaseChannel = "alpha"  // Alpha 测试版（alpha 分支）
	ChannelDev    ReleaseChannel = "dev"    // 开发版
)

// GetChannel 根据版本号判断当前发布渠道
// 版本号格式示例：
//   - "v1.0.0" 或 "1.0.0" → ChannelStable
//   - "v1.0.0-alpha" 或 "1.0.0-alpha" → ChannelAlpha
//   - "dev" 或空 → ChannelDev
func GetChannel() ReleaseChannel {
	v := strings.TrimSpace(AgentVersion)
	if v == "" || v == "dev" {
		return ChannelDev
	}

	// 检查是否有预发布后缀
	lowerV := strings.ToLower(v)
	if strings.Contains(lowerV, "-alpha") {
		return ChannelAlpha
	}

	return ChannelStable
}

// IsStable 返回当前是否为正式版本
func IsStable() bool {
	return GetChannel() == ChannelStable
}

// IsAlpha 返回当前是否为 Alpha 版本
func IsAlpha() bool {
	return GetChannel() == ChannelAlpha
}

// IsDev 返回当前是否为开发版本
func IsDev() bool {
	return GetChannel() == ChannelDev
}

// GetBranchName 返回对应的 Git 分支名称
func GetBranchName() string {
	switch GetChannel() {
	case ChannelAlpha:
		return "wirearc-Alpha"
	case ChannelStable:
		return "main"
	default:
		return ""
	}
}

// CleanVersion 返回清理后的版本号（移除 v 前缀）
func CleanVersion() string {
	v := strings.TrimSpace(AgentVersion)
	return strings.TrimPrefix(v, "v")
}
