package agent

import (
	"context"
	"path/filepath"
	"time"

	"nodectl/internal/agent/singbox"
	"nodectl/internal/agent/wgrelay"
)

// Called under commandMu. WG operations never enter the ordinary sing-box
// configuration path or stop its existing listeners.
func (rt *Runtime) executeWGCommand(cmd ServerCommand, reply func(CommandResult)) {
	fail := func(message string) { reply(CommandResult{Type: "result", Status: "error", Message: message}) }
	if rt.cfg == nil || rt.cfg.AgentToken == "" || validateAgentTransport(rt.cfg) != nil {
		fail("WG 中转要求已安全绑定的 Agent 和可信 HTTPS/WSS 连接")
		return
	}
	switch cmd.Action {
	case "wg-prepare", "wg-configure", "wg-verify", "wg-activate", "wg-remove", "wg-status":
	default:
		fail("不支持的 WG 操作")
		return
	}
	if rt.wgManager == nil {
		configPath := singbox.DefaultConfigPath
		if rt.cfg.Singbox != nil && rt.cfg.Singbox.ConfigPath != "" {
			configPath = rt.cfg.Singbox.ConfigPath
		}
		manager, err := wgrelay.New(filepath.Join(filepath.Dir(configPath), "wg-relay"))
		if err != nil {
			fail("WG 初始化失败：需 Linux/systemd、root 权限、ip/wg 工具及独占的安全状态目录")
			return
		}
		rt.wgManager = manager
	}
	ctx := rt.commandCtx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 18*time.Second)
	defer cancel()
	reply(CommandResult{Type: "accepted", Status: "ok", Stage: "正在执行受管 WG 操作"})
	data, err := rt.wgManager.Execute(ctx, cmd.Action, cmd.Payload)
	if err != nil {
		fail("WG 操作失败；请检查权限、端口/路由冲突及双端连接，等待面板完成清理后重试")
		return
	}
	reply(CommandResult{Type: "result", Status: "ok", Data: data})
}
