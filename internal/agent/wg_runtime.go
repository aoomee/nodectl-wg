package agent

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"nodectl/internal/agent/singbox"
	"nodectl/internal/agent/wgrelay"
)

func (rt *Runtime) ensureWGManager() error {
	if rt.wgManager != nil {
		return nil
	}
	configPath := singbox.DefaultConfigPath
	if rt.cfg != nil && rt.cfg.Singbox != nil && rt.cfg.Singbox.ConfigPath != "" {
		configPath = rt.cfg.Singbox.ConfigPath
	}
	manager, err := wgrelay.New(filepath.Join(filepath.Dir(configPath), "wg-relay"))
	if err != nil {
		return err
	}
	rt.wgManager = manager
	return nil
}

// Called under commandMu. WG operations never enter the ordinary sing-box
// configuration path or stop its existing listeners.
func (rt *Runtime) executeWGCommand(cmd ServerCommand, reply func(CommandResult)) {
	fail := func(message string) { reply(CommandResult{Type: "result", Status: "error", Message: message}) }
	if rt.cfg == nil || strings.TrimSpace(rt.cfg.InstallID) == "" || (rt.cfg.AgentToken != "" && validateAgentTransport(rt.cfg) != nil) {
		fail("WG 中转要求有效的节点配置；若启用了独立凭据则需可信 HTTPS/WSS 连接")
		return
	}
	ctx := rt.commandCtx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()

	if strings.HasPrefix(cmd.Action, "wg-v2-") {
		data, err := rt.executeWGV2(ctx, cmd)
		if err != nil {
			if errors.Is(err, wgrelay.ErrUnsupported) {
				fail("WG 初始化失败：需 Linux/systemd、root 权限及 ip/wg 工具")
				return
			}
			fail("WG REALITY→SS 操作失败；保持阻断，请检查阶段状态及双端配置")
			return
		}
		reply(CommandResult{Type: "result", Status: "ok", Data: data})
		return
	}
	switch cmd.Action {
	case "wg-prepare", "wg-configure", "wg-verify", "wg-activate", "wg-remove", "wg-status":
	default:
		fail("不支持的 WG 操作")
		return
	}
	if err := rt.ensureWGManager(); err != nil {
		fail("WG 初始化失败：需 Linux/systemd、root 权限、ip/wg 工具及独占的安全状态目录")
		return
	}
	reply(CommandResult{Type: "accepted", Status: "ok", Stage: "正在执行受管 WG 操作"})
	data, err := rt.wgManager.Execute(ctx, cmd.Action, cmd.Payload)
	if err != nil {
		fail("WG 操作失败；请检查权限、端口/路由冲突及双端连接，等待面板完成清理后重试")
		return
	}
	reply(CommandResult{Type: "result", Status: "ok", Data: data})
}
