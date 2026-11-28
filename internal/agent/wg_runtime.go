package agent

import (
	"context"
	"errors"
	"log"
	"path/filepath"
	"strings"
	"time"

	"wirearc/internal/agent/singbox"
	"wirearc/internal/agent/wgrelay"
)

func (rt *Runtime) ensureWGManager() error {
	if rt.wgManager != nil {
		return nil
	}
	configPath := filepath.Join(singbox.ResolveWorkDir(), "singbox-config.json")
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

func wgV2FailureMessage(err error) string {
	switch {
	case errors.Is(err, wgrelay.ErrUnsupported):
		return "WG 初始化失败：需 Linux/systemd、root 权限及 ip/wg 工具"
	case errors.Is(err, singbox.ErrWGRouteStale):
		return "WG 路由状态冲突（节点存在未释放的旧配对或过期修订），请检查节点路由状态后重试"
	case errors.Is(err, singbox.ErrWGConfigCheck):
		return "WG sing-box 配置校验失败，请检查节点 sing-box 版本与协议配置"
	default:
		return "WG REALITY→SS 操作失败；保持阻断，请检查阶段状态及双端配置"
	}
}

// Called under commandMu. WG operations never enter the ordinary sing-box
// configuration path or stop its existing listeners.
func (rt *Runtime) executeWGCommand(cmd ServerCommand, reply func(CommandResult)) {
	fail := func(message string) { reply(CommandResult{Type: "result", Status: "error", Message: message}) }
	if rt.cfg == nil || strings.TrimSpace(rt.cfg.InstallID) == "" || (rt.cfg.AgentToken != "" && validateAgentTransport(rt.cfg) != nil) {
		fail("WG 中转要求有效的节点配置；若启用了独立凭据则需可信 HTTPS/WSS 连接")
		return
	}
	probeFailure := func(err error) bool {
		if !errors.Is(err, wgrelay.ErrProbeTimeout) {
			return false
		}
		reply(CommandResult{Type: "result", Status: "error", ErrorCode: wgrelay.ProbeTimeoutCode, Message: "WG 探活超时"})
		return true
	}
	ctx := rt.commandCtx
	if ctx == nil {
		ctx = context.Background()
	}
	cmdTimeout := 75 * time.Second
	switch cmd.Action {
	case "wg-v2-status", "wg-v2-ss", "wg-verify", "wg-status":
		// Keep periodic health probes bounded well below the 90s local WG route lease
		// so a stuck probe can never hold commandMu past lease expiry.
		cmdTimeout = 25 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()

	if strings.HasPrefix(cmd.Action, "wg-v2-") {
		data, err := rt.executeWGV2(ctx, cmd)
		if err != nil {
			log.Printf("[Agent] WG v2 命令失败 (action=%s): %v", cmd.Action, err)
			if cmd.Action == "wg-v2-status" && probeFailure(err) {
				return
			}
			fail(wgV2FailureMessage(err))
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
		log.Printf("[Agent] WG 管理器初始化失败 (action=%s): %v", cmd.Action, err)
		fail("WG 初始化失败：需 Linux/systemd、root 权限、ip/wg 工具及独占的安全状态目录")
		return
	}
	reply(CommandResult{Type: "accepted", Status: "ok", Stage: "正在执行受管 WG 操作"})
	data, err := rt.wgManager.Execute(ctx, cmd.Action, cmd.Payload)
	if err != nil {
		log.Printf("[Agent] WG 命令失败 (action=%s): %v", cmd.Action, err)
		if cmd.Action == "wg-verify" && probeFailure(err) {
			return
		}
		fail("WG 操作失败；请检查权限、端口/路由冲突及双端连接，等待面板完成清理后重试")
		return
	}
	reply(CommandResult{Type: "result", Status: "ok", Data: data})
}
