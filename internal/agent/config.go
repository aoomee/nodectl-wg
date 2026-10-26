// 路径: internal/agent/config.go
package agent

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"nodectl/internal/agent/singbox"
)

// DefaultConfigPath 默认配置文件路径
const DefaultConfigPath = "/etc/nodectl-agent/config.json"

// Config Agent 主配置结构体，从 /etc/nodectl-agent/config.json 读取
type Config struct {
	// 基础配置
	AgentToken string `json:"agent_token,omitempty"` // Permanent enrollment credential; config must remain 0600.
	InstallID  string `json:"install_id"`            // 节点唯一标识 (12位)
	PanelURL   string `json:"panel_url,omitempty"`   // 🆕 面板地址（新版安装脚本使用，自动推导 ws_url）
	WSURL      string `json:"ws_url,omitempty"`      // WebSocket 上报地址（旧版兼容 / 运行时计算）
	Interface  string `json:"interface"`             // 网卡名称 ("auto" 自动检测)
	LogLevel   string `json:"log_level"`             // 日志等级

	// 🆕 协议配置（首次启动时从后端拉取，或从缓存加载）
	Protocols *singbox.ProtocolConfig `json:"protocols,omitempty"`

	// 🆕 sing-box 进程配置
	Singbox *SingboxProcessConfig `json:"singbox,omitempty"`
}

// SingboxProcessConfig sing-box 进程管理配置
type SingboxProcessConfig struct {
	BinaryPath   string `json:"binary_path,omitempty"`   // sing-box 二进制路径（默认 /var/lib/nodectl-agent/sing-box）
	ConfigPath   string `json:"config_path,omitempty"`   // sing-box 配置文件路径（默认 /var/lib/nodectl-agent/singbox-config.json）
	AutoRestart  *bool  `json:"auto_restart,omitempty"`  // 崩溃后自动重启（默认 true）
	RestartDelay string `json:"restart_delay,omitempty"` // 重启间隔（默认 "5s"）
}

// DefaultConfig 返回带有合理默认值的配置
func DefaultConfig() *Config {
	autoRestart := true
	return &Config{
		Interface: "auto",
		LogLevel:  "info",
		Singbox: &SingboxProcessConfig{
			BinaryPath:   singbox.DefaultBinaryPath,
			ConfigPath:   singbox.DefaultConfigPath,
			AutoRestart:  &autoRestart,
			RestartDelay: "5s",
		},
	}
}

// LoadConfig 从指定路径加载配置文件
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		path = DefaultConfigPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败 [%s]: %w", path, err)
	}

	// 以默认值为基础，再覆盖 JSON 中的字段
	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 校验必要字段
	if strings.TrimSpace(cfg.InstallID) == "" {
		return nil, fmt.Errorf("配置项 install_id 不能为空")
	}

	// 🆕 新版配置兼容：如果有 panel_url 但没有 ws_url，则自动推导
	if strings.TrimSpace(cfg.WSURL) == "" && strings.TrimSpace(cfg.PanelURL) != "" {
		cfg.WSURL = DeriveWSURL(cfg.PanelURL)
	}

	if strings.TrimSpace(cfg.WSURL) == "" {
		return nil, fmt.Errorf("配置项 ws_url 或 panel_url 不能同时为空")
	}

	// 🆕 如果 panel_url 为空但 ws_url 存在，反向推导 panel_url（兼容旧版配置）
	if strings.TrimSpace(cfg.PanelURL) == "" && strings.TrimSpace(cfg.WSURL) != "" {
		cfg.PanelURL = DerivePanelURL(cfg.WSURL)
	}

	// 应用默认值
	if strings.TrimSpace(cfg.Interface) == "" {
		cfg.Interface = "auto"
	}
	if strings.TrimSpace(cfg.LogLevel) == "" {
		cfg.LogLevel = "info"
	}

	// 确保 Singbox 配置有默认值
	if cfg.Singbox == nil {
		cfg.Singbox = DefaultConfig().Singbox
	} else {
		if cfg.Singbox.BinaryPath == "" {
			cfg.Singbox.BinaryPath = singbox.DefaultBinaryPath
		}
		if cfg.Singbox.ConfigPath == "" {
			cfg.Singbox.ConfigPath = singbox.DefaultConfigPath
		}
		if cfg.Singbox.AutoRestart == nil {
			autoRestart := true
			cfg.Singbox.AutoRestart = &autoRestart
		}
		if cfg.Singbox.RestartDelay == "" {
			cfg.Singbox.RestartDelay = "5s"
		}
	}

	return cfg, nil
}

// Validate 验证配置有效性
func (c *Config) Validate() error {
	// 验证必要字段
	if strings.TrimSpace(c.InstallID) == "" {
		return fmt.Errorf("install_id is required")
	}

	// 验证 panel_url 或 ws_url 至少有一个
	if strings.TrimSpace(c.PanelURL) == "" && strings.TrimSpace(c.WSURL) == "" {
		return fmt.Errorf("panel_url 或 ws_url 至少需要一个")
	}

	// 验证 URL 格式
	if c.PanelURL != "" {
		if _, err := url.Parse(c.PanelURL); err != nil {
			return fmt.Errorf("invalid panel_url: %w", err)
		}
	}
	if c.WSURL != "" {
		if _, err := url.Parse(c.WSURL); err != nil {
			return fmt.Errorf("invalid ws_url: %w", err)
		}
	}

	// 验证协议配置（如果存在）
	if c.Protocols != nil {
		if err := ValidateProtocolConfig(c.Protocols); err != nil {
			return err
		}
	}

	return nil
}

// ValidateProtocolConfig 验证协议配置有效性
func ValidateProtocolConfig(p *singbox.ProtocolConfig) error {
	enabledList := p.EnabledProtocolList()
	if len(enabledList) == 0 {
		// 协议配置存在但没有启用任何协议，这是合法的（可能正在配置中）
		return nil
	}

	// 验证各协议端口范围
	for _, proto := range enabledList {
		port := getProtocolPort(p, proto)
		if port != 0 && (port < 1 || port > 65535) {
			return fmt.Errorf("协议 %s 端口超出范围: %d", proto, port)
		}
	}

	return nil
}

// getProtocolPort 获取指定协议的端口号
func getProtocolPort(p *singbox.ProtocolConfig, protocol string) int {
	switch protocol {
	case singbox.ProtoSS:
		return p.SS.Port
	case singbox.ProtoHY2:
		return p.HY2.Port
	case singbox.ProtoTUIC:
		return p.TUIC.Port
	case singbox.ProtoReality:
		return p.Reality.Port
	case singbox.ProtoSocks5:
		return p.Socks5.Port
	case singbox.ProtoTrojan:
		return p.Trojan.Port
	case singbox.ProtoAnyTLS:
		return p.AnyTLS.Port
	case singbox.ProtoVmessTCP:
		return p.VMess.TCPPort
	case singbox.ProtoVmessWS:
		return p.VMess.WSPort
	case singbox.ProtoVmessHTTP:
		return p.VMess.HTTPPort
	case singbox.ProtoVmessQUIC:
		return p.VMess.QUICPort
	case singbox.ProtoVmessWST:
		return p.VMess.WSTPort
	case singbox.ProtoVmessHUT:
		return p.VMess.HUTPort
	case singbox.ProtoVlessWST:
		return p.VlessTLS.WSTPort
	case singbox.ProtoVlessHUT:
		return p.VlessTLS.HUTPort
	case singbox.ProtoTrojanWST:
		return p.TrojanTLS.WSTPort
	case singbox.ProtoTrojanHUT:
		return p.TrojanTLS.HUTPort
	default:
		return 0
	}
}

// DeriveWSURL 从 panel_url 推导 WebSocket 上报地址
// panel_url: https://panel.example.com
// 返回: wss://panel.example.com/api/callback/traffic/ws
func DeriveWSURL(panelURL string) string {
	u := strings.TrimSpace(panelURL)
	u = strings.TrimRight(u, "/")
	// 将 https:// 转换为 wss://，http:// 转换为 ws://
	u = strings.Replace(u, "https://", "wss://", 1)
	u = strings.Replace(u, "http://", "ws://", 1)
	return u + "/api/callback/traffic/ws"
}

// DerivePanelURL 从 ws_url 反向推导面板地址
// ws_url: wss://panel.example.com/api/callback/traffic/ws
// 返回: https://panel.example.com
func DerivePanelURL(wsURL string) string {
	u := strings.TrimSpace(wsURL)
	u = strings.Replace(u, "wss://", "https://", 1)
	u = strings.Replace(u, "ws://", "http://", 1)
	if idx := strings.Index(u, "/api/"); idx > 0 {
		u = u[:idx]
	}
	return u
}

// SaveConfig 将配置写回 JSON 文件（持久化运行时变更）
func SaveConfig(path string, cfg *Config) error {
	if path == "" {
		path = DefaultConfigPath
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}

	// Atomic replacement also removes permissive modes from pre-existing files.
	f, err := os.CreateTemp(filepath.Dir(path), ".nodectl-config-*")
	if err != nil {
		return fmt.Errorf("create private config: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return fmt.Errorf("write private config: %w", err)
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace private config: %w", err)
	}
	return nil
}

// GetSingboxBinaryPath 获取 sing-box 二进制路径（带默认值）
func (c *Config) GetSingboxBinaryPath() string {
	if c.Singbox != nil && c.Singbox.BinaryPath != "" {
		return c.Singbox.BinaryPath
	}
	return singbox.DefaultBinaryPath
}

// GetSingboxConfigPath 获取 sing-box 配置文件路径（带默认值）
func (c *Config) GetSingboxConfigPath() string {
	if c.Singbox != nil && c.Singbox.ConfigPath != "" {
		return c.Singbox.ConfigPath
	}
	return singbox.DefaultConfigPath
}

// IsSingboxAutoRestart 是否自动重启 sing-box（默认 true）
func (c *Config) IsSingboxAutoRestart() bool {
	if c.Singbox != nil && c.Singbox.AutoRestart != nil {
		return *c.Singbox.AutoRestart
	}
	return true
}

// MergeProtocolsFromCache 如果 Config.Protocols 为空，尝试从缓存加载
// 返回是否成功加载了协议配置
func (c *Config) MergeProtocolsFromCache() bool {
	if c.Protocols != nil && len(c.Protocols.EnabledProtocolList()) > 0 {
		return true // 配置文件中已有协议配置
	}

	// 尝试从缓存加载
	cm := singbox.NewConfigManager()
	if err := cm.LoadFromCache(); err != nil {
		return false
	}

	c.Protocols = cm.Protocols
	return true
}
