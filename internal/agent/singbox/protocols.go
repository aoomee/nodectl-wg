// 路径: internal/agent/singbox/protocols.go
// 协议配置结构定义 & 默认值
// 支持的协议: SS, HY2, TUIC, Reality(VLESS), Socks5, Trojan,
//
//	VMess(TCP/WS/HTTP/QUIC/WST/HUT),
//	VLESS-TLS(WST/HUT), Trojan-TLS(WST/HUT)
package singbox

// ProtocolName 协议标识常量（全局统一使用下划线格式，与面板端一致）
const (
	ProtoSS        = "ss"
	ProtoHY2       = "hy2"
	ProtoTUIC      = "tuic"
	ProtoReality   = "reality"    // VLESS+Reality
	ProtoSocks5    = "socks5"     // SOCKS5
	ProtoTrojan    = "trojan"     // Trojan (自签TLS)
	ProtoAnyTLS    = "anytls"     // AnyTLS
	ProtoVmessTCP  = "vmess_tcp"  // VMess 纯TCP
	ProtoVmessWS   = "vmess_ws"   // VMess WebSocket
	ProtoVmessHTTP = "vmess_http" // VMess HTTP
	ProtoVmessQUIC = "vmess_quic" // VMess QUIC(TLS)
	ProtoVmessWST  = "vmess_wst"  // VMess WS+TLS
	ProtoVmessHUT  = "vmess_hut"  // VMess HTTPUpgrade+TLS
	ProtoVlessWST  = "vless_wst"  // VLESS WS+TLS
	ProtoVlessHUT  = "vless_hut"  // VLESS HTTPUpgrade+TLS
	ProtoTrojanWST = "trojan_wst" // Trojan WS+TLS
	ProtoTrojanHUT = "trojan_hut" // Trojan HTTPUpgrade+TLS
)

// AllProtocols 所有支持的协议名称列表
var AllProtocols = []string{
	ProtoSS, ProtoHY2, ProtoTUIC, ProtoReality, ProtoSocks5, ProtoTrojan, ProtoAnyTLS,
	ProtoVmessTCP, ProtoVmessWS, ProtoVmessHTTP, ProtoVmessQUIC, ProtoVmessWST, ProtoVmessHUT,
	ProtoVlessWST, ProtoVlessHUT, ProtoTrojanWST, ProtoTrojanHUT,
}

// ProtocolConfig 所有协议的统一配置集合
type ProtocolConfig struct {
	// 全局参数
	HostSuffix       string `json:"host_suffix"`        // 节点名称后缀（默认取 hostname）
	CustomIP         string `json:"custom_ip"`          // 自定义连接 IP（空=自动检测公网IP）
	TLSTransportPath string `json:"tls_transport_path"` // TLS传输协议共用路径（默认 /ray）

	// 协议开关 map: protocol_name -> enabled
	EnabledProtocols map[string]bool `json:"enabled_protocols"`

	// 各协议独立配置
	SS      SSConfig      `json:"ss,omitempty"`
	HY2     HY2Config     `json:"hy2,omitempty"`
	TUIC    TUICConfig    `json:"tuic,omitempty"`
	Reality RealityConfig `json:"reality,omitempty"`
	Socks5  Socks5Config  `json:"socks5,omitempty"`
	Trojan  TrojanConfig  `json:"trojan,omitempty"`
	AnyTLS  AnyTLSConfig  `json:"anytls,omitempty"`

	// VMess 族（共用 UUID）
	VMess VMessGroupConfig `json:"vmess,omitempty"`

	// VLESS-TLS 族（共用 UUID，与 Reality 不同）
	VlessTLS VlessTLSGroupConfig `json:"vless_tls,omitempty"`

	// Trojan-TLS 族（共用密码，与基础 Trojan 不同）
	TrojanTLS TrojanTLSGroupConfig `json:"trojan_tls,omitempty"`
}

// SSConfig Shadowsocks 协议配置
type SSConfig struct {
	Port     int    `json:"port"`
	Method   string `json:"method"`   // 加密方法，如 2022-blake3-aes-128-gcm
	Password string `json:"password"` // PSK 密码
}

// HY2Config Hysteria2 协议配置
type HY2Config struct {
	Port     int    `json:"port"`
	Password string `json:"password"` // 认证密码
	SNI      string `json:"sni"`      // 客户端 SNI（默认 www.bing.com）
}

// TUICConfig TUIC 协议配置
type TUICConfig struct {
	Port     int    `json:"port"`
	UUID     string `json:"uuid"`
	Password string `json:"password"`
	SNI      string `json:"sni"` // 客户端 SNI
}

// RealityConfig VLESS+Reality 协议配置
type RealityConfig struct {
	Port       int    `json:"port"`
	UUID       string `json:"uuid"`
	PrivateKey string `json:"private_key"` // Reality 私钥（base64）
	PublicKey  string `json:"public_key"`  // Reality 公钥（客户端使用）
	ShortID    string `json:"short_id"`    // Reality Short ID
	SNI        string `json:"sni"`         // 伪装域名（默认 addons.mozilla.org）
}

// Socks5Config SOCKS5 协议配置
type Socks5Config struct {
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// TrojanConfig Trojan 协议配置（自签 TLS）
type TrojanConfig struct {
	Port     int    `json:"port"`
	Password string `json:"password"`
	SNI      string `json:"sni"` // 客户端 SNI
}

// AnyTLSConfig AnyTLS 协议配置（自签 TLS）
type AnyTLSConfig struct {
	Port     int    `json:"port"`
	Password string `json:"password"` // UUID 作为密码
	SNI      string `json:"sni"`      // 客户端 SNI（默认 addons.mozilla.org）
}

// VMessGroupConfig VMess 协议族配置（共用 UUID）
type VMessGroupConfig struct {
	UUID string `json:"uuid"` // 所有 VMess 变体共用

	// 各变体端口（0 = 未启用，由 EnabledProtocols 开关控制）
	TCPPort  int `json:"tcp_port,omitempty"`
	WSPort   int `json:"ws_port,omitempty"`
	HTTPPort int `json:"http_port,omitempty"`
	QUICPort int `json:"quic_port,omitempty"`
	WSTPort  int `json:"wst_port,omitempty"` // WS+TLS
	HUTPort  int `json:"hut_port,omitempty"` // HTTPUpgrade+TLS

	// TLS 相关
	TLSSNI string `json:"tls_sni,omitempty"` // VMess+TLS 的 SNI（默认 www.bing.com）
}

// VlessTLSGroupConfig VLESS+TLS 族配置（共用 UUID，与 Reality VLESS 不同）
type VlessTLSGroupConfig struct {
	UUID string `json:"uuid"` // VLESS-TLS 族共用 UUID

	WSTPort int `json:"wst_port,omitempty"` // WS+TLS
	HUTPort int `json:"hut_port,omitempty"` // HTTPUpgrade+TLS

	TLSSNI string `json:"tls_sni,omitempty"` // VLESS+TLS 的 SNI
}

// TrojanTLSGroupConfig Trojan+TLS 族配置（共用密码，与基础 Trojan 不同）
type TrojanTLSGroupConfig struct {
	Password string `json:"password"` // Trojan-TLS 族共用密码

	WSTPort int `json:"wst_port,omitempty"` // WS+TLS
	HUTPort int `json:"hut_port,omitempty"` // HTTPUpgrade+TLS

	TLSSNI string `json:"tls_sni,omitempty"` // Trojan+TLS 的 SNI
}

// DefaultProtocolConfig 返回带有默认值的协议配置
func DefaultProtocolConfig() *ProtocolConfig {
	return &ProtocolConfig{
		TLSTransportPath: "/ray",
		EnabledProtocols: make(map[string]bool),
		SS: SSConfig{
			Method: "2022-blake3-aes-128-gcm",
		},
		HY2: HY2Config{
			SNI: "www.bing.com",
		},
		TUIC: TUICConfig{
			SNI: "www.bing.com",
		},
		Reality: RealityConfig{
			SNI: "www.bing.com", // 与 VlessTLS 保持一致，面板下发 vless_tls SNI 时同步覆盖
		},
		Trojan: TrojanConfig{
			SNI: "www.bing.com",
		},
		AnyTLS: AnyTLSConfig{
			SNI: "addons.mozilla.org",
		},
		VMess: VMessGroupConfig{
			TLSSNI: "www.bing.com",
		},
		VlessTLS: VlessTLSGroupConfig{
			TLSSNI: "www.bing.com",
		},
		TrojanTLS: TrojanTLSGroupConfig{
			TLSSNI: "www.bing.com",
		},
	}
}

// IsEnabled 检查某个协议是否启用
func (pc *ProtocolConfig) IsEnabled(protocol string) bool {
	if pc.EnabledProtocols == nil {
		return false
	}
	return pc.EnabledProtocols[protocol]
}

// SetEnabled 设置协议启用/禁用
func (pc *ProtocolConfig) SetEnabled(protocol string, enabled bool) {
	if pc.EnabledProtocols == nil {
		pc.EnabledProtocols = make(map[string]bool)
	}
	pc.EnabledProtocols[protocol] = enabled
}

// EnabledProtocolList 返回所有已启用协议名称列表
func (pc *ProtocolConfig) EnabledProtocolList() []string {
	var result []string
	for _, p := range AllProtocols {
		if pc.IsEnabled(p) {
			result = append(result, p)
		}
	}
	return result
}

// GetTransportPath 获取 TLS 传输路径（带默认值）
func (pc *ProtocolConfig) GetTransportPath() string {
	if pc.TLSTransportPath == "" {
		return "/ray"
	}
	return pc.TLSTransportPath
}

// NeedSelfSignedCert 判断是否有协议需要自签证书
func (pc *ProtocolConfig) NeedSelfSignedCert() bool {
	certProtocols := []string{
		ProtoHY2, ProtoTUIC, ProtoTrojan, ProtoAnyTLS,
		ProtoVmessQUIC, ProtoVmessWST, ProtoVmessHUT,
		ProtoVlessWST, ProtoVlessHUT,
		ProtoTrojanWST, ProtoTrojanHUT,
	}
	for _, p := range certProtocols {
		if pc.IsEnabled(p) {
			return true
		}
	}
	return false
}

// ValidateProtocolName 验证协议名称是否合法
func ValidateProtocolName(name string) bool {
	for _, p := range AllProtocols {
		if p == name {
			return true
		}
	}
	return false
}
