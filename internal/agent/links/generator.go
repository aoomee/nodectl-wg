// 路径: internal/agent/links/generator.go
// 统一链接生成器：根据协议配置生成各协议的客户端链接
package links

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"wirearc/internal/agent/singbox"
)

// Link 通用链接结构
type Link struct {
	Protocol string `json:"protocol"` // 协议标识（与 singbox.Proto* 一致）
	Name     string `json:"name"`     // 显示名称（如 "ss-节点名"）
	URI      string `json:"uri"`      // 完整的协议链接
}

// Generator 链接生成器
type Generator struct {
	config *singbox.ProtocolConfig
	hostIP string // 节点公网 IP（或自定义 IP）
	suffix string // 节点名称后缀
}

// NewGenerator 创建链接生成器
// hostIP: 节点公网 IP（必填）
// suffix: 节点名称后缀（可选，如 hostname）
// config: 协议配置（必填）
func NewGenerator(hostIP, suffix string, config *singbox.ProtocolConfig) *Generator {
	return &Generator{
		config: config,
		hostIP: hostIP,
		suffix: suffix,
	}
}

// GenerateAll 生成所有已启用协议的链接
func (g *Generator) GenerateAll() []Link {
	var links []Link

	for _, proto := range singbox.AllProtocols {
		if !g.config.IsEnabled(proto) {
			continue
		}

		generated := g.generateForProtocol(proto)
		links = append(links, generated...)
	}

	return links
}

// GenerateForProtocols 生成指定协议的链接
func (g *Generator) GenerateForProtocols(protocols []string) []Link {
	var links []Link

	for _, proto := range protocols {
		if !g.config.IsEnabled(proto) {
			continue
		}
		generated := g.generateForProtocol(proto)
		links = append(links, generated...)
	}

	return links
}

// GenerateAllMap 生成链接 map 格式（protocol -> uri）
func (g *Generator) GenerateAllMap() map[string]string {
	result := make(map[string]string)
	for _, link := range g.GenerateAll() {
		result[link.Protocol] = link.URI
	}
	return result
}

// generateForProtocol 生成单个协议的链接
func (g *Generator) generateForProtocol(proto string) []Link {
	switch proto {
	case singbox.ProtoSS:
		return g.generateSS()
	case singbox.ProtoHY2:
		return g.generateHY2()
	case singbox.ProtoTUIC:
		return g.generateTUIC()
	case singbox.ProtoReality:
		return g.generateReality()
	case singbox.ProtoSocks5:
		return g.generateSocks5()
	case singbox.ProtoTrojan:
		return g.generateTrojan()
	case singbox.ProtoAnyTLS:
		return g.generateAnyTLS()
	case singbox.ProtoVmessTCP:
		return g.generateVMess(singbox.ProtoVmessTCP, "tcp", g.config.VMess.TCPPort, false, "")
	case singbox.ProtoVmessWS:
		return g.generateVMess(singbox.ProtoVmessWS, "ws", g.config.VMess.WSPort, false, g.config.GetTransportPath())
	case singbox.ProtoVmessHTTP:
		return g.generateVMess(singbox.ProtoVmessHTTP, "http", g.config.VMess.HTTPPort, false, g.config.GetTransportPath())
	case singbox.ProtoVmessQUIC:
		return g.generateVMess(singbox.ProtoVmessQUIC, "quic", g.config.VMess.QUICPort, true, "")
	case singbox.ProtoVmessWST:
		return g.generateVMess(singbox.ProtoVmessWST, "ws", g.config.VMess.WSTPort, true, g.config.GetTransportPath())
	case singbox.ProtoVmessHUT:
		return g.generateVMess(singbox.ProtoVmessHUT, "httpupgrade", g.config.VMess.HUTPort, true, g.config.GetTransportPath())
	case singbox.ProtoVlessWST:
		return g.generateVlessTLS(singbox.ProtoVlessWST, "ws", g.config.VlessTLS.WSTPort)
	case singbox.ProtoVlessHUT:
		return g.generateVlessTLS(singbox.ProtoVlessHUT, "httpupgrade", g.config.VlessTLS.HUTPort)
	case singbox.ProtoTrojanWST:
		return g.generateTrojanTLS(singbox.ProtoTrojanWST, "ws", g.config.TrojanTLS.WSTPort)
	case singbox.ProtoTrojanHUT:
		return g.generateTrojanTLS(singbox.ProtoTrojanHUT, "httpupgrade", g.config.TrojanTLS.HUTPort)
	default:
		return nil
	}
}

// --- 辅助函数 ---

// linkHost 返回用于链接中的 host 部分
// IPv6 地址需要用方括号包裹
func (g *Generator) linkHost() string {
	ip := g.hostIP
	if g.config.CustomIP != "" {
		ip = g.config.CustomIP
	}
	if strings.Contains(ip, ":") {
		return "[" + ip + "]"
	}
	return ip
}

// rawHost 返回不带方括号的原始 IP
func (g *Generator) rawHost() string {
	if g.config.CustomIP != "" {
		return g.config.CustomIP
	}
	return g.hostIP
}

// nodeName 返回节点名称
// 优先使用服务器名称（suffix / hostname），无则回退到协议标识
func (g *Generator) nodeName(proto string) string {
	if g.suffix != "" {
		return g.suffix
	}
	return proto
}

// urlEncode URL 编码特殊字符
func urlEncode(s string) string {
	return url.QueryEscape(s)
}

// isIPv6 判断是否是 IPv6 地址
func isIPv6(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() == nil
}

// formatHostPort 格式化 host:port（IPv6 自动加方括号）
func formatHostPort(host string, port int) string {
	if isIPv6(host) {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}
