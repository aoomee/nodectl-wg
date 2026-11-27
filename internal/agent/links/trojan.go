// 路径: internal/agent/links/trojan.go
// Trojan 协议链接生成 + Trojan-TLS 传输族
package links

import (
	"fmt"

	"wirearc/internal/agent/singbox"
)

// generateTrojan 生成基础 Trojan 链接（自签 TLS）
// 格式: trojan://<password>@<host>:<port>?sni=<sni>&allowInsecure=1#<name>
func (g *Generator) generateTrojan() []Link {
	cfg := g.config.Trojan
	if cfg.Port <= 0 || cfg.Password == "" {
		return nil
	}

	host := g.linkHost()
	name := g.nodeName(singbox.ProtoTrojan)
	sni := cfg.SNI
	if sni == "" {
		sni = "www.bing.com"
	}

	uri := fmt.Sprintf("trojan://%s@%s:%d?sni=%s&allowInsecure=1#%s",
		urlEncode(cfg.Password), host, cfg.Port, sni, urlEncode(name))

	return []Link{
		{Protocol: singbox.ProtoTrojan, Name: name, URI: uri},
	}
}

// generateTrojanTLS 生成 Trojan+TLS 传输族链接（WST/HUT）
// 格式: trojan://<password>@<host>:<port>?sni=<sni>&type=<transport>&path=<path>&allowInsecure=1&host=<sni>#<name>
func (g *Generator) generateTrojanTLS(tag, transport string, port int) []Link {
	cfg := g.config.TrojanTLS
	if port <= 0 || cfg.Password == "" {
		return nil
	}

	host := g.linkHost()
	name := g.nodeName(tag)
	sni := cfg.TLSSNI
	if sni == "" {
		sni = "www.bing.com"
	}
	tp := g.config.GetTransportPath()

	uri := fmt.Sprintf("trojan://%s@%s:%d?sni=%s&type=%s&path=%s&allowInsecure=1&host=%s#%s",
		urlEncode(cfg.Password), host, port, sni, transport, urlEncode(tp), sni, urlEncode(name))

	return []Link{
		{Protocol: tag, Name: name, URI: uri},
	}
}
