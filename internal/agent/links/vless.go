// 路径: internal/agent/links/vless.go
// VLESS/Reality 协议链接生成 + VLESS-TLS 传输族
package links

import (
	"fmt"

	"wirearc/internal/agent/singbox"
)

// generateReality 生成 VLESS+Reality 链接
// 格式: vless://<uuid>@<host>:<port>?encryption=none&flow=xtls-rprx-vision&security=reality&sni=<sni>&fp=chrome&pbk=<pubkey>&sid=<shortid>#<name>
func (g *Generator) generateReality() []Link {
	cfg := g.config.Reality
	if cfg.Port <= 0 || cfg.UUID == "" || cfg.PublicKey == "" {
		return nil
	}

	host := g.linkHost()
	name := g.nodeName(singbox.ProtoReality)
	sni := cfg.SNI
	if sni == "" {
		sni = "addons.mozilla.org"
	}

	uri := fmt.Sprintf("vless://%s@%s:%d?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s#%s",
		cfg.UUID, host, cfg.Port, sni, cfg.PublicKey, cfg.ShortID, urlEncode(name))

	return []Link{
		{Protocol: singbox.ProtoReality, Name: name, URI: uri},
	}
}

// generateVlessTLS 生成 VLESS+TLS 传输族链接（WST/HUT）
// 格式: vless://<uuid>@<host>:<port>?security=tls&sni=<sni>&type=<transport>&path=<path>&allowInsecure=1&host=<sni>#<name>
func (g *Generator) generateVlessTLS(tag, transport string, port int) []Link {
	cfg := g.config.VlessTLS
	if port <= 0 || cfg.UUID == "" {
		return nil
	}

	host := g.linkHost()
	name := g.nodeName(tag)
	sni := cfg.TLSSNI
	if sni == "" {
		sni = "www.bing.com"
	}
	tp := g.config.GetTransportPath()

	uri := fmt.Sprintf("vless://%s@%s:%d?security=tls&sni=%s&type=%s&path=%s&allowInsecure=1&host=%s#%s",
		cfg.UUID, host, port, sni, transport, urlEncode(tp), sni, urlEncode(name))

	return []Link{
		{Protocol: tag, Name: name, URI: uri},
	}
}
