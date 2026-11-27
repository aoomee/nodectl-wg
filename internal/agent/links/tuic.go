// 路径: internal/agent/links/tuic.go
// TUIC 协议链接生成
package links

import (
	"fmt"

	"wirearc/internal/agent/singbox"
)

// generateTUIC 生成 TUIC 链接
// 格式: tuic://<uuid>:<password>@<host>:<port>/?congestion_control=bbr&alpn=h3&sni=<sni>&insecure=1#<name>
func (g *Generator) generateTUIC() []Link {
	cfg := g.config.TUIC
	if cfg.Port <= 0 || cfg.UUID == "" || cfg.Password == "" {
		return nil
	}

	host := g.linkHost()
	name := g.nodeName(singbox.ProtoTUIC)
	sni := cfg.SNI
	if sni == "" {
		sni = "www.bing.com"
	}

	uri := fmt.Sprintf("tuic://%s:%s@%s:%d/?congestion_control=bbr&alpn=h3&sni=%s&insecure=1#%s",
		cfg.UUID, urlEncode(cfg.Password), host, cfg.Port, sni, urlEncode(name))

	return []Link{
		{Protocol: singbox.ProtoTUIC, Name: name, URI: uri},
	}
}
