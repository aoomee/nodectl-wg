// 路径: internal/agent/links/hy2.go
// Hysteria2 协议链接生成
package links

import (
	"fmt"

	"wirearc/internal/agent/singbox"
)

// generateHY2 生成 Hysteria2 链接
// 格式: hy2://<password>@<host>:<port>/?sni=<sni>&alpn=h3&insecure=1#<name>
func (g *Generator) generateHY2() []Link {
	cfg := g.config.HY2
	if cfg.Port <= 0 || cfg.Password == "" {
		return nil
	}

	host := g.linkHost()
	name := g.nodeName(singbox.ProtoHY2)
	sni := cfg.SNI
	if sni == "" {
		sni = "www.bing.com"
	}

	uri := fmt.Sprintf("hy2://%s@%s:%d/?sni=%s&alpn=h3&insecure=1#%s",
		urlEncode(cfg.Password), host, cfg.Port, sni, urlEncode(name))

	return []Link{
		{Protocol: singbox.ProtoHY2, Name: name, URI: uri},
	}
}
