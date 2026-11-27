// 路径: internal/agent/links/anytls.go
// AnyTLS 协议链接生成
package links

import (
	"fmt"

	"wirearc/internal/agent/singbox"
)

// generateAnyTLS 生成 AnyTLS 链接
// 格式: anytls://<password>@<host>:<port>?security=tls&sni=<sni>&fp=firefox&insecure=1&allowInsecure=1&type=tcp#<name>
func (g *Generator) generateAnyTLS() []Link {
	cfg := g.config.AnyTLS
	if cfg.Port <= 0 || cfg.Password == "" {
		return nil
	}

	host := g.linkHost()
	name := g.nodeName(singbox.ProtoAnyTLS)
	sni := cfg.SNI
	if sni == "" {
		sni = "addons.mozilla.org"
	}

	uri := fmt.Sprintf("anytls://%s@%s:%d?security=tls&sni=%s&fp=firefox&insecure=1&allowInsecure=1&type=tcp#%s",
		urlEncode(cfg.Password), host, cfg.Port, sni, urlEncode(name))

	return []Link{
		{Protocol: singbox.ProtoAnyTLS, Name: name, URI: uri},
	}
}
