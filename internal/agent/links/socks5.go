// 路径: internal/agent/links/socks5.go
// SOCKS5 协议链接生成
package links

import (
	"fmt"

	"wirearc/internal/agent/singbox"
)

// generateSocks5 生成 SOCKS5 链接
// 格式: socks5://<username>:<password>@<host>:<port>#<name>
func (g *Generator) generateSocks5() []Link {
	cfg := g.config.Socks5
	if cfg.Port <= 0 || cfg.Username == "" || cfg.Password == "" {
		return nil
	}

	host := g.linkHost()
	name := g.nodeName(singbox.ProtoSocks5)

	uri := fmt.Sprintf("socks5://%s:%s@%s:%d#%s",
		urlEncode(cfg.Username), urlEncode(cfg.Password), host, cfg.Port, urlEncode(name))

	return []Link{
		{Protocol: singbox.ProtoSocks5, Name: name, URI: uri},
	}
}
