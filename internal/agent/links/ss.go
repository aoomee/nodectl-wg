// 路径: internal/agent/links/ss.go
// Shadowsocks 协议链接生成
package links

import (
	"encoding/base64"
	"fmt"

	"wirearc/internal/agent/singbox"
)

// generateSS 生成 Shadowsocks 链接
// 格式: ss://<base64(method:password)>@<host>:<port>#<name>
func (g *Generator) generateSS() []Link {
	cfg := g.config.SS
	if cfg.Port <= 0 || cfg.Password == "" {
		return nil
	}

	host := g.linkHost()
	name := g.nodeName(singbox.ProtoSS)

	// 标准格式: ss://base64(method:password)@host:port#name
	userInfo := fmt.Sprintf("%s:%s", cfg.Method, cfg.Password)
	encoded := base64.StdEncoding.EncodeToString([]byte(userInfo))

	uri := fmt.Sprintf("ss://%s@%s:%d#%s", encoded, host, cfg.Port, urlEncode(name))

	return []Link{
		{Protocol: singbox.ProtoSS, Name: name, URI: uri},
	}
}
