// 路径: internal/agent/links/vmess.go
// VMess 协议族链接生成
// VMess 使用 base64 JSON 格式: vmess://<base64(json)>
package links

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// vmessLinkJSON VMess 链接 JSON 结构（v2rayN 标准格式）
type vmessLinkJSON struct {
	V             string `json:"v"`
	PS            string `json:"ps"`
	Add           string `json:"add"`
	Port          string `json:"port"`
	ID            string `json:"id"`
	AID           string `json:"aid"`
	Net           string `json:"net"`
	Type          string `json:"type"`
	Host          string `json:"host"`
	Path          string `json:"path"`
	TLS           string `json:"tls"`
	SNI           string `json:"sni"`
	ALPN          string `json:"alpn"`
	AllowInsecure any    `json:"allowInsecure"`
}

// generateVMess 生成 VMess 链接
// tag: 链接标签名（如 "vmess-tcp"）
// net: 传输类型（tcp/ws/http/quic/httpupgrade）
// port: 监听端口
// useTLS: 是否启用 TLS
// path: 传输路径（仅 ws/http/httpupgrade 需要）
func (g *Generator) generateVMess(tag, net string, port int, useTLS bool, path string) []Link {
	cfg := g.config.VMess
	if port <= 0 || cfg.UUID == "" {
		return nil
	}

	rawIP := g.rawHost()
	name := g.nodeName(tag)

	tlsStr := ""
	sni := ""
	alpn := ""
	allowInsecure := false

	if useTLS {
		tlsStr = "tls"
		sni = cfg.TLSSNI
		if sni == "" {
			sni = "www.bing.com"
		}
		allowInsecure = true
		// QUIC 默认 ALPN
		if net == "quic" && alpn == "" {
			alpn = "h3"
		}
	}

	host := rawIP
	if useTLS && sni != "" {
		host = sni
	}

	linkJSON := vmessLinkJSON{
		V:             "2",
		PS:            name,
		Add:           rawIP,
		Port:          fmt.Sprintf("%d", port),
		ID:            cfg.UUID,
		AID:           "0",
		Net:           net,
		Type:          "none",
		Host:          host,
		Path:          path,
		TLS:           tlsStr,
		SNI:           sni,
		ALPN:          alpn,
		AllowInsecure: allowInsecure,
	}

	jsonBytes, err := json.Marshal(linkJSON)
	if err != nil {
		return nil
	}

	encoded := base64.StdEncoding.EncodeToString(jsonBytes)
	uri := fmt.Sprintf("vmess://%s", encoded)

	return []Link{
		{Protocol: tag, Name: name, URI: uri},
	}
}
