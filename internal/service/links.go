package service

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"wirearc/internal/logger"
)

// 1. 数据结构定义

// ClashNode 统一节点结构体，强制规范 YAML 输出格式
type ClashNode struct {
	Name                 string                 `yaml:"name"`
	Type                 string                 `yaml:"type"`
	Server               string                 `yaml:"server"`
	Port                 int                    `yaml:"port"`
	Username             string                 `yaml:"username,omitempty"`
	Password             string                 `yaml:"password,omitempty"`
	UUID                 string                 `yaml:"uuid,omitempty"`
	Cipher               string                 `yaml:"cipher,omitempty"`
	AlterId              *int                   `yaml:"alterId,omitempty"`
	Network              string                 `yaml:"network,omitempty"`
	UDP                  bool                   `yaml:"udp,omitempty"`
	TLS                  bool                   `yaml:"tls,omitempty"`
	SkipCertVerify       bool                   `yaml:"skip-cert-verify,omitempty"`
	ServerName           string                 `yaml:"servername,omitempty"`
	SNI                  string                 `yaml:"sni,omitempty"`
	ALPN                 []string               `yaml:"alpn,omitempty"`
	Flow                 string                 `yaml:"flow,omitempty"`
	PacketEncoding       string                 `yaml:"packet-encoding,omitempty"`
	ClientFingerprint    string                 `yaml:"client-fingerprint,omitempty"`
	Plugin               string                 `yaml:"plugin,omitempty"`
	PluginOpts           map[string]interface{} `yaml:"plugin-opts,omitempty"`
	WSOpts               map[string]interface{} `yaml:"ws-opts,omitempty"`
	HTTPOpts             map[string]interface{} `yaml:"http-opts,omitempty"`
	GRPCOpts             map[string]interface{} `yaml:"grpc-opts,omitempty"`
	RealityOpts          map[string]interface{} `yaml:"reality-opts,omitempty"`
	Up                   int                    `yaml:"up,omitempty"`
	Down                 int                    `yaml:"down,omitempty"`
	Obfs                 string                 `yaml:"obfs,omitempty"`
	ObfsPassword         string                 `yaml:"obfs-password,omitempty"`
	CongestionController string                 `yaml:"congestion-controller,omitempty"`
	UDPRelayMode         string                 `yaml:"udp-relay-mode,omitempty"`
	ReduceRTT            bool                   `yaml:"reduce-rtt,omitempty"`

	// 扩展字段: 用于支持 SSR 和 Hysteria v1 等特殊协议
	Protocol      string `yaml:"protocol,omitempty"`
	ProtocolParam string `yaml:"protocol-param,omitempty"`
	ObfsParam     string `yaml:"obfs-param,omitempty"`
	AuthStr       string `yaml:"auth-str,omitempty"`
}

// vmessJSON 定义 VMess 协议特有的 JSON 结构
type vmessJSON struct {
	V             interface{} `json:"v"`
	Ps            string      `json:"ps"`
	Add           string      `json:"add"`
	Port          interface{} `json:"port"`
	Id            string      `json:"id"`
	Aid           interface{} `json:"aid"`
	Scy           string      `json:"scy"`
	Net           string      `json:"net"`
	Type          string      `json:"type"`
	Host          interface{} `json:"host"`
	Path          string      `json:"path"`
	Tls           string      `json:"tls"`
	Sni           string      `json:"sni"`
	Alpn          string      `json:"alpn"`
	Fp            string      `json:"fp"`
	AllowInsecure bool        `json:"allowInsecure"` // 自定义扩展字段：自签证书跳过验证
}

// 2. 通用辅助函数

// ptrInt 返回指向整数的指针，用于 AlterId 字段（omitempty 不会忽略 *int 指向的 0 值）
func ptrInt(v int) *int { return &v }

func parseBool(v string) bool {
	v = strings.TrimSpace(strings.ToLower(v))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

// parseInt 统一处理解析引擎中可能是 interface{} 或 string 的端口类型
func parseInt(port interface{}) int {
	if port == nil {
		return 0
	}
	switch v := port.(type) {
	case int:
		return v
	case float64:
		return int(v)
	case string:
		i, _ := strconv.Atoi(v)
		return i
	default:
		return 0
	}
}

// safeBase64Decode 尝试多种 Base64 补齐和解码方式，增强容错率
func safeBase64Decode(str string) string {
	str = strings.ReplaceAll(str, "-", "+")
	str = strings.ReplaceAll(str, "_", "/")
	pads := len(str) % 4
	if pads > 0 {
		str += strings.Repeat("=", 4-pads)
	}
	decoded, err := base64.StdEncoding.DecodeString(str)
	if err == nil {
		return string(decoded)
	}
	decoded, err = base64.URLEncoding.DecodeString(str)
	if err == nil {
		return string(decoded)
	}
	return ""
}

func detectLinkNodeName(link string) string {
	trimmed := strings.TrimSpace(link)
	if trimmed == "" {
		return "unknown"
	}

	if u, err := url.Parse(trimmed); err == nil {
		name := strings.TrimSpace(u.Fragment)
		if name != "" {
			if decoded, err := url.QueryUnescape(name); err == nil && strings.TrimSpace(decoded) != "" {
				return strings.TrimSpace(decoded)
			}
			return name
		}
	}

	return "unknown"
}

// logLinkParseSkip 统一记录链接转换失败日志，便于定位订阅生成时被忽略的节点
func logLinkParseSkip(reason string, link string) {
	trimmed := strings.TrimSpace(link)
	nodeName := detectLinkNodeName(trimmed)
	if trimmed == "" {
		logger.Log.Warn("链接转换失败，已跳过", "reason", reason, "protocol", "unknown", "node_name", nodeName, "link", "<empty>")
		return
	}

	if len(trimmed) > 256 {
		trimmed = trimmed[:256] + "..."
	}

	proto := "unknown"
	if idx := strings.Index(trimmed, "://"); idx > 0 {
		proto = strings.ToLower(trimmed[:idx])
	}

	logger.Log.Warn("链接转换失败，已跳过", "reason", reason, "protocol", proto, "node_name", nodeName, "link", trimmed)
}

// 3. 核心分发调度中心

// ParseLinkToClashNode 将分享链接解析并映射为 Clash 节点对象
func ParseLinkToClashNode(link string, nameSuffix string) *ClashNode {
	lowerLink := strings.ToLower(link)
	if strings.TrimSpace(link) == "" {
		logLinkParseSkip("empty-link", link)
		return nil
	}

	// [1] 处理 VMess 协议 (JSON over Base64)
	if strings.HasPrefix(lowerLink, "vmess://") {
		body := safeBase64Decode(link[8:])
		if body == "" {
			logLinkParseSkip("vmess-base64-decode-failed", link)
			return nil
		}
		var vj vmessJSON
		if err := json.Unmarshal([]byte(body), &vj); err != nil {
			logLinkParseSkip("vmess-json-unmarshal-failed", link)
			return nil
		}
		alterId := parseInt(vj.Aid)
		node := &ClashNode{
			Name:              vj.Ps + nameSuffix,
			Type:              "vmess",
			Server:            vj.Add,
			Port:              parseInt(vj.Port),
			UUID:              vj.Id,
			AlterId:           ptrInt(alterId),
			Cipher:            vj.Scy,
			Network:           vj.Net,
			ServerName:        vj.Sni,
			ClientFingerprint: vj.Fp,
			UDP:               true,
		}

		if node.Cipher == "" {
			node.Cipher = "auto"
		}

		if vj.Tls == "tls" {
			node.TLS = true
		}
		if vj.AllowInsecure {
			node.SkipCertVerify = true
		}
		if vj.Alpn != "" {
			node.ALPN = strings.Split(vj.Alpn, ",")
		}
		if node.Network == "quic" && node.TLS && len(node.ALPN) == 0 {
			node.ALPN = []string{"h3"}
		}
		// 智能解析 host 字段（可能是字符串或数组）
		hostStr := ""
		switch v := vj.Host.(type) {
		case string:
			hostStr = v
		case []interface{}:
			if len(v) > 0 {
				if s, ok := v[0].(string); ok {
					hostStr = s
				}
			}
		}

		if node.Network == "ws" {
			node.WSOpts = map[string]interface{}{"path": vj.Path}
			if hostStr != "" {
				node.WSOpts["headers"] = map[string]string{"Host": hostStr}
			}
		} else if node.Network == "grpc" {
			node.GRPCOpts = map[string]interface{}{"grpc-service-name": vj.Path}
		} else if node.Network == "httpupgrade" {
			// Mihomo 侧使用 ws + v2ray-http-upgrade 表达 HTTPUpgrade 传输
			node.Network = "ws"
			node.WSOpts = map[string]interface{}{
				"path":               vj.Path,
				"v2ray-http-upgrade": true,
			}
			if hostStr != "" {
				node.WSOpts["headers"] = map[string]string{"Host": hostStr}
			}
		} else if node.Network == "http" {
			// VMess-HTTP (HTTP/1.1 无 TLS) 需要显式 http-opts 传递 path
			node.HTTPOpts = map[string]interface{}{"path": []string{vj.Path}}
			if hostStr != "" {
				node.HTTPOpts["headers"] = map[string]interface{}{"Host": []string{hostStr}}
			}
		}
		return node
	}

	// [2] 处理 Trojan 协议
	if strings.HasPrefix(lowerLink, "trojan://") {
		u, err := url.Parse(link)
		if err != nil {
			logLinkParseSkip("trojan-url-parse-failed", link)
			return nil
		}
		port, _ := strconv.Atoi(u.Port())
		pass := u.User.Username()
		if pass == "" {
			pass, _ = u.User.Password()
		}
		node := &ClashNode{
			Name:              u.Fragment + nameSuffix,
			Type:              "trojan",
			Server:            u.Hostname(),
			Port:              port,
			Password:          pass,
			UDP:               true,
			SNI:               u.Query().Get("sni"),
			ClientFingerprint: u.Query().Get("fp"),
			Network:           u.Query().Get("type"),
		}
		if node.SNI == "" {
			node.SNI = u.Query().Get("peer")
		}
		if insecure := u.Query().Get("allowInsecure"); parseBool(insecure) {
			node.SkipCertVerify = true
		}
		if alpn := u.Query().Get("alpn"); alpn != "" {
			node.ALPN = strings.Split(alpn, ",")
		}
		if node.Network == "ws" {
			node.WSOpts = map[string]interface{}{"path": u.Query().Get("path")}
			if host := u.Query().Get("host"); host != "" {
				node.WSOpts["headers"] = map[string]string{"Host": host}
			}
		} else if node.Network == "grpc" {
			node.GRPCOpts = map[string]interface{}{"grpc-service-name": u.Query().Get("serviceName")}
		} else if node.Network == "httpupgrade" {
			// Mihomo 侧使用 ws + v2ray-http-upgrade 表达 HTTPUpgrade 传输
			node.Network = "ws"
			node.WSOpts = map[string]interface{}{
				"path":               u.Query().Get("path"),
				"v2ray-http-upgrade": true,
			}
			if host := u.Query().Get("host"); host != "" {
				node.WSOpts["headers"] = map[string]string{"Host": host}
			}
		}
		return node
	}

	// [3] 处理 SSR (ShadowsocksR) 协议
	if strings.HasPrefix(lowerLink, "ssr://") {
		decoded := safeBase64Decode(link[6:])
		if decoded == "" {
			logLinkParseSkip("ssr-base64-decode-failed", link)
			return nil
		}
		parts := strings.SplitN(decoded, "/?", 2)
		mainPart := parts[0]
		queryPart := ""
		if len(parts) > 1 {
			queryPart = parts[1]
		}
		params := strings.Split(mainPart, ":")
		if len(params) >= 6 {
			port, _ := strconv.Atoi(params[1])
			node := &ClashNode{
				Type:     "ssr",
				Server:   params[0],
				Port:     port,
				Protocol: params[2],
				Cipher:   params[3],
				Obfs:     params[4],
				Password: safeBase64Decode(params[5]),
				UDP:      true,
			}
			// 解析查询参数中的名称和混淆
			if queryPart != "" {
				q, _ := url.ParseQuery(queryPart)
				if obfsparam := q.Get("obfsparam"); obfsparam != "" {
					node.ObfsParam = safeBase64Decode(obfsparam)
				}
				if protoparam := q.Get("protoparam"); protoparam != "" {
					node.ProtocolParam = safeBase64Decode(protoparam)
				}
				if remarks := q.Get("remarks"); remarks != "" {
					node.Name = safeBase64Decode(remarks) + nameSuffix
				}
			}
			if node.Name == "" {
				node.Name = node.Server + ":" + strconv.Itoa(port) + nameSuffix
			}
			return node
		}
		logLinkParseSkip("ssr-format-invalid", link)
		return nil
	}

	// [4] 处理 VLESS 协议
	if strings.HasPrefix(lowerLink, "vless://") {
		u, err := url.Parse(link)
		if err != nil {
			logLinkParseSkip("vless-url-parse-failed", link)
			return nil
		}
		port, _ := strconv.Atoi(u.Port())
		node := &ClashNode{
			Name:       u.Fragment + nameSuffix,
			Type:       "vless",
			Server:     u.Hostname(),
			Port:       port,
			UUID:       u.User.Username(),
			UDP:        true,
			Network:    u.Query().Get("type"),
			ServerName: u.Query().Get("sni"),
		}
		if flow := u.Query().Get("flow"); flow != "" {
			node.Flow = flow
		}
		if pe := u.Query().Get("packetEncoding"); pe != "" {
			node.PacketEncoding = pe
		}
		if alpn := u.Query().Get("alpn"); alpn != "" {
			node.ALPN = strings.Split(alpn, ",")
		}
		if u.Query().Get("security") == "tls" || u.Query().Get("security") == "reality" {
			node.TLS = true
		}
		if insecure := u.Query().Get("allowInsecure"); parseBool(insecure) {
			node.SkipCertVerify = true
		}
		if u.Query().Get("security") == "reality" {
			node.RealityOpts = map[string]interface{}{
				"public-key": u.Query().Get("pbk"),
				"short-id":   u.Query().Get("sid"),
			}
		}
		if u.Query().Get("fp") != "" {
			node.ClientFingerprint = u.Query().Get("fp")
		}
		if node.Network == "ws" {
			node.WSOpts = map[string]interface{}{
				"path": u.Query().Get("path"),
				"headers": map[string]string{
					"Host": u.Query().Get("host"),
				},
			}
		} else if node.Network == "grpc" {
			node.GRPCOpts = map[string]interface{}{
				"grpc-service-name": u.Query().Get("serviceName"),
			}
		} else if node.Network == "httpupgrade" {
			// Mihomo 侧使用 ws + v2ray-http-upgrade 表达 HTTPUpgrade 传输
			node.Network = "ws"
			node.WSOpts = map[string]interface{}{
				"path":               u.Query().Get("path"),
				"v2ray-http-upgrade": true,
			}
			if host := u.Query().Get("host"); host != "" {
				node.WSOpts["headers"] = map[string]string{"Host": host}
			}
		}
		return node
	}

	// [5] 处理 Hysteria 协议 (兼容 v1 和 v2 别名)
	if strings.HasPrefix(lowerLink, "hy2://") || strings.HasPrefix(lowerLink, "hysteria2://") {
		u, err := url.Parse(link)
		if err != nil {
			logLinkParseSkip("hysteria2-url-parse-failed", link)
			return nil
		}
		port, _ := strconv.Atoi(u.Port())
		pass := u.User.Username()
		if pass == "" {
			pass, _ = u.User.Password()
		}
		node := &ClashNode{
			Name:     u.Fragment + nameSuffix,
			Type:     "hysteria2",
			Server:   u.Hostname(),
			Port:     port,
			Password: pass,
			SNI:      u.Query().Get("sni"),
		}
		if node.SNI == "" {
			node.SNI = u.Query().Get("peer")
		}
		if alpn := u.Query().Get("alpn"); alpn != "" {
			node.ALPN = strings.Split(alpn, ",")
		}
		if insecure := u.Query().Get("insecure"); parseBool(insecure) {
			node.SkipCertVerify = true
		}
		if obfs := u.Query().Get("obfs"); obfs != "" && obfs != "none" {
			node.Obfs = obfs
			node.ObfsPassword = u.Query().Get("obfs-password")
		}
		return node
	} else if strings.HasPrefix(lowerLink, "hy://") || strings.HasPrefix(lowerLink, "hysteria://") {
		u, err := url.Parse(link)
		if err != nil {
			logLinkParseSkip("hysteria-url-parse-failed", link)
			return nil
		}
		port, _ := strconv.Atoi(u.Port())
		node := &ClashNode{
			Name:    u.Fragment + nameSuffix,
			Type:    "hysteria",
			Server:  u.Hostname(),
			Port:    port,
			SNI:     u.Query().Get("peer"),
			AuthStr: u.Query().Get("auth"),
			Up:      parseInt(u.Query().Get("upmbps")),
			Down:    parseInt(u.Query().Get("downmbps")),
		}
		if insecure := u.Query().Get("insecure"); parseBool(insecure) {
			node.SkipCertVerify = true
		}
		if alpn := u.Query().Get("alpn"); alpn != "" {
			node.ALPN = strings.Split(alpn, ",")
		}
		return node
	}

	// [6] 处理 TUIC 协议
	if strings.HasPrefix(lowerLink, "tuic://") {
		u, err := url.Parse(link)
		if err != nil {
			logLinkParseSkip("tuic-url-parse-failed", link)
			return nil
		}
		port, _ := strconv.Atoi(u.Port())
		pass, _ := u.User.Password()
		node := &ClashNode{
			Name:                 u.Fragment + nameSuffix,
			Type:                 "tuic",
			Server:               u.Hostname(),
			Port:                 port,
			UUID:                 u.User.Username(),
			Password:             pass,
			SNI:                  u.Query().Get("sni"),
			CongestionController: u.Query().Get("congestion_control"),
			UDPRelayMode:         u.Query().Get("udp_relay_mode"),
		}
		if alpn := u.Query().Get("alpn"); alpn != "" {
			node.ALPN = strings.Split(alpn, ",")
		}
		if insecure := u.Query().Get("allow_insecure"); insecure == "1" || insecure == "true" {
			node.SkipCertVerify = true
		} else if insecure := u.Query().Get("insecure"); insecure == "1" || insecure == "true" {
			node.SkipCertVerify = true
		}
		return node
	}

	// [7] 处理 Shadowsocks (SS) 协议
	if strings.HasPrefix(lowerLink, "ss://") {
		body := link[5:]
		if !strings.Contains(body, "@") {
			if decoded := safeBase64Decode(body); decoded != "" {
				body = decoded
			} else {
				logLinkParseSkip("ss-base64-decode-failed", link)
				return nil
			}
		}
		if lastColon := strings.LastIndex(body, ":"); lastColon != -1 {
			if atIndex := strings.LastIndex(body[:lastColon], "@"); atIndex != -1 {
				userInfo := body[:atIndex]
				portInfo := body[lastColon+1:]

				port := portInfo
				name := ""
				if queryIdx := strings.Index(portInfo, "/?"); queryIdx != -1 {
					portInfo = portInfo[:queryIdx] + portInfo[strings.Index(portInfo, "#"):]
				}
				if hashIdx := strings.Index(portInfo, "#"); hashIdx != -1 {
					port = portInfo[:hashIdx]
					name = portInfo[hashIdx+1:]
				}
				port = strings.Trim(port, "/")
				if unescaped, err := url.QueryUnescape(name); err == nil && unescaped != "" {
					name = unescaped
				}
				if unescaped, err := url.QueryUnescape(userInfo); err == nil && strings.Contains(unescaped, ":") {
					userInfo = unescaped
				}
				if !strings.Contains(userInfo, ":") {
					if decoded := safeBase64Decode(userInfo); decoded != "" {
						userInfo = decoded
					}
				}
				b64UserInfo := userInfo
				if decoded := safeBase64Decode(userInfo); decoded != "" {
					b64UserInfo = decoded
				}

				methodPass := strings.SplitN(b64UserInfo, ":", 2)
				if len(methodPass) == 2 {
					p, _ := strconv.Atoi(port)
					return &ClashNode{
						Name:     name + nameSuffix,
						Type:     "ss",
						Server:   body[atIndex+1 : lastColon],
						Port:     p,
						Cipher:   methodPass[0],
						Password: methodPass[1],
						UDP:      true,
					}
				}
			}
		}
	}

	// [8] 处理 Socks5 协议
	if strings.HasPrefix(lowerLink, "socks5://") {
		body := link[9:]
		if !strings.Contains(body, "@") {
			if decoded := safeBase64Decode(body); decoded != "" {
				body = decoded
			}
		}
		parsedURL, err := url.Parse("socks5://" + body)
		if err != nil {
			logLinkParseSkip("socks5-url-parse-failed", link)
			return nil
		}
		portStr := parsedURL.Port()
		if portStr == "" {
			portStr = "1080"
		}
		port, _ := strconv.Atoi(portStr)
		pass, _ := parsedURL.User.Password()
		node := &ClashNode{
			Name:     parsedURL.Fragment + nameSuffix,
			Type:     "socks5",
			Server:   parsedURL.Hostname(),
			Port:     port,
			Username: parsedURL.User.Username(),
			Password: pass,
			UDP:      true,
		}
		return node
	}

	// [9] 处理 AnyTLS 协议 (新增支持)
	if strings.HasPrefix(lowerLink, "anytls://") {
		u, err := url.Parse(link)
		if err != nil {
			logLinkParseSkip("anytls-url-parse-failed", link)
			return nil
		}
		portStr := u.Port()
		if portStr == "" {
			portStr = "443"
		}
		port, _ := strconv.Atoi(portStr)

		// 尝试获取密码，如果为空则尝试使用 Username 字段
		pass, _ := u.User.Password()
		if pass == "" {
			pass = u.User.Username()
		}

		node := &ClashNode{
			Name:              u.Fragment + nameSuffix,
			Type:              "anytls",
			Server:            u.Hostname(),
			Port:              port,
			Password:          pass,
			SNI:               u.Query().Get("sni"),
			ClientFingerprint: u.Query().Get("fp"),
		}
		if skip := u.Query().Get("insecure"); skip == "1" || skip == "true" {
			node.SkipCertVerify = true
		}
		return node
	}

	// [10] 处理 HTTP/HTTPS 代理协议
	if strings.HasPrefix(lowerLink, "http://") || strings.HasPrefix(lowerLink, "https://") {
		u, err := url.Parse(link)
		if err != nil {
			logLinkParseSkip("http-url-parse-failed", link)
			return nil
		}
		portStr := u.Port()
		if portStr == "" {
			if strings.HasPrefix(lowerLink, "https") {
				portStr = "443"
			} else {
				portStr = "80"
			}
		}
		port, _ := strconv.Atoi(portStr)
		pass, _ := u.User.Password()
		node := &ClashNode{
			Name:     u.Fragment + nameSuffix,
			Type:     "http",
			Server:   u.Hostname(),
			Port:     port,
			Username: u.User.Username(),
			Password: pass,
		}
		if strings.HasPrefix(lowerLink, "https") {
			node.TLS = true
			if skip := u.Query().Get("skip-cert-verify"); skip == "true" || skip == "1" {
				node.SkipCertVerify = true
			}
			if sni := u.Query().Get("sni"); sni != "" {
				node.SNI = sni
			}
		}
		return node
	}

	logLinkParseSkip("unsupported-protocol", link)
	return nil
}
