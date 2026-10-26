// Package wgrelay runs the supplied Songrong deployment engine in isolated jobs.
package wgrelay

import (
	"errors"
	"net/netip"
	"regexp"
	"strings"
)

type Request struct {
	Mode         string `json:"mode"`
	Architecture string `json:"architecture"`
	AIP          string `json:"a_ip"`
	BIP          string `json:"b_ip"`
	ASSH         int    `json:"a_ssh"`
	BSSH         int    `json:"b_ssh"`
	APort        int    `json:"a_port"`
	BPort        int    `json:"b_port"`
	AUsername    string `json:"a_username"`
	BUsername    string `json:"b_username"`
	APassword    string `json:"a_password,omitempty"`
	BPassword    string `json:"b_password,omitempty"`
	SNI          string `json:"sni"`
	MTU          int    `json:"mtu"`
}

var usernameRE = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}[$]?$`)
var domainRE = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$`)

func publicIPv4(s string) bool {
	ip, err := netip.ParseAddr(s)
	if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, block := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4"} {
		if netip.MustParsePrefix(block).Contains(ip) {
			return false
		}
	}
	return true
}
func (r *Request) Validate() error {
	r.AIP, r.BIP, r.SNI = strings.TrimSpace(r.AIP), strings.TrimSpace(r.BIP), strings.TrimSpace(r.SNI)
	if r.Mode != "check" && r.Mode != "deploy" {
		return errors.New("操作必须为检查或部署")
	}
	if r.Architecture != "realm" && r.Architecture != "vless_ss" {
		return errors.New("请选择有效的链路模式")
	}
	if !publicIPv4(r.AIP) || !publicIPv4(r.BIP) || r.AIP == r.BIP {
		return errors.New("请填写两台不同服务器的公网 IPv4")
	}
	for _, p := range []int{r.ASSH, r.BSSH, r.APort, r.BPort} {
		if p < 1 || p > 65535 {
			return errors.New("端口必须为 1–65535")
		}
	}
	if r.ASSH == r.APort || r.BSSH == r.BPort {
		return errors.New("业务端口不能与 SSH 端口相同")
	}
	if !usernameRE.MatchString(r.AUsername) || !usernameRE.MatchString(r.BUsername) {
		return errors.New("SSH 用户名格式不正确")
	}
	for _, p := range []string{r.APassword, r.BPassword} {
		if len(p) < 1 || len(p) > 512 {
			return errors.New("请填写两台服务器的 SSH 密码（最多 512 字节）")
		}
	}
	if len(r.SNI) > 253 || !domainRE.MatchString(r.SNI) {
		return errors.New("REALITY 请填写域名，不带协议或路径")
	}
	if r.MTU < 1280 || r.MTU > 1500 {
		return errors.New("MTU 必须为 1280–1500")
	}
	return nil
}
func (r Request) Public() Request { r.APassword = ""; r.BPassword = ""; return r }
