// 路径: internal/agent/api/report.go
// 公网 IP 检测工具函数
package api

import (
	"io"
	"net/http"
	"strings"
	"time"
)

// GetPublicIP 获取节点公网 IPv4 地址
func GetPublicIP() string {
	urls := []string{
		"https://api.ipify.org",
		"https://ipinfo.io/ip",
		"https://ifconfig.me",
	}

	client := &http.Client{Timeout: 5 * time.Second}

	for _, u := range urls {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		ip := strings.TrimSpace(string(body))
		if ip != "" {
			return ip
		}
	}

	return ""
}

// GetPublicIPv6 获取节点公网 IPv6 地址
// 使用仅支持 IPv6 的 API 端点，若节点无 IPv6 连通性则返回空字符串
func GetPublicIPv6() string {
	urls := []string{
		"https://api6.ipify.org",
		"https://v6.ident.me",
		"https://ifconfig.co",
	}

	client := &http.Client{Timeout: 5 * time.Second}

	for _, u := range urls {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		ip := strings.TrimSpace(string(body))
		// 去除可能存在的方括号（某些 API 可能返回 [::1] 格式）
		ip = strings.Trim(ip, "[]")
		// 简单校验是否包含冒号（IPv6 地址特征）且长度合理（标准 IPv6 最长 45 字符含 zone id）
		if ip != "" && strings.Contains(ip, ":") && len(ip) <= 45 {
			return ip
		}
	}

	return ""
}
