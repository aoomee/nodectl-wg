// 路径: internal/agent/singbox/cert.go
// 自签证书生成（纯 Go 实现，替代 openssl 命令行）
package singbox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// GenerateSelfSignedCert 生成自签名证书（替代 openssl 命令）
// 使用 ECDSA P-256 算法（更短的密钥、更快的握手），有效期 10 年。
// certPath: 证书输出路径（PEM 格式）
// keyPath:  私钥输出路径（PEM 格式，权限 0600）
// commonName: 证书 CN 字段（一般填域名或 IP）
func GenerateSelfSignedCert(certPath, keyPath, commonName string) error {
	// 1. 生成 ECDSA P-256 私钥
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("生成 ECDSA 私钥失败: %w", err)
	}

	// 2. 生成随机序列号
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("生成证书序列号失败: %w", err)
	}

	// 3. 创建证书模板
	notBefore := time.Now()
	notAfter := notBefore.AddDate(10, 0, 0) // 10 年有效期

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"WireArc"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// 如果 commonName 是 IP，添加到 IPAddresses；否则添加到 DNSNames
	if ip := net.ParseIP(commonName); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, commonName)
	}

	// 4. 自签名（issuer == subject）
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("创建证书失败: %w", err)
	}

	// 5. 确保输出目录存在
	if dir := filepath.Dir(certPath); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建证书目录失败: %w", err)
		}
	}
	if dir := filepath.Dir(keyPath); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建私钥目录失败: %w", err)
		}
	}

	// 6. 写入证书文件
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("创建证书文件失败: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("写入证书 PEM 失败: %w", err)
	}

	// 7. 写入私钥文件（权限 0600，仅 root 可读）
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("序列化私钥失败: %w", err)
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("创建私钥文件失败: %w", err)
	}
	defer keyOut.Close()

	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return fmt.Errorf("写入私钥 PEM 失败: %w", err)
	}

	return nil
}

// CertExists 检查证书和私钥文件是否都存在
func CertExists(certPath, keyPath string) bool {
	_, errCert := os.Stat(certPath)
	_, errKey := os.Stat(keyPath)
	return errCert == nil && errKey == nil
}

// EnsureCert 确保证书存在，若不存在则自动生成
func EnsureCert(certPath, keyPath, commonName string) error {
	if CertExists(certPath, keyPath) {
		return nil
	}
	return GenerateSelfSignedCert(certPath, keyPath, commonName)
}
