package service

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"nodectl/internal/database"
	"nodectl/internal/logger"
	"nodectl/internal/requestmeta"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

var (
	CertDir     = filepath.Join("data", "cert")
	CertFile    = filepath.Join(CertDir, "server.crt")
	KeyFile     = filepath.Join(CertDir, "server.key")
	certMutex   sync.RWMutex
	currentCert *tls.Certificate
)

func isCertEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(getCFConfig("cf_cert_enabled")))
	return v == "true" || v == "1"
}

// CertInfo 这里的结构体用于返回给前端展示
type CertInfo struct {
	Domain string `json:"domain"`
	Expire string `json:"expire"`
	Issuer string `json:"issuer"`
	Valid  bool   `json:"valid"`
}

// ------------------- [基础证书管理功能] -------------------

// InitCertManager 初始化证书目录，并启动后台续期任务
func InitCertManager() {
	if err := os.MkdirAll(CertDir, 0755); err != nil {
		logger.Log.Error("无法创建证书目录", "error", err)
	}

	// 启动 Cloudflare 证书自动续期后台守护线程
	startAutoRenewalTask()
}

// GetCertificate 用于 http.Server 的 TLSConfig.GetCertificate 回调 (实现热加载核心)
func GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	certMutex.RLock()
	defer certMutex.RUnlock()
	return currentCert, nil
}

// LoadCertificate 从磁盘加载证书到内存
func LoadCertificate() error {
	certMutex.Lock()
	defer certMutex.Unlock()

	if !isCertEnabled() {
		currentCert = nil
		return fmt.Errorf("证书未启用")
	}

	if _, err := os.Stat(CertFile); os.IsNotExist(err) {
		return fmt.Errorf("证书文件不存在")
	}

	pair, err := tls.LoadX509KeyPair(CertFile, KeyFile)
	if err != nil {
		return err
	}
	currentCert = &pair
	return nil
}

// SaveCertificatePair 保存证书并进行热加载校验
func SaveCertificatePair(certContent, keyContent []byte) error {
	certMutex.Lock()
	defer certMutex.Unlock()

	// 备份旧证书
	os.Rename(CertFile, CertFile+".bak")
	os.Rename(KeyFile, KeyFile+".bak")

	if err := os.WriteFile(CertFile, certContent, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(KeyFile, keyContent, 0600); err != nil {
		return err
	}

	// 尝试加载新证书进行校验
	pair, err := tls.LoadX509KeyPair(CertFile, KeyFile)
	if err != nil {
		// 校验失败，回滚
		os.Rename(CertFile+".bak", CertFile)
		os.Rename(KeyFile+".bak", KeyFile)
		return fmt.Errorf("证书格式错误或密钥不匹配，已回滚: %v", err)
	}

	currentCert = &pair
	return nil
}

// GetCurrentCertInfo 解析当前加载的证书信息，供前端展示
func GetCurrentCertInfo() CertInfo {
	certMutex.RLock()
	defer certMutex.RUnlock()

	info := CertInfo{Valid: false, Domain: "--", Expire: "--", Issuer: "--"}

	if currentCert != nil && len(currentCert.Certificate) > 0 {
		x509Cert, err := x509.ParseCertificate(currentCert.Certificate[0])
		if err == nil {
			return buildCertInfoFromX509(x509Cert)
		}
	}

	// 回退：即使当前未启用 HTTPS（内存未加载），也尝试从本地证书文件读取展示信息
	crtBytes, err := os.ReadFile(CertFile)
	if err != nil {
		return info
	}

	block, _ := pem.Decode(crtBytes)
	if block == nil {
		return info
	}

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return info
	}

	return buildCertInfoFromX509(x509Cert)
}

func buildCertInfoFromX509(x509Cert *x509.Certificate) CertInfo {
	info := CertInfo{Valid: true, Domain: "--", Expire: "--", Issuer: "--"}
	info.Valid = true
	if len(x509Cert.DNSNames) > 0 {
		info.Domain = x509Cert.DNSNames[0]
	} else {
		info.Domain = x509Cert.Subject.CommonName
	}
	info.Expire = x509Cert.NotAfter.Format("2006-01-02 15:04:05")
	info.Issuer = x509Cert.Issuer.CommonName

	if time.Now().After(x509Cert.NotAfter) {
		info.Expire += " (已过期)"
		info.Valid = false
	}

	return info
}

// CheckRequestSecure 检查请求是否安全 (HTTPS)
func CheckRequestSecure(r *http.Request) bool {
	return requestmeta.IsSecure(r)
}

// HasValidLocalCertificate 检查本地证书文件是否存在且有效（未过期）
func HasValidLocalCertificate() bool {
	if _, err := os.Stat(CertFile); err != nil {
		return false
	}
	if _, err := os.Stat(KeyFile); err != nil {
		return false
	}

	pair, err := tls.LoadX509KeyPair(CertFile, KeyFile)
	if err != nil || len(pair.Certificate) == 0 {
		return false
	}

	x509Cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false
	}

	return time.Now().Before(x509Cert.NotAfter)
}

// acmeUser 结构体实现 lego.registration.User 接口
type acmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.Email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// startAutoRenewalTask 启动后台静默定时续期任务
func startAutoRenewalTask() {
	go func() {
		for {
			// 每天检查一次
			time.Sleep(24 * time.Hour)
			checkAndRenewCert()
		}
	}()
}

// checkAndRenewCert 检查证书有效期，并在不足 7 天时触发自动续期
func checkAndRenewCert() {
	certMutex.RLock()
	if currentCert == nil || len(currentCert.Certificate) == 0 {
		certMutex.RUnlock()
		return
	}
	x509Cert, err := x509.ParseCertificate(currentCert.Certificate[0])
	certMutex.RUnlock()
	if err != nil {
		return
	}

	daysLeft := time.Until(x509Cert.NotAfter).Hours() / 24
	if daysLeft > 7 {
		return
	}

	logger.Log.Info("SSL 证书剩余有效期不足 7 天，准备触发续期检查...", "days_left", int(daysLeft))

	var autoRenew database.SysConfig
	database.DB.Where("key = ?", "cf_auto_renew").First(&autoRenew)
	if autoRenew.Value == "false" {
		logger.Log.Info("用户已在面板关闭了自动续期，跳过此次操作。")
		return
	}

	var email, apiKey, domain database.SysConfig
	database.DB.Where("key = ?", "cf_email").First(&email)
	database.DB.Where("key = ?", "cf_api_key").First(&apiKey)
	database.DB.Where("key = ?", "cf_domain").First(&domain)

	if email.Value == "" || apiKey.Value == "" || domain.Value == "" {
		logger.Log.Warn("证书自动续期失败: 缺少 Cloudflare 配置信息，请在 Cloudflare 面板中补全")
		return
	}

	if err := ApplyCloudflareCert(email.Value, apiKey.Value, domain.Value); err != nil {
		logger.Log.Error("证书自动续期失败", "error", err)
	} else {
		logger.Log.Info("🎉 证书自动续期成功！新证书已无感热加载生效。")
	}
}

var (
	certLogBuffer []string
	certLogMutex  sync.Mutex
)

func ClearCertLogs() {
	certLogMutex.Lock()
	certLogBuffer = []string{}
	certLogMutex.Unlock()
}

func AddCertLog(msg string) {
	certLogMutex.Lock()
	certLogBuffer = append(certLogBuffer, time.Now().Format("2006/01/02 15:04:05")+" "+msg)
	certLogMutex.Unlock()
}

func GetCertLogs() []string {
	certLogMutex.Lock()
	defer certLogMutex.Unlock()
	return append([]string(nil), certLogBuffer...)
}

type legoLogWriter struct{}

func (w *legoLogWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))
	for strings.HasPrefix(msg, "[INFO]") || strings.HasPrefix(msg, "[DEBUG]") {
		msg = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(msg, "[INFO]"), "[DEBUG]"))
	}
	msg = strings.Replace(msg, "Obtaining bundled SAN certificate", "正在获取 SAN 证书捆绑包", 1)
	msg = strings.Replace(msg, "Could not find solver for", "跳过不支持的验证方式:", 1)
	msg = strings.Replace(msg, "use dns-01 solver", "采用 dns-01 验证方式", 1)
	msg = strings.Replace(msg, "Preparing to solve DNS-01", "准备执行 DNS-01 验证", 1)
	msg = strings.Replace(msg, "Trying to solve DNS-01", "尝试下发 TXT 记录解决 DNS-01 验证", 1)
	msg = strings.Replace(msg, "Registering account for", "正在注册账号:", 1)
	msg = strings.Replace(msg, "AuthURL:", "授权地址:", 1)
	msg = strings.Replace(msg, "Checking DNS record propagation", "正在检查 DNS 记录是否生效", 1)
	msg = strings.Replace(msg, "Wait for propagation", "等待 DNS 传播", 1)
	msg = strings.Replace(msg, "Waiting for DNS record propagation.", "等待 DNS 记录传播...", 1)
	msg = strings.Replace(msg, "The server validated our request", "CA 服务器已成功验证我们的请求", 1)
	msg = strings.Replace(msg, "Cleaning DNS-01 challenge", "正在清理 DNS-01 验证产生的 TXT 记录", 1)
	msg = strings.Replace(msg, "Validations succeeded; requesting certificates", "所有验证成功！正在请求签发证书...", 1)
	msg = strings.Replace(msg, "Server responded with a certificate", "CA 服务器已响应并下发证书", 1)
	msg = strings.Replace(msg, "cloudflare: new record for", "Cloudflare: 成功添加 TXT 记录用于", 1)
	msg = strings.Replace(msg, "acme:", "acme:", 1)
	AddCertLog("[INFO] " + msg)
	return len(p), nil
}

// ApplyCloudflareCert 使用 Cloudflare DNS 验证申请 Let's Encrypt 证书
func ApplyCloudflareCert(email, apiKey, domain string) error {
	ClearCertLogs()
	AddCertLog(fmt.Sprintf("开始申请证书，域名 [%s] 申请方式 [DNS 自动] 通信邮箱 [%s] 厂商 [CloudFlare]", domain, email))
	legolog.Logger = log.New(&legoLogWriter{}, "", 0)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		AddCertLog("[ERROR] 生成账号私钥失败: " + err.Error())
		return fmt.Errorf("生成账号私钥失败: %v", err)
	}

	myUser := acmeUser{Email: email, key: privateKey}
	config := lego.NewConfig(&myUser)
	config.CADirURL = lego.LEDirectoryProduction
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		AddCertLog("[ERROR] 初始化 ACME 客户端失败: " + err.Error())
		return fmt.Errorf("初始化 ACME 客户端失败: %v", err)
	}

	cfConfig := cloudflare.NewDefaultConfig()
	cfConfig.AuthToken = apiKey
	cfConfig.PropagationTimeout = 2 * time.Minute
	cfProvider, err := cloudflare.NewDNSProviderConfig(cfConfig)
	if err != nil {
		AddCertLog("[ERROR] 配置 CF API 失败 (请检查Token权限): " + err.Error())
		return fmt.Errorf("配置 CF API 失败: %v", err)
	}

	if err = client.Challenge.SetDNS01Provider(cfProvider); err != nil {
		return fmt.Errorf("设置 DNS Provider 失败: %v", err)
	}

	AddCertLog("[INFO] 正在向 Let's Encrypt 注册 ACME 账号...")
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		AddCertLog("[ERROR] ACME 账号注册失败: " + err.Error())
		return fmt.Errorf("ACME 账号注册失败: %v", err)
	}
	myUser.Registration = reg

	AddCertLog("[INFO] 账号注册成功，即将开始 DNS 验证流程...")
	request := certificate.ObtainRequest{Domains: []string{domain}, Bundle: true}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		AddCertLog("[ERROR] 证书获取失败: " + err.Error())
		return fmt.Errorf("证书获取失败: %v", err)
	}

	AddCertLog("[INFO] 正在将新证书写入系统并热加载...")
	if err := SaveCertificatePair(certificates.Certificate, certificates.PrivateKey); err != nil {
		AddCertLog("[ERROR] 新证书应用失败: " + err.Error())
		return fmt.Errorf("新证书应用失败: %v", err)
	}

	AddCertLog(fmt.Sprintf("申请 [%s] 证书成功！！", domain))
	return nil
}
