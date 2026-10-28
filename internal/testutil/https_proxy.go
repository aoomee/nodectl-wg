// Package testutil contains local-only HTTP fixtures for transport integration tests.
package testutil

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// HTTPSProxy terminates TLS and forwards plain HTTP, preserving Host and the
// WebSocket upgrade. nginx mode uses a real local process and an ephemeral CA.
// CI sets NODECTL_TEST_NGINX to require nginx; local runs may skip that variant.
func HTTPSProxy(t *testing.T, upstream, kind string) (string, *http.Client) {
	t.Helper()
	if kind == "nginx" && os.Getenv("NODECTL_TEST_NGINX") == "" {
		t.Skip("set NODECTL_TEST_NGINX to run the real NGINX transport test")
	}
	target, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(target)
		pr.Out.Host = pr.In.Host
		pr.SetXForwarded()
		host, _, _ := net.SplitHostPort(pr.In.RemoteAddr)
		pr.Out.Header.Set("X-Real-IP", host)
	}}
	tlsServer := httptest.NewTLSServer(proxy)
	client := tlsServer.Client()
	client.Timeout = 5 * time.Second
	if kind == "go" {
		t.Cleanup(tlsServer.Close)
		return tlsServer.URL, client
	}
	dir := t.TempDir()
	cert := tlsServer.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, block := range map[string]*pem.Block{
		"cert.pem": {Type: "CERTIFICATE", Bytes: cert.Certificate[0]},
		"key.pem":  {Type: "PRIVATE KEY", Bytes: key},
	} {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
	listen := tlsServer.Listener.Addr().String()
	external := tlsServer.URL
	tlsServer.Close()
	config := fmt.Sprintf(`daemon off;
master_process off;
pid "%s/nginx.pid";
error_log stderr warn;
events { worker_connections 128; }
http {
    access_log off;
    client_body_temp_path "%s/body";
    proxy_temp_path "%s/proxy";
    server {
        listen %s ssl;
        ssl_certificate "%s/cert.pem";
        ssl_certificate_key "%s/key.pem";
        location / {
            proxy_pass %s;
            proxy_http_version 1.1;
            proxy_set_header Host $http_host;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_buffering off;
        }
    }
}
`, dir, dir, dir, listen, dir, dir, upstream)
	confPath := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(confPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Getenv("NODECTL_TEST_NGINX"), "-p", dir+string(os.PathSeparator), "-c", confPath)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = cmd.Process.Kill()
			<-done
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			stopped = true
			t.Fatalf("nginx exited: %v: %s", err, output.String())
		default:
		}
		conn, err := net.DialTimeout("tcp", strings.TrimPrefix(external, "https://"), 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return external, client
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("nginx did not start")
	return "", nil
}
