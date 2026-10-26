package singbox

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Opt in with a pinned sing-box executable; checks real schema, not a fake checker.
func TestWGConfigPinnedBinary(t *testing.T) {
	binary := os.Getenv("NODECTL_TEST_SINGBOX")
	if binary == "" {
		t.Skip("set NODECTL_TEST_SINGBOX to pinned sing-box 1.13.2")
	}
	dir := t.TempDir()
	cm := NewConfigManagerWithPaths(filepath.Join(dir, "config.json"), filepath.Join(dir, "protocols.json"), dir)
	for _, proto := range AllProtocols {
		cm.Protocols.SetEnabled(proto, false)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cm.Protocols.SetEnabled(ProtoReality, true)
	cm.Protocols.Reality = RealityConfig{Port: 24443, UUID: "11111111-1111-4111-8111-111111111111", PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), SNI: "example.com", ShortID: "0123456789abcdef"}
	r := WGRoute{PairID: "0123456789abcdef", Revision: 1, Mode: "blocked"}
	for _, mode := range []string{"blocked", "active", "direct"} {
		r.Mode = mode
		if mode == "active" {
			r.Interface = "wg-test"
			r.Server = "10.9.0.2"
			r.Port = 8388
			r.Method = "2022-blake3-aes-128-gcm"
			r.Password = base64.StdEncoding.EncodeToString(make([]byte, 16))
			r.SourceDigest = cm.RealityConfigDigest()
		}
		if err = cm.SetWGRoute(r); err != nil {
			t.Fatal(err)
		}
		if err = cm.GenerateAndSave(); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		out, e := exec.CommandContext(ctx, binary, "check", "-c", cm.GetConfigPath()).CombinedOutput()
		cancel()
		if e != nil {
			t.Fatalf("%s real binary check failed: %v\n%s", mode, e, out)
		}
	}
}
