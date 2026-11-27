package agent

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"nodectl/internal/agent/singbox"
)

func TestShouldSkipBackgroundUpdateForWGRoutes(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfgMgr := singbox.NewConfigManagerWithPaths(cfgPath, "", "")
	cfgMgr.Protocols.SetEnabled(singbox.ProtoReality, true)
	cfgMgr.Protocols.Reality = singbox.RealityConfig{
		Port:       24443,
		UUID:       "11111111-1111-4111-8111-111111111111",
		PrivateKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		PublicKey:  base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		SNI:        "example.com",
		ShortID:    "0123456789abcdef",
	}
	rt := &Runtime{
		singboxMgr: singbox.NewManagerWithConfig(cfgMgr, singbox.NewInstaller(filepath.Join(dir, "sing-box"))),
	}

	// 1. 无 WG 路由状态时，允许后台自动更新
	if rt.shouldSkipBackgroundUpdate() {
		t.Fatal("expected background update to be allowed when no WG route exists")
	}

	// 2. blocked 状态（配对建链/保护态）必须跳过后台自动更新
	if err := cfgMgr.SetWGRoute(singbox.WGRoute{
		PairID:   "0123456789abcdef",
		Revision: 1,
		Mode:     "blocked",
	}); err != nil {
		t.Fatalf("SetWGRoute(blocked) failed: %v", err)
	}
	if !rt.shouldSkipBackgroundUpdate() {
		t.Fatal("expected background update to be skipped while WG route is blocked")
	}

	// 3. active 状态（活跃转发态）必须跳过后台自动更新，防止原地重启触发 fail-closed 断网
	if err := cfgMgr.SetWGRoute(singbox.WGRoute{
		PairID:       "0123456789abcdef",
		Revision:     1,
		Mode:         "active",
		Interface:    "wg-relay",
		Server:       "10.10.0.2",
		Port:         4433,
		Method:       "2022-blake3-aes-128-gcm",
		Password:     base64.StdEncoding.EncodeToString(make([]byte, 16)),
		SourceDigest: cfgMgr.RealityConfigDigest(),
	}); err != nil {
		t.Fatalf("SetWGRoute(active) failed: %v", err)
	}
	if !rt.shouldSkipBackgroundUpdate() {
		t.Fatal("expected background update to be skipped while WG route is active")
	}

	// 4. direct tombstone（已解除配对）恢复允许后台自动更新
	if err := cfgMgr.SetWGRoute(singbox.WGRoute{
		PairID:   "0123456789abcdef",
		Revision: 1,
		Mode:     "direct",
	}); err != nil {
		t.Fatalf("SetWGRoute(direct) failed: %v", err)
	}
	if rt.shouldSkipBackgroundUpdate() {
		t.Fatal("expected background update to be allowed after WG route returns to direct")
	}

	// 5. 状态文件损坏时采取保守策略：跳过后台静默重启，保留排障现场
	routeFile := cfgPath + ".wg-route.json"
	if err := os.WriteFile(routeFile, []byte("{corrupted"), 0o600); err != nil {
		t.Fatalf("write corrupted wg-route.json failed: %v", err)
	}
	if !rt.shouldSkipBackgroundUpdate() {
		t.Fatal("expected background update to be skipped when WG route state is corrupted")
	}
}
