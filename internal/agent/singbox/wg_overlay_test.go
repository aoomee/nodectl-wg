package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func overlayConfig(t *testing.T) *ConfigManager {
	t.Helper()
	d := t.TempDir()
	cm := NewConfigManagerWithPaths(filepath.Join(d, "config.json"), filepath.Join(d, "protocols.json"), d)
	cm.Protocols.SetEnabled(ProtoReality, true)
	cm.Protocols.Reality = RealityConfig{Port: 443, UUID: "11111111-1111-4111-8111-111111111111", PrivateKey: "private-key", PublicKey: "public-key", SNI: "example.com", ShortID: "aabb"}
	cm.Protocols.SetEnabled(ProtoSS, true)
	cm.Protocols.SS = SSConfig{Port: 8388, Method: "aes-128-gcm", Password: " local secret \n"}
	cm.Protocols.SetEnabled(ProtoVlessWST, true)
	cm.Protocols.VlessTLS = VlessTLSGroupConfig{UUID: "other-uuid", WSTPort: 8443}
	return cm
}
func activeRoute() WGRoute {
	return WGRoute{PairID: "pair-1", Revision: 1, Mode: "active", Interface: "wg-test", Server: "10.9.0.2", Port: 8388, Method: "aes-128-gcm", Password: " remote secret \n", SourceDigest: "source"}
}
func generated(t *testing.T, cm *ConfigManager) map[string]json.RawMessage {
	t.Helper()
	data, err := cm.GenerateConfig()
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func assertBlocked(t *testing.T, cm *ConfigManager) {
	t.Helper()
	cfg := generated(t, cm)
	var route sbRoute
	if err := json.Unmarshal(cfg["route"], &route); err != nil {
		t.Fatal(err)
	}
	want := []sbRouteRule{{Inbound: []string{"vless-in"}, Action: "reject"}}
	if route.Final != "direct-out" || !reflect.DeepEqual(route.Rules, want) {
		t.Fatalf("not blocked: %+v", route)
	}
	if bytes.Contains(cfg["outbounds"], []byte("wg-ss-out")) {
		t.Fatal("blocked config contains WG outbound")
	}
}

func TestWGOverlayScopedAndPreservesCredentials(t *testing.T) {
	cm := overlayConfig(t)
	before := generated(t, cm)
	pc, _ := json.Marshal(cm.Protocols)
	if _, ok := before["route"]; ok {
		t.Fatal("legacy route changed")
	}
	guard := WGRoute{PairID: "pair-1", Revision: 1, Mode: "blocked"}
	if err := cm.SetWGRoute(guard); err != nil {
		t.Fatal(err)
	}
	assertBlocked(t, cm)
	r := activeRoute()
	if err := cm.SetWGRoute(r); err != nil {
		t.Fatal(err)
	}
	after := generated(t, cm)
	if !bytes.Equal(before["inbounds"], after["inbounds"]) {
		t.Fatal("inbounds mutated")
	}
	afterPC, _ := json.Marshal(cm.Protocols)
	if !bytes.Equal(pc, afterPC) {
		t.Fatal("protocol credentials mutated")
	}
	var route sbRoute
	json.Unmarshal(after["route"], &route)
	want := []sbRouteRule{{Inbound: []string{"vless-in"}, Network: "tcp", Action: "route", Outbound: "wg-ss-out"}, {Inbound: []string{"vless-in"}, Action: "reject"}}
	if route.Final != "direct-out" || !reflect.DeepEqual(route.Rules, want) {
		t.Fatalf("bad route: %+v", route)
	}
	var out []sbOutbound
	json.Unmarshal(after["outbounds"], &out)
	if len(out) != 2 || out[1].BindInterface != r.Interface || out[1].Network != "tcp" || out[1].Password != r.Password || out[1].Server != r.Server {
		t.Fatal("bad bound SS outbound")
	}
	r.Mode = "blocked"
	if err := cm.SetWGRoute(r); err != nil {
		t.Fatal(err)
	}
	assertBlocked(t, cm)
	r.Mode = "active"
	if err := cm.SetWGRoute(r); err != nil {
		t.Fatal(err)
	}
	r.Mode = "direct"
	if err := cm.SetWGRoute(r); err != nil {
		t.Fatal(err)
	}
	cfg := generated(t, cm)
	json.Unmarshal(cfg["route"], &route)
	var released sbRoute
	json.Unmarshal(cfg["route"], &released)
	if len(released.Rules) != 0 || released.Final != "direct-out" {
		t.Fatal("release is not direct")
	}
	if _, err := os.Stat(cm.configPath + ".wg-route.json"); err != nil {
		t.Fatal("missing tombstone")
	}
}

func TestWGOverlayRestartAndRealityMutationBlock(t *testing.T) {
	cm := overlayConfig(t)
	r := activeRoute()
	if err := cm.SetWGRoute(r); err != nil {
		t.Fatal(err)
	}
	restart := NewConfigManagerWithPaths(cm.configPath, cm.protocolsPath, cm.certDir)
	restart.Protocols = cm.Protocols
	assertBlocked(t, restart)
	cm.Protocols.Reality.UUID = "changed"
	assertBlocked(t, cm)
	if err := cm.SetWGRoute(r); err != nil {
		t.Fatal(err)
	}
	cm.Protocols.SetEnabled(ProtoReality, false)
	assertBlocked(t, cm)
	if err := cm.SetWGRoute(r); err == nil {
		t.Fatal("active allowed without REALITY")
	}
	empty := overlayConfig(t)
	empty.Protocols = DefaultProtocolConfig()
	if err := empty.SetWGRoute(WGRoute{PairID: "pair", Revision: 1, Mode: "blocked"}); err != nil {
		t.Fatal(err)
	}
	assertBlocked(t, empty)
}

func TestWGOverlayCASAndValidation(t *testing.T) {
	cm := overlayConfig(t)
	r := activeRoute()
	r.Revision = 2
	if err := cm.SetWGRoute(r); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*WGRoute){func(r *WGRoute) { r.Revision = 1 }, func(r *WGRoute) { r.PairID = "other" }, func(r *WGRoute) { r.Password = "changed" }, func(r *WGRoute) { r.Server = "8.8.8.8" }, func(r *WGRoute) { r.Interface = "wg/test" }, func(r *WGRoute) { r.Port = 0 }, func(r *WGRoute) { r.Mode = "invalid" }, func(r *WGRoute) { r.Method = "none" }} {
		bad := r
		mutate(&bad)
		if err := cm.SetWGRoute(bad); err == nil {
			t.Fatalf("accepted invalid route %+v", bad)
		}
	}
	r.Mode = "direct"
	if err := cm.SetWGRoute(r); err != nil {
		t.Fatal(err)
	}
	r.Mode = "active"
	if err := cm.SetWGRoute(r); err == nil {
		t.Fatal("reactivated tombstone")
	}
	r.Mode = "blocked"
	if err := cm.SetWGRoute(r); err == nil {
		t.Fatal("same revision replaced tombstone")
	}
	r.Revision++
	if err := cm.SetWGRoute(r); err != nil {
		t.Fatal(err)
	}
}

func TestWGOverlayMalformedAndDeletedFailClosed(t *testing.T) {
	for _, data := range []string{"{", "null", "{}", `{"pair_id":"p","revision":1,"mode":"blocked","unexpected":true}`, `{"pair_id":"p","revision":1,"mode":"blocked"} {}`} {
		t.Run(data, func(t *testing.T) {
			cm := overlayConfig(t)
			os.WriteFile(cm.configPath+".wg-route.json", []byte(data), 0600)
			if _, err := cm.GenerateConfig(); err == nil {
				t.Fatal("malformed overlay generated direct")
			}
		})
	}
	cm := overlayConfig(t)
	if err := cm.SetWGRoute(activeRoute()); err != nil {
		t.Fatal(err)
	}
	os.Remove(cm.configPath + ".wg-route.json")
	if _, err := cm.GenerateConfig(); err == nil {
		t.Fatal("deleted guard generated direct")
	}
}

func TestWGPrivateFilesAndCanonicalDigests(t *testing.T) {
	cm := overlayConfig(t)
	r := activeRoute()
	if err := cm.SetWGRoute(r); err != nil {
		t.Fatal(err)
	}
	if err := cm.GenerateAndSave(); err != nil {
		t.Fatal(err)
	}
	if err := cm.SaveToCache(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{cm.configPath, cm.protocolsPath, cm.configPath + ".wg-route.json"} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0600 {
			t.Fatalf("insecure mode: %s %v", p, st.Mode())
		}
	}
	c, d, err := cm.SSConfigCredentials()
	if err != nil || c != cm.Protocols.SS || len(d) != 64 {
		t.Fatal("canonical credentials differ")
	}
	cm.Protocols.SS.Password += "x"
	_, d2, _ := cm.SSConfigCredentials()
	if d == d2 {
		t.Fatal("password missing from digest")
	}
	cm.Protocols.SetEnabled(ProtoSS, false)
	if _, _, err := cm.SSConfigCredentials(); err == nil {
		t.Fatal("disabled SS credentials returned")
	}
	before := cm.RealityConfigDigest()
	cm.Protocols.Reality.PrivateKey += "x"
	if before == cm.RealityConfigDigest() {
		t.Fatal("key missing from digest")
	}
	before = cm.RealityConfigDigest()
	cm.Protocols.SetEnabled(ProtoReality, false)
	if before == cm.RealityConfigDigest() {
		t.Fatal("enabled missing from digest")
	}
}

// The test executable doubles as the installed binary; no downloads, shell
// scripts, root privileges, network listeners or installed sing-box are needed.
func TestMain(m *testing.M) {
	if os.Getenv("NC_WG_FAKE_BINARY") == "1" && len(os.Args) > 1 && (os.Args[1] == "check" || os.Args[1] == "run") {
		data, err := os.ReadFile(os.Args[3])
		if err != nil {
			os.Exit(2)
		}
		active := bytes.Contains(data, []byte(`"wg-ss-out"`))
		direct := !bytes.Contains(data, []byte(`"reject"`))
		f, _ := os.OpenFile(os.Getenv("NC_WG_TRACE"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if f != nil {
			fmt.Fprintf(f, "%s active=%v direct=%v\n", os.Args[1], active, direct)
			f.Close()
		}
		if os.Args[1] == "check" {
			if os.Getenv("NC_WG_FAIL_CHECK") == "all" || (active && os.Getenv("NC_WG_FAIL_CHECK") == "active") {
				os.Exit(3)
			}
			os.Exit(0)
		}
		if active && os.Getenv("NC_WG_FAIL_RUN") == "active" {
			os.Exit(4)
		}
		for {
			time.Sleep(time.Second)
		}
	}
	os.Exit(m.Run())
}
func fakeManager(t *testing.T) *Manager {
	t.Helper()
	cm := overlayConfig(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	m := NewManagerWithConfig(cm, NewInstaller(exe))
	m.logPath = filepath.Join(t.TempDir(), "log")
	m.pidPath = filepath.Join(t.TempDir(), "pid")
	m.maxRestarts = 0
	t.Setenv("NC_WG_FAKE_BINARY", "1")
	t.Setenv("NC_WG_TRACE", filepath.Join(t.TempDir(), "trace"))
	t.Cleanup(func() { m.Stop() })
	return m
}
func TestWGApplyDurableAndFence(t *testing.T) {
	m := fakeManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	if err := m.ApplyWGRoute(ctx, activeRoute()); err != nil {
		t.Fatal(err)
	}
	cancel()
	time.Sleep(50 * time.Millisecond)
	if !m.IsRunning() {
		t.Fatal("short command context killed process")
	}
	if err := m.FenceWGRoute(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertBlocked(t, m.config)
	if !m.IsRunning() {
		t.Fatal("reject process did not start")
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if m.IsRunning() {
		t.Fatal("Stop restarted owned process")
	}
}
func TestWGApplyFailuresNeverRestoreDirect(t *testing.T) {
	for _, failure := range []string{"active-check", "active-run", "all-check"} {
		t.Run(failure, func(t *testing.T) {
			m := fakeManager(t)
			switch failure {
			case "active-check":
				t.Setenv("NC_WG_FAIL_CHECK", "active")
			case "active-run":
				t.Setenv("NC_WG_FAIL_RUN", "active")
			case "all-check":
				t.Setenv("NC_WG_FAIL_CHECK", "all")
			}
			if err := m.ApplyWGRoute(context.Background(), activeRoute()); err == nil {
				t.Fatal("expected apply error")
			}
			assertBlocked(t, m.config)
			data, err := os.ReadFile(m.configPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(data, []byte(`"reject"`)) {
				t.Fatal("disk config not blocked")
			}
			if failure == "all-check" && m.IsRunning() {
				t.Fatal("process running after reject check failed")
			}
			trace, _ := os.ReadFile(os.Getenv("NC_WG_TRACE"))
			if strings.Contains(string(trace), "run active=false direct=true") {
				t.Fatal("restored direct process")
			}
		})
	}
}
func TestWGStartRewritesStoredActiveAfterRestart(t *testing.T) {
	m := fakeManager(t)
	if err := m.config.SetWGRoute(activeRoute()); err != nil {
		t.Fatal(err)
	}
	if err := m.config.GenerateAndSave(); err != nil {
		t.Fatal(err)
	}
	old := m.config
	m.config = NewConfigManagerWithPaths(old.configPath, old.protocolsPath, old.certDir)
	m.config.Protocols = old.Protocols
	if err := m.StartAndVerify(context.Background(), 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(m.configPath)
	if !bytes.Contains(data, []byte(`"reject"`)) || bytes.Contains(data, []byte(`"wg-ss-out"`)) {
		t.Fatal("restart reused active config")
	}
}
