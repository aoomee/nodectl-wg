package singbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewConfigManagerWithPathsColocatesProtocolsAndCerts(t *testing.T) {
	legacyDir := filepath.Join(t.TempDir(), "nodectl-agent")
	cfgPath := filepath.Join(legacyDir, "singbox-config.json")

	cm := NewConfigManagerWithPaths(cfgPath, "", "")
	if cm.GetConfigPath() != cfgPath {
		t.Fatalf("unexpected configPath: %s", cm.GetConfigPath())
	}
	wantProtocols := filepath.Join(legacyDir, "protocols.json")
	if cm.protocolsPath != wantProtocols {
		t.Fatalf("protocolsPath must colocate with configPath: got %q want %q", cm.protocolsPath, wantProtocols)
	}
	wantCertDir := filepath.Join(legacyDir, "certs")
	if cm.certDir != wantCertDir {
		t.Fatalf("certDir must colocate with configPath: got %q want %q", cm.certDir, wantCertDir)
	}
}

func TestResolveWorkDirInPrefersCompleteNewDirAndHealsHalfMigration(t *testing.T) {
	root := t.TempDir()
	newDir := filepath.Join(root, "wirearc-agent")
	oldDir := filepath.Join(root, "nodectl-agent")

	// 1. Fresh install: neither exists -> default new dir.
	if got := resolveWorkDirIn(newDir, oldDir); got != newDir {
		t.Fatalf("fresh install: got %q want %q", got, newDir)
	}

	// 2. Legacy node with protocols.json + sing-box, AND a half-created newDir containing only protocols.json (v1.1.10 bug).
	if err := os.MkdirAll(oldDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(newDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldDir, "protocols.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldDir, "sing-box"), []byte("bin"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newDir, "protocols.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := resolveWorkDirIn(newDir, oldDir); got != oldDir {
		t.Fatalf("half-migrated node must heal back to legacy dir: got %q want %q", got, oldDir)
	}

	// 3. Fully migrated/fresh newDir containing sing-box -> prefers newDir.
	if err := os.WriteFile(filepath.Join(newDir, "sing-box"), []byte("bin"), 0755); err != nil {
		t.Fatal(err)
	}
	if got := resolveWorkDirIn(newDir, oldDir); got != newDir {
		t.Fatalf("complete new dir must be selected: got %q want %q", got, newDir)
	}
}
