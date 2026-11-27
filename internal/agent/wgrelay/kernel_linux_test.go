//go:build linux

package wgrelay

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRealLinuxKernelWireGuard(t *testing.T) {
	if os.Getenv("WIREARC_TEST_KERNEL_WG") != "1" {
		t.Skip("set WIREARC_TEST_KERNEL_WG=1 inside isolated Linux netns")
	}
	if err := exec.Command("ip", "link", "set", "lo", "up").Run(); err != nil {
		t.Fatalf("bring up lo: %v", err)
	}
	ctx := context.Background()

	// 1. Full prepare -> owned check against real iproute2 JSON -> configure (x2) -> remove.
	dir1 := filepath.Join(t.TempDir(), "wg-state-1")
	m1, err := New(dir1)
	if err != nil {
		t.Fatalf("New manager: %v", err)
	}
	defer m1.Close()

	p := Payload{
		Topology:     "reality_ss_v2",
		PairID:       "0123456789abcdef",
		Revision:     1,
		Role:         "entry",
		LocalAddress: "10.88.10.2/32",
		PeerAddress:  "10.88.10.3/32",
		ListenPort:   31820,
		EntryPort:    20000,
		TargetPort:   20001,
	}
	if _, err := m1.Execute(ctx, "wg-prepare", payload(p)); err != nil {
		t.Fatalf("wg-prepare failed on real kernel: %v", err)
	}
	rec := m1.records[p.PairID]
	owned, err := m1.owned(ctx, rec)
	if err != nil || !owned {
		t.Fatalf("real iproute2 JSON alias check failed: owned=%v err=%v", owned, err)
	}

	peerKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p.PeerPublicKey = base64.StdEncoding.EncodeToString(peerKey.PublicKey().Bytes())
	p.PeerEndpoint = "203.0.113.2"
	p.PeerPort = 41820

	if _, err := m1.Execute(ctx, "wg-configure", payload(p)); err != nil {
		t.Fatalf("first wg-configure failed: %v", err)
	}
	if _, err := m1.Execute(ctx, "wg-configure", payload(p)); err != nil {
		t.Fatalf("idempotent wg-configure failed: %v", err)
	}
	if _, err := m1.Execute(ctx, "wg-remove", payload(Payload{PairID: p.PairID, Revision: 2})); err != nil {
		t.Fatalf("wg-remove failed: %v", err)
	}
	if err := exec.Command("ip", "link", "show", "dev", rec.Interface).Run(); err == nil {
		t.Fatalf("expected interface %s to be deleted after wg-remove", rec.Interface)
	}
	_ = m1.Close()

	// 2. Self-heal regression: reproduce v1.1.1 unaliased kernel interface + persisted state.
	dir2 := filepath.Join(t.TempDir(), "wg-state-2")
	m2, err := New(dir2)
	if err != nil {
		t.Fatalf("New manager 2: %v", err)
	}
	p2 := p
	p2.PairID = "fedcba9876543210"
	p2.Revision = 1
	p2.ListenPort = 31821
	if _, err := m2.Execute(ctx, "wg-prepare", payload(p2)); err != nil {
		t.Fatalf("wg-prepare 2: %v", err)
	}
	iface2 := m2.records[p2.PairID].Interface
	_ = m2.Close()

	// Replace with an unaliased WireGuard link (exact state left by v1.1.1).
	if err := exec.Command("ip", "link", "delete", "dev", iface2).Run(); err != nil {
		t.Fatalf("delete aliased link: %v", err)
	}
	if err := exec.Command("ip", "link", "add", "name", iface2, "type", "wireguard").Run(); err != nil {
		t.Fatalf("recreate unaliased link: %v", err)
	}

	m2Reopen, err := New(dir2)
	if err != nil {
		t.Fatalf("reopen with unaliased v1.1.1 interface failed: %v", err)
	}
	defer m2Reopen.Close()
	if _, err := m2Reopen.Execute(ctx, "wg-remove", payload(Payload{PairID: p2.PairID, Revision: 2})); err != nil {
		t.Fatalf("wg-remove on unaliased v1.1.1 interface failed: %v", err)
	}
	if err := exec.Command("ip", "link", "show", "dev", iface2).Run(); err == nil {
		t.Fatalf("expected unaliased interface %s to be deleted", iface2)
	}

	// 3. Foreign interface without state record must still be refused with ErrNotOwned.
	dir3 := filepath.Join(t.TempDir(), "wg-state-3")
	m3, err := New(dir3)
	if err != nil {
		t.Fatalf("New manager 3: %v", err)
	}
	defer m3.Close()
	foreignPair := "1122334455667788"
	foreignIface := interfaceName(foreignPair)
	if err := exec.Command("ip", "link", "add", "name", foreignIface, "type", "wireguard").Run(); err != nil {
		t.Fatalf("create foreign wg link: %v", err)
	}
	defer exec.Command("ip", "link", "delete", "dev", foreignIface).Run()

	p3 := p
	p3.PairID = foreignPair
	p3.ListenPort = 31822
	raw3, _ := json.Marshal(p3)
	if _, err := m3.Execute(ctx, "wg-prepare", raw3); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("expected ErrNotOwned for foreign interface, got: %v", err)
	}
}
