package wgrelay

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
)

type fakeRunner struct {
	calls      []string
	links      string
	handshakes string
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	s := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, s)
	if s == "ip -j -d link show" && f.links != "" {
		return []byte(f.links), nil
	}
	if strings.HasPrefix(s, "ip -j") {
		return []byte("[]"), nil
	}
	if strings.HasSuffix(s, " latest-handshakes") {
		return []byte(f.handshakes), nil
	}
	if s == "wg show all listen-port" {
		return nil, nil
	}
	return nil, nil
}
func payload(p Payload) json.RawMessage { b, _ := json.Marshal(p); return b }
func testPayload() Payload {
	return Payload{PairID: "0123456789abcdef", Revision: 1, Role: "entry", LocalAddress: "10.202.0.1/32", PeerAddress: "10.202.0.2/32", ListenPort: 51830, EntryPort: 24443, TargetPort: 443}
}
func TestRejectBeforeHostMutation(t *testing.T) {
	for _, change := range []func(*Payload){func(p *Payload) { p.PairID = "../../unsafe" }, func(p *Payload) { p.LocalAddress = "0.0.0.0/0" }, func(p *Payload) { p.LocalAddress = p.PeerAddress }, func(p *Payload) { p.EntryPort = 0 }, func(p *Payload) { p.Role = "shell" }} {
		f := &fakeRunner{}
		m := newManager(t.TempDir(), f)
		p := testPayload()
		change(&p)
		if _, err := m.Execute(context.Background(), "wg-prepare", payload(p)); err == nil {
			t.Fatal("invalid configuration accepted")
		}
		if len(f.calls) != 0 {
			t.Fatal("host accessed before validation", f.calls)
		}
	}
}
func TestUnknownRemovePersistsTombstoneWithoutHostAccess(t *testing.T) {
	f := &fakeRunner{}
	dir := t.TempDir()
	m := newManager(dir, f)
	p := testPayload()
	for i := 0; i < 2; i++ {
		b, err := m.Execute(context.Background(), "wg-remove", payload(p))
		if err != nil {
			t.Fatal(err)
		}
		var s Status
		json.Unmarshal(b, &s)
		if s.Phase != "removed" {
			t.Fatal(s)
		}
	}
	if len(f.calls) != 0 {
		t.Fatal(f.calls)
	}
	p.Revision = 0
	if _, err := m.Execute(context.Background(), "wg-remove", payload(p)); !errors.Is(err, ErrStaleRevision) {
		t.Fatal(err)
	}
	restored := newManager(dir, f)
	if err := restored.load(); err != nil {
		t.Fatal(err)
	}
	if restored.records[p.PairID].Phase != "removed" {
		t.Fatal("tombstone not restored")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		info, _ := e.Info()
		if info.Mode().Perm()&0077 != 0 {
			t.Fatal("unsafe state permissions")
		}
	}
}
func TestRefusesForeignInterface(t *testing.T) {
	p := testPayload()
	for _, field := range []string{`"alias":"foreign"`, `"ifalias":"foreign"`, `"alias":""`} {
		f := &fakeRunner{links: `[{"ifname":"` + interfaceName(p.PairID) + `",` + field + `,"linkinfo":{"info_kind":"wireguard"}}]`}
		m := newManager(t.TempDir(), f)
		if _, err := m.Execute(context.Background(), "wg-prepare", payload(p)); !errors.Is(err, ErrNotOwned) {
			t.Fatalf("expected ErrNotOwned for %s, got %v", field, err)
		}
		for _, c := range f.calls {
			if !strings.HasPrefix(c, "ip -j") {
				t.Fatal("mutated foreign interface", c)
			}
		}
	}
}

func TestAdoptsOwnedUnaliasedInterfaceAndReadsStandardAlias(t *testing.T) {
	p := testPayload()
	dir := t.TempDir()
	f := &fakeRunner{}
	m := newManager(dir, f)
	if _, err := m.Execute(context.Background(), "wg-prepare", payload(p)); err != nil {
		t.Fatal(err)
	}
	rec := m.records[p.PairID]
	if rec == nil {
		t.Fatal("missing persisted record")
	}

	// 1. Standard iproute2 JSON key `"alias"` is recognized as owned.
	f.links = `[{"ifname":"` + rec.Interface + `","alias":"` + rec.alias() + `","linkinfo":{"info_kind":"wireguard"}}]`
	owned, err := m.owned(context.Background(), rec)
	if err != nil || !owned {
		t.Fatalf("standard iproute2 alias not recognized: owned=%v err=%v", owned, err)
	}

	// 2. Unaliased interface left by v1.1.1 with matching persisted record self-heals on remove.
	f.links = `[{"ifname":"` + rec.Interface + `","linkinfo":{"info_kind":"wireguard"}}]`
	if _, err := m.Execute(context.Background(), "wg-remove", payload(Payload{PairID: p.PairID, Revision: 2})); err != nil {
		t.Fatalf("expected self-healing remove to succeed, got: %v", err)
	}
}

func TestSteadyStateVerifyFailurePreservesKernelInterface(t *testing.T) {
	p := testPayload()
	p.Topology = "reality_ss_v2"
	f := &fakeRunner{}
	m := newManager(t.TempDir(), f)
	m.dial = func(context.Context, string, string, string) (net.Conn, error) {
		return nil, context.DeadlineExceeded
	}
	if _, err := m.Execute(context.Background(), "wg-prepare", payload(p)); err != nil {
		t.Fatal(err)
	}
	rec := m.records[p.PairID]
	rec.Phase = "verified"
	rec.Config.PeerPublicKey = "expected"
	f.handshakes = "expected\t0\n"
	f.links = `[{"ifname":"` + rec.Interface + `","alias":"` + rec.alias() + `","linkinfo":{"info_kind":"wireguard"}}]`
	callsBefore := len(f.calls)
	if _, err := m.Execute(context.Background(), "wg-verify", payload(Payload{PairID: p.PairID, Revision: 1})); !errors.Is(err, ErrProbeTimeout) {
		t.Fatalf("expected probe timeout, got %v", err)
	}
	if rec.Phase != "verified" {
		t.Fatalf("expected phase to remain verified after transient probe failure, got %q", rec.Phase)
	}
	for _, c := range f.calls[callsBefore:] {
		if strings.Contains(c, "link delete") {
			t.Fatalf("transient steady-state verify failure deleted live interface: %s", c)
		}
	}
	f.handshakes = "foreign\t0\n"
	if _, err := m.Execute(context.Background(), "wg-verify", payload(Payload{PairID: p.PairID, Revision: 1})); err == nil || errors.Is(err, ErrProbeTimeout) || rec.Phase != "failed" {
		t.Fatalf("peer replacement was not a hard failure: phase=%s err=%v", rec.Phase, err)
	}
}
func TestPrepareIdempotentAndStaleRejected(t *testing.T) {
	f := &fakeRunner{}
	m := newManager(t.TempDir(), f)
	p := testPayload()
	ctx := context.Background()
	first, err := m.Execute(ctx, "wg-prepare", payload(p))
	if err != nil {
		t.Fatal(err)
	}
	n := len(f.calls)
	second, err := m.Execute(ctx, "wg-prepare", payload(p))
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) || len(f.calls) != n {
		t.Fatal("prepare not idempotent")
	}
	p.EntryPort++
	if _, err = m.Execute(ctx, "wg-prepare", payload(p)); !errors.Is(err, ErrRevisionConflict) {
		t.Fatal(err)
	}
	p.Revision = 0
	if _, err = m.Execute(ctx, "wg-prepare", payload(p)); !errors.Is(err, ErrStaleRevision) {
		t.Fatal(err)
	}
	if strings.Contains(string(first), "private") || strings.Contains(string(first), "ownership") {
		t.Fatal("secret in reply")
	}
}
func TestClosedAndCancelledManager(t *testing.T) {
	m := newManager(t.TempDir(), &fakeRunner{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Execute(ctx, "wg-status", json.RawMessage(`{}`)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Execute(context.Background(), "wg-status", json.RawMessage(`{}`)); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}
