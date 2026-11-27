package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIsVirtualInterface(t *testing.T) {
	virtuals := []string{
		"", "lo", "docker0", "veth1234", "br-abcd", "virbr0",
		"wg0", "nw1a2b3c4d5e6f7", "tun0", "tap0", "tailscale0",
		"cni0", "flannel.1", "cali123", "podman0", "zt1234", "utun3",
	}
	for _, name := range virtuals {
		if !isVirtualInterface(name) {
			t.Fatalf("expected %q to be treated as virtual interface", name)
		}
	}

	physicals := []string{"eth0", "eth1", "ens3", "enp1s0", "venet0", "eno1"}
	for _, name := range physicals {
		if isVirtualInterface(name) {
			t.Fatalf("expected %q to be treated as physical interface", name)
		}
	}
}

func TestParseDefaultRouteInterface(t *testing.T) {
	route := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"nw1a2b3c4d5e6f7\t00000000\t00000000\t0001\t0\t0\t10\t00000000\t0\t0\t0\n" +
		"ens3\t00000000\t010010AC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"ens3\t000010AC\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"

	got := parseDefaultRouteInterface(route)
	if got != "ens3" {
		t.Fatalf("expected default route interface ens3, got %q", got)
	}
}

func TestCollectorSelfHealsWhenInterfaceDisappears(t *testing.T) {
	root := t.TempDir()
	writeCounter := func(iface, counter string, val int64) {
		t.Helper()
		dir := filepath.Join(root, iface)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, counter), []byte(fmt.Sprintf("%d\n", val)), 0644); err != nil {
			t.Fatal(err)
		}
	}

	writeCounter("nicA", "rx_bytes", 1000)
	writeCounter("nicA", "tx_bytes", 2000)
	writeCounter("nicB", "rx_bytes", 50000)
	writeCounter("nicB", "tx_bytes", 60000)

	detectedIface := "nicA"
	c := NewCollector("auto")
	c.detectFn = func() (string, error) {
		return detectedIface, nil
	}
	c.openCounterFn = func(iface, counter string) (*os.File, error) {
		return os.Open(filepath.Join(root, iface, counter))
	}

	if err := c.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer c.Close()

	if c.GetInterface() != "nicA" {
		t.Fatalf("expected nicA, got %s", c.GetInterface())
	}

	// Simulate nicA disappearing and FD becoming unreadable.
	_ = c.rxFile.Close()
	_ = c.txFile.Close()
	if err := os.RemoveAll(filepath.Join(root, "nicA")); err != nil {
		t.Fatal(err)
	}
	detectedIface = "nicB"

	if err := c.Sample(); err != nil {
		t.Fatalf("expected Sample to self-heal to nicB, got error: %v", err)
	}
	if c.GetInterface() != "nicB" {
		t.Fatalf("expected collector to rebind to nicB, got %s", c.GetInterface())
	}
	if gotBoot := c.EffectiveBootID("boot-1"); gotBoot != "boot-1#nic1" {
		t.Fatalf("expected EffectiveBootID to bump epoch after NIC switch, got %q", gotBoot)
	}
	rxRate, txRate, rxBytes, txBytes := c.GetLiveSnapshot()
	if rxRate != 0 || txRate != 0 || rxBytes != 50000 || txBytes != 60000 {
		t.Fatalf("unexpected post-rebind snapshot: rxRate=%d txRate=%d rx=%d tx=%d", rxRate, txRate, rxBytes, txBytes)
	}

	// Subsequent sample on nicB computes positive rates cleanly.
	time.Sleep(20 * time.Millisecond)
	writeCounter("nicB", "rx_bytes", 52000)
	writeCounter("nicB", "tx_bytes", 64000)
	if err := c.Sample(); err != nil {
		t.Fatalf("second sample on nicB failed: %v", err)
	}
	rxRate, txRate, rxBytes, txBytes = c.GetLiveSnapshot()
	if rxRate <= 0 || txRate <= 0 || rxBytes != 52000 || txBytes != 64000 {
		t.Fatalf("unexpected nicB sampled snapshot: rxRate=%d txRate=%d rx=%d tx=%d", rxRate, txRate, rxBytes, txBytes)
	}
}
