package agent

import "testing"

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
