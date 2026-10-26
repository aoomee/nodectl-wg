// Package requestmeta resolves transport and client identity at the proxy trust
// boundary. Forwarding headers are never trusted without an explicit TCP peer.
package requestmeta

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
)

const TrustedProxiesEnv = "NODECTL_TRUSTED_PROXIES"

type policy struct{ proxies []netip.Prefix }

// The zero value trusts no proxies, including loopback and Docker gateways.
var current atomic.Pointer[policy]

// Configure installs an immutable policy. Call before serving requests. An
// invalid configuration leaves the previous policy intact and must fail startup.
func Configure(raw string) error {
	p := &policy{}
	if strings.TrimSpace(raw) != "" {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			prefix, err := netip.ParsePrefix(part)
			if err != nil {
				addr, addrErr := netip.ParseAddr(part)
				if addrErr != nil || addr.Zone() != "" {
					return fmt.Errorf("%s: expected comma-separated IP addresses or CIDRs, got %q", TrustedProxiesEnv, part)
				}
				addr = addr.Unmap()
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
			if prefix.Addr().Is4In6() || prefix.Bits() == 0 || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
				return fmt.Errorf("%s: use a specific proxy IP or network, got %q", TrustedProxiesEnv, part)
			}
			p.proxies = append(p.proxies, prefix.Masked())
		}
	}
	current.Store(p)
	return nil
}

func (p *policy) trusted(addr netip.Addr) bool {
	if p == nil || !addr.IsValid() {
		return false
	}
	for _, prefix := range p.proxies {
		if prefix.Contains(addr.Unmap()) {
			return true
		}
	}
	return false
}

func parseIP(raw string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func peerIP(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return parseIP(host)
}

// IsSecure reports the external HTTPS transport. The configured proxy must
// overwrite X-Forwarded-Proto with one value; ambiguous chains fail closed.
// Do not replace r.TLS: it still describes the actual backend connection.
func IsSecure(r *http.Request) bool {
	peer, _ := peerIP(r)
	if current.Load().trusted(peer) {
		values := r.Header.Values("X-Forwarded-Proto")
		if len(values) != 0 {
			return len(values) == 1 && strings.EqualFold(strings.TrimSpace(values[0]), "https")
		}
	}
	return r.TLS != nil
}

// ClientIP walks X-Forwarded-For from the nearest proxy towards the client and
// stops at the first untrusted hop. Client-supplied prefixes are not identities.
// A malformed chain falls back to the TCP peer, never another forwarded header.
func ClientIP(r *http.Request) string {
	peer, ok := peerIP(r)
	if !ok {
		return "unknown"
	}
	p := current.Load()
	if !p.trusted(peer) {
		return peer.String()
	}
	if values := r.Header.Values("X-Forwarded-For"); len(values) > 0 {
		raw := strings.Join(values, ",")
		parts := strings.Split(raw, ",")
		if len(raw) > 4096 || len(parts) > 32 {
			return peer.String()
		}
		chain := make([]netip.Addr, len(parts))
		for i, part := range parts {
			addr, valid := parseIP(part)
			if !valid {
				return peer.String()
			}
			chain[i] = addr
		}
		client := peer
		for i := len(chain) - 1; i >= 0 && p.trusted(client); i-- {
			client = chain[i]
		}
		return client.String()
	}
	if values := r.Header.Values("X-Real-IP"); len(values) == 1 {
		if addr, valid := parseIP(values[0]); valid {
			return addr.String()
		}
	}
	return peer.String()
}
