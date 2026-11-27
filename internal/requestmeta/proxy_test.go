package requestmeta

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"
)

func setPolicy(t *testing.T, value string) {
	t.Helper()
	old := current.Load()
	t.Cleanup(func() { current.Store(old) })
	if err := Configure(value); err != nil {
		t.Fatal(err)
	}
}

func TestSecureTransport(t *testing.T) {
	setPolicy(t, "127.0.0.1, ::1, 172.30.0.1/32")
	for _, tc := range []struct {
		name, peer string
		tls        bool
		proto      []string
		want       bool
	}{
		{"native TLS", "198.51.100.1:123", true, nil, true},
		{"direct HTTP", "198.51.100.1:123", false, nil, false},
		{"forged HTTPS", "198.51.100.1:123", false, []string{"https"}, false},
		{"trusted loopback", "127.0.0.1:123", false, []string{"https"}, true},
		{"trusted IPv6", "[::1]:123", false, []string{"https"}, true},
		{"mapped IPv4", "[::ffff:127.0.0.1]:123", false, []string{"https"}, true},
		{"trusted Docker gateway", "172.30.0.1:123", false, []string{"https"}, true},
		{"other private peer", "172.30.0.2:123", false, []string{"https"}, false},
		{"missing declaration", "127.0.0.1:123", false, nil, false},
		{"external HTTP over TLS upstream", "127.0.0.1:123", true, []string{"http"}, false},
		{"untrusted HTTP header on TLS", "198.51.100.1:123", true, []string{"http"}, true},
		{"comma chain", "127.0.0.1:123", false, []string{"https,http"}, false},
		{"duplicate", "127.0.0.1:123", true, []string{"https", "https"}, false},
		{"empty", "127.0.0.1:123", true, []string{""}, false},
		{"scheme invalid", "127.0.0.1:123", true, []string{"wss"}, false},
		{"invalid peer", "proxy.example:123", false, []string{"https"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://panel.test/", nil)
			r.RemoteAddr = tc.peer
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			for _, v := range tc.proto {
				r.Header.Add("X-Forwarded-Proto", v)
			}
			if got := IsSecure(r); got != tc.want {
				t.Fatalf("secure=%v want %v", got, tc.want)
			}
		})
	}
}

func TestClientIPTrustBoundary(t *testing.T) {
	setPolicy(t, "127.0.0.1, 10.2.0.0/24, ::1")
	for _, tc := range []struct{ name, peer, xff, real, want string }{
		{"direct spoof", "198.51.100.8:1", "1.1.1.1", "2.2.2.2", "198.51.100.8"},
		{"trusted real IP", "127.0.0.1:1", "", "198.51.100.8", "198.51.100.8"},
		{"trusted XFF", "127.0.0.1:1", "198.51.100.8", "2.2.2.2", "198.51.100.8"},
		{"ignore forged prefix", "127.0.0.1:1", "1.1.1.1, 198.51.100.8", "", "198.51.100.8"},
		{"multiple trusted hops", "127.0.0.1:1", "1.1.1.1, 198.51.100.8, 10.2.0.3", "", "198.51.100.8"},
		{"untrusted private hop", "127.0.0.1:1", "1.1.1.1, 10.3.0.3", "", "10.3.0.3"},
		{"malformed chain", "127.0.0.1:1", "bad, 198.51.100.8", "2.2.2.2", "127.0.0.1"},
		{"malformed tail", "127.0.0.1:1", "198.51.100.8,", "2.2.2.2", "127.0.0.1"},
		{"invalid real IP", "127.0.0.1:1", "", "user-controlled", "127.0.0.1"},
		{"real IP list", "127.0.0.1:1", "", "1.1.1.1, 2.2.2.2", "127.0.0.1"},
		{"IPv6", "[::1]:1", "2001:db8::1", "", "2001:db8::1"},
		{"mapped IPv4", "[::ffff:198.51.100.8]:1", "", "", "198.51.100.8"},
		{"invalid peer", "unknown", "1.1.1.1", "2.2.2.2", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://panel.test/", nil)
			r.RemoteAddr = tc.peer
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.real != "" {
				r.Header.Set("X-Real-IP", tc.real)
			}
			if got := ClientIP(r); got != tc.want {
				t.Fatalf("IP=%q want %q", got, tc.want)
			}
		})
	}
}

func TestProxyConfiguration(t *testing.T) {
	setPolicy(t, "")
	r := httptest.NewRequest("GET", "http://panel.test/", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Real-IP", "198.51.100.8")
	if IsSecure(r) || ClientIP(r) != "127.0.0.1" {
		t.Fatal("loopback trusted by default")
	}
	for _, raw := range []string{"*", "0.0.0.0/0", "::/0", "proxy.local", "127.0.0.1,", "127.0.0.1,,::1", "127.0.0.1:80", "fe80::1%en0", "::ffff:127.0.0.0/104", "224.0.0.1"} {
		if Configure(raw) == nil {
			t.Errorf("accepted invalid policy %q", raw)
		}
		if IsSecure(r) {
			t.Fatal("failed configuration was partly installed")
		}
	}
}
