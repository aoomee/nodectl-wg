// Package wgrelay manages isolated kernel WireGuard links and TCP entry relays.
// It never changes default routes, firewall rules, or existing services.
package wgrelay

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
)

var (
	ErrUnsupported      = errors.New("wgrelay requires Linux with systemd, root, and existing ip/wg tools")
	ErrStaleRevision    = errors.New("stale relay revision")
	ErrRevisionConflict = errors.New("relay revision conflicts with existing configuration")
	ErrNotOwned         = errors.New("relay interface is not owned by this manager")
	ErrClosed           = errors.New("relay manager is closed")
	pairPattern         = regexp.MustCompile(`^[0-9a-f]{16,32}$`)
	tokenPattern        = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// Payload is the action wire format. Prepare needs all local fields; peer
// credentials may be omitted until configure. Configure needs the full payload.
// Verify, activate, and remove need only PairID and Revision. Status accepts {}.
type Payload struct {
	Topology      string `json:"topology,omitempty"`
	PairID        string `json:"pair_id"`
	Revision      uint64 `json:"revision"`
	Role          string `json:"role,omitempty"`
	LocalAddress  string `json:"local_address,omitempty"`
	PeerAddress   string `json:"peer_address,omitempty"`
	PeerEndpoint  string `json:"peer_endpoint,omitempty"`
	ListenPort    int    `json:"listen_port,omitempty"`
	PeerPort      int    `json:"peer_port,omitempty"`
	PeerPublicKey string `json:"peer_public_key,omitempty"`
	EntryPort     int    `json:"entry_port,omitempty"`
	TargetPort    int    `json:"target_port,omitempty"`
}

type record struct {
	Config         Payload `json:"config"`
	Interface      string  `json:"interface"`
	Token          string  `json:"ownership_token,omitempty"`
	PublicKey      string  `json:"public_key,omitempty"`
	Phase          string  `json:"phase"`
	LastAction     string  `json:"last_action,omitempty"`
	TargetVerified bool    `json:"target_tcp_verified"`
}

// Status contains no private keys, ownership tokens, or command output.
type Status struct {
	RouteActive       bool   `json:"route_active,omitempty"`
	SourceDigest      string `json:"source_digest,omitempty"`
	PairID            string `json:"pair_id"`
	Revision          uint64 `json:"revision"`
	Role              string `json:"role,omitempty"`
	Interface         string `json:"interface,omitempty"`
	PublicKey         string `json:"public_key,omitempty"`
	Phase             string `json:"phase"`
	TargetTCPVerified bool   `json:"target_tcp_verified"`
	ProxyListening    bool   `json:"proxy_listening"`
}

func decodePayload(raw json.RawMessage) (Payload, error) {
	var p Payload
	if len(raw) == 0 || len(raw) > 16384 {
		return p, errors.New("invalid relay payload size")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, errors.New("invalid relay payload")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return p, errors.New("invalid relay payload")
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return p, errors.New("relay payload must be an object")
	}
	return p, nil
}

func validateID(p Payload) error {
	if !pairPattern.MatchString(p.PairID) {
		return errors.New("pair_id must be 16-32 lowercase hexadecimal characters")
	}
	// Revision zero is valid: the wire contract specifies uint64, not a minimum.
	return nil
}

func privateHost(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() || !p.Addr().IsPrivate() || p.Bits() != 32 {
		return netip.Prefix{}, errors.New("relay addresses must be private IPv4 /32 hosts")
	}
	if p.String() != s {
		return netip.Prefix{}, errors.New("relay address must be canonical")
	}
	return p, nil
}

func validateConfig(p Payload, peerRequired bool) error {
	if p.Topology != "" && p.Topology != "reality_ss_v2" {
		return errors.New("unsupported relay topology")
	}
	if err := validateID(p); err != nil {
		return err
	}
	if p.Role != "entry" && p.Role != "landing" {
		return errors.New("role must be entry or landing")
	}
	if _, err := privateHost(p.LocalAddress); err != nil {
		return err
	}
	if _, err := privateHost(p.PeerAddress); err != nil {
		return err
	}
	if p.LocalAddress == p.PeerAddress {
		return errors.New("local and peer relay addresses must differ")
	}
	for _, port := range []int{p.ListenPort, p.EntryPort, p.TargetPort} {
		if port < 1 || port > 65535 {
			return errors.New("relay ports must be between 1 and 65535")
		}
	}
	if peerRequired || p.PeerEndpoint != "" {
		a, err := netip.ParseAddr(p.PeerEndpoint)
		if err != nil || !a.Is4() || !a.IsGlobalUnicast() || a.IsLoopback() {
			return errors.New("peer_endpoint must be a unicast IPv4 address")
		}
		if a.String()+"/32" == p.LocalAddress || a.String()+"/32" == p.PeerAddress {
			return errors.New("peer endpoint cannot be a relay tunnel address")
		}
	}
	if peerRequired || p.PeerPort != 0 {
		if p.PeerPort < 1 || p.PeerPort > 65535 {
			return errors.New("peer_port must be between 1 and 65535")
		}
	}
	if peerRequired || p.PeerPublicKey != "" {
		if !validKey(p.PeerPublicKey) {
			return errors.New("invalid WireGuard public key")
		}
	}
	return nil
}

func validKey(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != s {
		return false
	}
	var nonzero byte
	for _, v := range b {
		nonzero |= v
	}
	return nonzero != 0
}

func interfaceName(id string) string {
	sum := sha256.Sum256([]byte(id))
	return "nw" + hex.EncodeToString(sum[:])[:13]
}
func (r *record) alias() string { return "ncwg:" + r.Config.PairID + ":" + r.Token }
func sameLocal(a, b Payload) bool {
	a.PeerEndpoint, b.PeerEndpoint = "", ""
	a.PeerPublicKey, b.PeerPublicKey = "", ""
	a.PeerPort, b.PeerPort = 0, 0
	return a == b
}
func stateError(operation string) error { return fmt.Errorf("relay state %s failed", operation) }
