package singbox

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
	"os"
	"path/filepath"
	"strings"
)

// WGRoute is a private, durable route intent. Password is a secret: callers must
// redact it before returning route state to an API or logging it.
type WGRoute struct {
	PairID       string `json:"pair_id"`
	Revision     uint64 `json:"revision"`
	Mode         string `json:"mode"`
	Interface    string `json:"interface,omitempty"`
	Server       string `json:"server,omitempty"`
	Port         int    `json:"port,omitempty"`
	Method       string `json:"method,omitempty"`
	Password     string `json:"password,omitempty"`
	SourceDigest string `json:"source_digest,omitempty"`
}

type sbRoute struct {
	Rules []sbRouteRule `json:"rules,omitempty"`
	Final string        `json:"final"`
}
type sbRouteRule struct {
	Inbound  []string `json:"inbound"`
	Network  string   `json:"network,omitempty"`
	Action   string   `json:"action"`
	Outbound string   `json:"outbound,omitempty"`
}

func validateSS(c SSConfig) error {
	if c.Port < 1 || c.Port > 65535 || c.Password == "" {
		return errors.New("invalid shadowsocks port or password")
	}
	var keySize int
	switch c.Method {
	case "2022-blake3-aes-128-gcm":
		keySize = 16
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		keySize = 32
	case "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305":
	default:
		return errors.New("unsupported shadowsocks method")
	}
	if keySize != 0 {
		key, err := base64.StdEncoding.DecodeString(c.Password)
		if err != nil || len(key) != keySize {
			return errors.New("invalid shadowsocks 2022 key")
		}
	}
	return nil
}

func validateWGRoute(r WGRoute) error {
	if strings.TrimSpace(r.PairID) == "" || r.Revision == 0 {
		return errors.New("WG route requires pair and nonzero revision")
	}
	switch r.Mode {
	case "blocked", "active", "direct":
	default:
		return errors.New("invalid WG route mode")
	}
	hasEndpoint := r.Interface != "" || r.Server != "" || r.Port != 0 || r.Method != "" || r.Password != ""
	if r.Mode != "active" && !hasEndpoint {
		return nil
	}
	if len(r.Interface) == 0 || len(r.Interface) > 15 || r.Interface == "." || r.Interface == ".." {
		return errors.New("invalid WG interface")
	}
	for _, ch := range r.Interface {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.') {
			return errors.New("invalid WG interface")
		}
	}
	addr, err := netip.ParseAddr(r.Server)
	if err != nil || !addr.Is4() || !addr.IsPrivate() {
		return errors.New("WG shadowsocks server must be a private IPv4 address")
	}
	return validateSS(SSConfig{Port: r.Port, Method: r.Method, Password: r.Password})
}

// readWGRoute requires wgMu. Missing overlays are legacy direct only until an
// overlay has been observed in this ConfigManager; deleting a guard is an error.
func (cm *ConfigManager) readWGRoute() (*WGRoute, error) {
	data, err := os.ReadFile(cm.configPath + ".wg-route.json")
	if errors.Is(err, os.ErrNotExist) && !cm.wgSeen {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read WG route: %w", err)
	}
	cm.wgSeen = true
	var r WGRoute
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, errors.New("malformed WG route overlay")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("trailing data in WG route overlay")
	}
	if err := validateWGRoute(r); err != nil {
		return nil, fmt.Errorf("invalid WG route overlay: %w", err)
	}
	return &r, nil
}

// GetWGRoute returns persisted intent, not proof that the route is authorized or
// running. It includes secrets; redaction is the caller's responsibility.
func (cm *ConfigManager) GetWGRoute() (*WGRoute, error) {
	cm.wgMu.Lock()
	defer cm.wgMu.Unlock()
	return cm.readWGRoute()
}

// SetWGRoute atomically persists an intent and authorizes active mode only in
// this process. Revisions are monotonic; pair replacement requires a newer
// revision after an explicit direct tombstone. Same-revision guard transitions
// preserve endpoint identity, except the initial empty blocked guard may acquire
// its endpoint once. A direct tombstone cannot be reactivated at its revision.
func (cm *ConfigManager) SetWGRoute(r WGRoute) error {
	cm.wgMu.Lock()
	defer cm.wgMu.Unlock()
	if err := validateWGRoute(r); err != nil {
		return err
	}
	old, err := cm.readWGRoute()
	if err != nil {
		cm.wgAuthorized = nil
		return err
	}
	if old != nil {
		if r.Revision < old.Revision {
			return errors.New("stale WG route revision")
		}
		if r.PairID != old.PairID && (old.Mode != "direct" || r.Revision <= old.Revision || r.Mode != "blocked") {
			return errors.New("WG route pair mismatch")
		}
		if r.Revision == old.Revision {
			if old.Mode == "direct" && r.Mode != "direct" {
				return errors.New("WG direct tombstone fences this revision")
			}
			if r.Mode != "direct" {
				a, b := *old, r
				a.Mode = ""
				b.Mode = ""
				emptyGuard := old.Mode == "blocked" && old.Interface == "" && old.Server == "" && old.Port == 0 && old.Method == "" && old.Password == "" && (old.SourceDigest == "" || old.SourceDigest == r.SourceDigest)
				if a != b && !emptyGuard {
					return errors.New("WG endpoint changed at the same revision")
				}
			}
		}
	}
	if r.Mode == "active" && (cm.Protocols == nil || !cm.Protocols.IsEnabled(ProtoReality)) {
		return errors.New("active WG route requires REALITY enabled")
	}
	// Revoke before attempting persistence: a failed fence must not leave live
	// in-memory authorization behind. Manager additionally stops the child.
	cm.wgAuthorized = nil
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := writePrivateAtomic(cm.configPath+".wg-route.json", data); err != nil {
		return err
	}
	cm.wgSeen = true
	if r.Mode == "active" {
		copy := r
		cm.wgAuthorized = &copy
		cm.wgRealityDigest = cm.RealityConfigDigest()
	}
	return nil
}

func (cm *ConfigManager) applyWGOverlay(cfg *sbConfig) error {
	cm.wgMu.Lock()
	defer cm.wgMu.Unlock()
	r, err := cm.readWGRoute()
	if err != nil {
		cm.wgAuthorized = nil
		return err
	}
	if r == nil {
		return nil
	}
	cfg.Route = &sbRoute{Final: "direct-out"}
	if r.Mode == "direct" {
		return nil
	}
	// Equality also prevents a disk edit at the same revision from authorizing
	// another endpoint. Changed REALITY credentials require fresh authorization.
	active := r.Mode == "active" && cm.wgAuthorized != nil && *cm.wgAuthorized == *r && cm.Protocols.IsEnabled(ProtoReality) && cm.wgRealityDigest == cm.RealityConfigDigest()
	if !active {
		cfg.Route.Rules = []sbRouteRule{{Inbound: []string{"vless-in"}, Action: "reject"}}
		return nil
	}
	cfg.Outbounds = append(cfg.Outbounds, sbOutbound{Type: "shadowsocks", Tag: "wg-ss-out", Server: r.Server, ServerPort: r.Port, Method: r.Method, Password: r.Password, BindInterface: r.Interface, Network: "tcp"})
	cfg.Route.Rules = []sbRouteRule{
		{Inbound: []string{"vless-in"}, Network: "tcp", Action: "route", Outbound: "wg-ss-out"},
		{Inbound: []string{"vless-in"}, Action: "reject"},
	}
	return nil
}

// RealityConfigDigest binds the source protocol identity without revealing keys.
func (cm *ConfigManager) RealityConfigDigest() string {
	if cm.Protocols == nil {
		return digestJSON(nil)
	}
	return digestJSON(struct {
		Enabled bool          `json:"enabled"`
		Config  RealityConfig `json:"config"`
	}{cm.Protocols.IsEnabled(ProtoReality), cm.Protocols.Reality})
}

// WGRouteAuthorized distinguishes persisted intent from this process's live route.
func (cm *ConfigManager) WGRouteAuthorized(pairID string, revision uint64) bool {
	cm.wgMu.Lock()
	defer cm.wgMu.Unlock()
	r, err := cm.readWGRoute()
	return err == nil && r != nil && r.PairID == pairID && r.Revision == revision && r.Mode == "active" && cm.wgAuthorized != nil && *cm.wgAuthorized == *r && cm.wgRealityDigest == cm.RealityConfigDigest()
}

// SSConfigCredentials returns the exact local SS credentials, never defaults or
// generated replacements. Only enabled, valid, supported configurations qualify.
func (cm *ConfigManager) SSConfigCredentials() (SSConfig, string, error) {
	if cm.Protocols == nil || !cm.Protocols.IsEnabled(ProtoSS) {
		return SSConfig{}, "", errors.New("shadowsocks is disabled")
	}
	c := cm.Protocols.SS
	if err := validateSS(c); err != nil {
		return SSConfig{}, "", err
	}
	return c, digestJSON(c), nil
}
func digestJSON(v any) string {
	b, _ := json.Marshal(v)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

func writePrivateAtomic(path string, data []byte) error {
	tmp, err := stagePrivateFile(path, data)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func stagePrivateFile(path string, data []byte) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(name)
		}
	}()
	if err := f.Chmod(0600); err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}
