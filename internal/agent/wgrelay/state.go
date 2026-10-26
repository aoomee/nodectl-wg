package wgrelay

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func atomicFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".relay-*")
	if err != nil {
		return stateError("write")
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return stateError("write")
	}
	if os.Rename(tmp, path) != nil {
		return stateError("rename")
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return stateError("sync")
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return stateError("sync")
	}
	return nil
}
func secureRead(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
		return nil, stateError("permissions")
	}
	return os.ReadFile(path)
}
func (m *Manager) statePath(id string) string { return filepath.Join(m.dir, id+".json") }
func (m *Manager) keyPath(id string) string   { return filepath.Join(m.dir, id+".key") }
func (m *Manager) save(r *record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return stateError("encode")
	}
	return atomicFile(m.statePath(r.Config.PairID), b)
}
func (m *Manager) key(r *record) error {
	raw, err := secureRead(m.keyPath(r.Config.PairID))
	if err == nil {
		bytes, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if e != nil {
			return stateError("key validation")
		}
		private, e := ecdh.X25519().NewPrivateKey(bytes)
		if e != nil {
			return stateError("key validation")
		}
		public := base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())
		if r.PublicKey != "" && r.PublicKey != public {
			return stateError("key mismatch")
		}
		r.PublicKey = public
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return stateError("key read")
	}
	if r.PublicKey != "" {
		return stateError("key missing")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return stateError("key generation")
	}
	// WireGuard private keys are X25519 scalars in their clamped representation.
	bytes := key.Bytes()
	bytes[0] &= 248
	bytes[31] &= 127
	bytes[31] |= 64
	if err := atomicFile(m.keyPath(r.Config.PairID), []byte(base64.StdEncoding.EncodeToString(bytes)+"\n")); err != nil {
		return err
	}
	r.PublicKey = base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	return nil
}
func newToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", stateError("random")
	}
	return hex.EncodeToString(b), nil
}
func (m *Manager) load() error {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return stateError("read")
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !pairPattern.MatchString(id) {
			return stateError("filename validation")
		}
		b, err := secureRead(m.statePath(id))
		if err != nil {
			return stateError("read")
		}
		var r record
		if json.Unmarshal(b, &r) != nil || r.Config.PairID != id || r.Interface != interfaceName(id) {
			return stateError("validation")
		}
		if r.Phase != "removed" && r.Phase != "removing" {
			if validateConfig(r.Config, r.Phase == "configured" || r.Phase == "verified" || r.Phase == "active" || r.Phase == "configuring") != nil {
				return stateError("configuration validation")
			}
		}
		switch r.Phase {
		case "preparing", "prepared", "configuring", "configured", "verifying", "verified", "activating", "active", "removing", "removed", "failed":
		default:
			return stateError("phase validation")
		}
		if !tokenPattern.MatchString(r.Token) {
			return stateError("ownership validation")
		}
		m.records[id] = &r
	}
	return nil
}
