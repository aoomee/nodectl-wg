package wgrelay

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Manager serializes local transitions. Close stops sessions and releases its
// state lock, but deliberately retains owned kernel links for restart recovery.
type Manager struct {
	mu      sync.Mutex
	dir     string
	runner  commandRunner
	dial    dialFunc
	listen  func(string, string) (net.Listener, error)
	records map[string]*record
	proxies map[string]*proxy
	lock    *os.File
	closed  bool
}

func New(stateDir string) (*Manager, error) {
	if err := prerequisites(); err != nil {
		return nil, err
	}
	dir, err := filepath.Abs(stateDir)
	if err != nil || stateDir == "" {
		return nil, stateError("directory")
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, stateError("directory")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, stateError("directory permissions")
	}
	lockPath := filepath.Join(dir, ".lock")
	if info, e := os.Lstat(lockPath); e == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
		return nil, stateError("lock permissions")
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, stateError("lock")
	}
	if lockState(lock) != nil {
		_ = lock.Close()
		return nil, errors.New("relay state is already managed")
	}
	m := newManager(dir, execRunner{})
	m.lock = lock
	if err = m.load(); err == nil {
		err = m.restore()
	}
	if err != nil {
		_ = m.Close()
		return nil, err
	}
	return m, nil
}
func newManager(dir string, runner commandRunner) *Manager {
	return &Manager{dir: dir, runner: runner, dial: boundDial, listen: net.Listen, records: make(map[string]*record), proxies: make(map[string]*proxy)}
}
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	for id, p := range m.proxies {
		_ = p.close()
		delete(m.proxies, id)
	}
	if m.lock != nil {
		unlockState(m.lock)
		return m.lock.Close()
	}
	return nil
}
func (m *Manager) restore() error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	for _, r := range m.records {
		switch r.Phase {
		case "removed":
			continue
		case "preparing", "configuring", "verifying", "activating", "removing", "failed":
			if err := m.cleanup(ctx, r); err != nil {
				return err
			}
			if r.Phase == "removing" {
				r.Phase = "removed"
				if err := m.removeKey(r); err != nil {
					return err
				}
			} else {
				r.Phase = "failed"
			}
			r.TargetVerified = false
			if err := m.save(r); err != nil {
				return err
			}
		default:
			if _, err := m.owned(ctx, r); err != nil {
				return err
			}
			if err := m.key(r); err != nil {
				return err
			}
			if r.Phase == "prepared" {
				if err := m.prepareKernel(ctx, r); err != nil {
					return m.failed(r, err)
				}
			} else {
				if err := m.configureKernel(ctx, r); err != nil {
					return m.failed(r, err)
				}
				// A previous verification is not evidence about a restarted connection.
				r.TargetVerified = false
				if r.Phase == "active" {
					// Never reopen a public listener solely from persisted state.
					r.Phase = "configured"
				} else if r.Phase == "verified" {
					r.Phase = "configured"
				}
				if err := m.save(r); err != nil {
					return m.failed(r, err)
				}
			}
		}
	}
	return nil
}

// Execute accepts one of wg-prepare/configure/verify/activate/remove/status.
// A newer revision must enter through prepare (or remove). Same-revision
// prepare/configure calls are idempotent only for identical configuration.
func (m *Manager) Execute(ctx context.Context, action string, raw json.RawMessage) (json.RawMessage, error) {
	p, err := decodePayload(raw)
	if err != nil {
		return nil, err
	}
	switch action {
	case "wg-prepare", "wg-configure", "wg-verify", "wg-activate", "wg-remove", "wg-status":
	default:
		return nil, errors.New("unknown relay action")
	}
	if action != "wg-status" || p.PairID != "" {
		if err = validateID(p); err != nil {
			return nil, err
		}
	}
	if action == "wg-prepare" || action == "wg-configure" {
		if err = validateConfig(p, action == "wg-configure"); err != nil {
			return nil, err
		}
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrClosed
	}
	if action == "wg-status" {
		if r := m.records[p.PairID]; r != nil && r.Phase == "active" {
			if err := m.verify(ctx, r); err != nil {
				return nil, m.failed(r, err)
			}
		}
		return m.status(p.PairID)
	}
	r := m.records[p.PairID]
	if r != nil && p.Revision < r.Config.Revision {
		return nil, ErrStaleRevision
	}
	if action == "wg-remove" {
		return m.remove(ctx, p, r)
	}
	if action == "wg-prepare" {
		return m.prepare(ctx, p, r)
	}
	if r == nil {
		return nil, errors.New("relay pair must be prepared first")
	}
	if p.Revision != r.Config.Revision {
		return nil, errors.New("new relay revision must be prepared first")
	}
	if r.Phase == "removed" || r.Phase == "removing" || r.Phase == "failed" {
		return nil, errors.New("relay requires a newer prepare revision")
	}
	switch action {
	case "wg-configure":
		if !sameLocal(p, r.Config) {
			return nil, ErrRevisionConflict
		}
		if r.Phase != "prepared" {
			if r.Config == p && (r.Phase == "configured" || r.Phase == "verified" || r.Phase == "active") {
				return m.result(r)
			}
			return nil, ErrRevisionConflict
		}
		// Prepare may carry peer credentials; do not silently change them.
		if r.Config.PeerPublicKey != "" && r.Config.PeerPublicKey != p.PeerPublicKey || r.Config.PeerEndpoint != "" && r.Config.PeerEndpoint != p.PeerEndpoint || r.Config.PeerPort != 0 && r.Config.PeerPort != p.PeerPort {
			return nil, ErrRevisionConflict
		}
		if p.PeerPublicKey == r.PublicKey {
			return nil, errors.New("peer public key must differ from local key")
		}
		if err = m.collisions(ctx, r); err != nil {
			return nil, err
		}
		r.Config = p
		r.Phase = "configuring"
		r.LastAction = action
		if err = m.save(r); err != nil {
			return nil, m.failed(r, err)
		}
		if err = m.configureKernel(ctx, r); err != nil {
			return nil, m.failed(r, err)
		}
		r.Phase = "configured"
	case "wg-verify":
		if r.Phase != "configured" && r.Phase != "verified" && r.Phase != "active" {
			return nil, errors.New("relay is not configured")
		}
		active := r.Phase == "active"
		r.Phase = "verifying"
		r.LastAction = action
		if err = m.save(r); err != nil {
			return nil, m.failed(r, err)
		}
		if err = m.verify(ctx, r); err != nil {
			return nil, m.failed(r, err)
		}
		r.Phase = "verified"
		if active {
			r.Phase = "active"
		}
	case "wg-activate":
		if r.Phase == "active" {
			return m.result(r)
		}
		if r.Phase != "verified" {
			return nil, errors.New("relay must be verified before activation")
		}
		r.Phase = "activating"
		r.LastAction = action
		if err = m.save(r); err != nil {
			return nil, m.failed(r, err)
		}
		if err = m.verify(ctx, r); err != nil {
			return nil, m.failed(r, err)
		}
		if err = m.start(r); err != nil {
			return nil, m.failed(r, err)
		}
		r.Phase = "active"
	}
	if err = m.save(r); err != nil {
		return nil, m.failed(r, err)
	}
	return m.result(r)
}
func (m *Manager) prepare(ctx context.Context, p Payload, old *record) (json.RawMessage, error) {
	if old != nil && p.Revision == old.Config.Revision {
		if old.Phase == "removed" || old.Phase == "removing" || old.Phase == "failed" {
			return nil, errors.New("relay requires a newer prepare revision")
		}
		if sameLocal(p, old.Config) && (p.PeerPublicKey == "" || p.PeerPublicKey == old.Config.PeerPublicKey) && (p.PeerEndpoint == "" || p.PeerEndpoint == old.Config.PeerEndpoint) && (p.PeerPort == 0 || p.PeerPort == old.Config.PeerPort) {
			return m.result(old)
		}
		return nil, ErrRevisionConflict
	}
	token, err := newToken()
	if err != nil {
		return nil, err
	}
	r := &record{Config: p, Interface: interfaceName(p.PairID), Token: token, Phase: "preparing", LastAction: "wg-prepare"}
	if old != nil {
		r.Token = old.Token
		if old.Phase != "removed" {
			r.PublicKey = old.PublicKey
		}
	}
	// Validate the entire candidate and host before any state/kernel mutation.
	if err = m.collisions(ctx, r); err != nil {
		return nil, err
	}
	if err = m.save(r); err != nil {
		return nil, err
	}
	m.records[p.PairID] = r
	if old != nil {
		if err = m.cleanup(ctx, old); err != nil {
			return nil, m.failed(r, err)
		}
	}
	if err = m.key(r); err != nil {
		return nil, m.failed(r, err)
	}
	if err = m.save(r); err != nil {
		return nil, m.failed(r, err)
	}
	if err = m.prepareKernel(ctx, r); err != nil {
		return nil, m.failed(r, err)
	}
	r.Phase = "prepared"
	if err = m.save(r); err != nil {
		return nil, m.failed(r, err)
	}
	return m.result(r)
}
func (m *Manager) prepareKernel(ctx context.Context, r *record) error {
	if err := m.collisions(ctx, r); err != nil {
		return err
	}
	if err := m.createInterface(ctx, r); err != nil {
		return err
	}
	_, err := m.run(ctx, "wg", "set", r.Interface, "private-key", m.keyPath(r.Config.PairID), "listen-port", strconv.Itoa(r.Config.ListenPort))
	return err
}
func (m *Manager) remove(ctx context.Context, p Payload, r *record) (json.RawMessage, error) {
	if r == nil {
		token, err := newToken()
		if err != nil {
			return nil, err
		}
		r = &record{Config: Payload{PairID: p.PairID, Revision: p.Revision}, Interface: interfaceName(p.PairID), Token: token, Phase: "removed", LastAction: "wg-remove"}
		if err = m.save(r); err != nil {
			return nil, err
		}
		m.records[p.PairID] = r
		// An unknown pair writes a tombstone only. Never inspect/delete its name.
		return m.result(r)
	}
	if r.Phase == "removed" && p.Revision == r.Config.Revision {
		return m.result(r)
	}
	r.Config.Revision = p.Revision
	r.Phase = "removing"
	r.LastAction = "wg-remove"
	r.TargetVerified = false
	if err := m.save(r); err != nil {
		return nil, err
	}
	if err := m.cleanup(ctx, r); err != nil {
		return nil, err
	}
	if err := m.removeKey(r); err != nil {
		return nil, err
	}
	r.PublicKey = ""
	r.Phase = "removed"
	if err := m.save(r); err != nil {
		return nil, err
	}
	return m.result(r)
}
func (m *Manager) removeKey(r *record) error {
	err := os.Remove(m.keyPath(r.Config.PairID))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return stateError("key removal")
	}
	return nil
}
func (m *Manager) failed(r *record, cause error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cleanupErr := m.cleanup(ctx, r)
	r.Phase = "failed"
	r.TargetVerified = false
	persistErr := m.save(r)
	if cleanupErr != nil {
		return errors.Join(cause, errors.New("owned relay cleanup incomplete"))
	}
	if persistErr != nil {
		return errors.Join(cause, persistErr)
	}
	return cause
}
func (m *Manager) verify(ctx context.Context, r *record) error {
	exists, err := m.owned(ctx, r)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("owned relay interface is missing")
	}
	r.TargetVerified = false
	vctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	if r.Config.Role == "entry" {
		c, err := m.dial(vctx, r.Interface, strings.TrimSuffix(r.Config.LocalAddress, "/32"), net.JoinHostPort(strings.TrimSuffix(r.Config.PeerAddress, "/32"), strconv.Itoa(r.Config.TargetPort)))
		if err != nil {
			return errors.New("bound WireGuard target TCP verification failed")
		}
		_ = c.Close()
		r.TargetVerified = true
	}
	for {
		if err = m.handshake(vctx, r); err == nil {
			return nil
		}
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-vctx.Done():
			timer.Stop()
			return errors.New("WireGuard handshake verification failed")
		case <-timer.C:
		}
	}
}
func (m *Manager) start(r *record) error {
	if r.Config.Role != "entry" {
		return nil
	}
	if p := m.proxies[r.Config.PairID]; p != nil {
		_ = p.close()
		delete(m.proxies, r.Config.PairID)
	}
	listener, err := m.listen("tcp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(r.Config.EntryPort)))
	if err != nil {
		return errors.New("entry TCP port cannot be bound")
	}
	device, source, destination := r.Interface, strings.TrimSuffix(r.Config.LocalAddress, "/32"), net.JoinHostPort(strings.TrimSuffix(r.Config.PeerAddress, "/32"), strconv.Itoa(r.Config.TargetPort))
	m.proxies[r.Config.PairID] = startProxy(listener, func(ctx context.Context) (net.Conn, error) { return m.dial(ctx, device, source, destination) })
	return nil
}
func (m *Manager) snapshot(r *record) Status {
	return Status{PairID: r.Config.PairID, Revision: r.Config.Revision, Role: r.Config.Role, Interface: r.Interface, PublicKey: r.PublicKey, Phase: r.Phase, TargetTCPVerified: r.TargetVerified, ProxyListening: m.proxies[r.Config.PairID] != nil}
}
func (m *Manager) result(r *record) (json.RawMessage, error) { return json.Marshal(m.snapshot(r)) }
func (m *Manager) status(id string) (json.RawMessage, error) {
	if id != "" {
		r := m.records[id]
		if r == nil {
			return nil, errors.New("unknown relay pair")
		}
		if proxy := m.proxies[id]; proxy != nil && !proxy.renew() {
			delete(m.proxies, id)
			r.TargetVerified = false
		}
		return m.result(r)
	}
	pairs := make([]Status, 0, len(m.records))
	for _, r := range m.records {
		pairs = append(pairs, m.snapshot(r))
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].PairID < pairs[j].PairID })
	return json.Marshal(struct {
		Supported bool     `json:"supported"`
		Backend   string   `json:"backend"`
		Actions   []string `json:"actions"`
		Pairs     []Status `json:"pairs"`
	}{true, "kernel-wireguard", []string{"wg-prepare", "wg-configure", "wg-verify", "wg-activate", "wg-remove", "wg-status"}, pairs})
}
