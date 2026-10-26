package wgrelay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type commandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}
type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	// Deliberately never expose stderr, arguments, or subprocess errors.
	if err != nil {
		return nil, fmt.Errorf("relay %s command failed", name)
	}
	return out, nil
}
func (m *Manager) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := m.runner.Run(ctx, name, args...)
	if err != nil {
		return nil, fmt.Errorf("relay %s command failed", name)
	}
	return out, nil
}

type linkInfo struct {
	Name  string `json:"ifname"`
	Alias string `json:"ifalias"`
	Info  struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
	Addresses []struct {
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
	} `json:"addr_info"`
}

func (m *Manager) links(ctx context.Context) ([]linkInfo, error) {
	b, err := m.run(ctx, "ip", "-j", "-d", "link", "show")
	if err != nil {
		return nil, err
	}
	var links []linkInfo
	if json.Unmarshal(b, &links) != nil {
		return nil, errors.New("invalid ip link response")
	}
	return links, nil
}
func (m *Manager) owned(ctx context.Context, r *record) (bool, error) {
	links, err := m.links(ctx)
	if err != nil {
		return false, err
	}
	for _, l := range links {
		if l.Name == r.Interface {
			if l.Alias != r.alias() || l.Info.Kind != "wireguard" {
				return false, ErrNotOwned
			}
			return true, nil
		}
	}
	return false, nil
}
func (m *Manager) collisions(ctx context.Context, r *record) error {
	links, err := m.links(ctx)
	if err != nil {
		return err
	}
	for _, l := range links {
		if l.Name == r.Interface && (l.Alias != r.alias() || l.Info.Kind != "wireguard") {
			return ErrNotOwned
		}
	}
	b, err := m.run(ctx, "ip", "-j", "-4", "address", "show")
	if err != nil {
		return err
	}
	var addresses []linkInfo
	if json.Unmarshal(b, &addresses) != nil {
		return errors.New("invalid ip address response")
	}
	local, _ := netip.ParsePrefix(r.Config.LocalAddress)
	peer, _ := netip.ParsePrefix(r.Config.PeerAddress)
	for _, l := range addresses {
		if l.Name == r.Interface {
			continue
		}
		for _, a := range l.Addresses {
			addr, e := netip.ParseAddr(a.Local)
			if e != nil || !addr.Is4() || a.PrefixLen < 0 || a.PrefixLen > 32 {
				return errors.New("invalid ip address response")
			}
			prefix := netip.PrefixFrom(addr, a.PrefixLen)
			if prefix.Contains(local.Addr()) || prefix.Contains(peer.Addr()) {
				return errors.New("relay address overlaps an existing interface")
			}
		}
	}
	b, err = m.run(ctx, "ip", "-j", "-4", "route", "show", "table", "all")
	if err != nil {
		return err
	}
	var routes []struct {
		Dst string `json:"dst"`
		Dev string `json:"dev"`
	}
	if json.Unmarshal(b, &routes) != nil {
		return errors.New("invalid ip route response")
	}
	for _, route := range routes {
		if route.Dev == r.Interface || route.Dst == "default" || route.Dst == "" || route.Dst == "0.0.0.0/0" {
			continue
		}
		dst := route.Dst
		if !strings.Contains(dst, "/") {
			dst += "/32"
		}
		prefix, e := netip.ParsePrefix(dst)
		if e != nil {
			return errors.New("invalid ip route response")
		}
		if prefix.Contains(local.Addr()) || prefix.Contains(peer.Addr()) {
			return errors.New("relay address overlaps an existing route")
		}
	}
	b, err = m.run(ctx, "wg", "show", "all", "listen-port")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			return errors.New("invalid WireGuard port response")
		}
		port, e := strconv.Atoi(fields[1])
		if e != nil {
			return errors.New("invalid WireGuard port response")
		}
		if fields[0] != r.Interface && port == r.Config.ListenPort {
			return errors.New("WireGuard listen port already in use")
		}
	}
	for id, other := range m.records {
		if id == r.Config.PairID || other.Phase == "removed" {
			continue
		}
		if other.Interface == r.Interface || other.Config.ListenPort == r.Config.ListenPort || other.Config.LocalAddress == r.Config.LocalAddress || other.Config.LocalAddress == r.Config.PeerAddress || other.Config.PeerAddress == r.Config.LocalAddress || other.Config.PeerAddress == r.Config.PeerAddress {
			return errors.New("relay conflicts with another managed pair")
		}
		if r.Config.Role == "entry" && other.Config.Role == "entry" && other.Config.EntryPort == r.Config.EntryPort {
			return errors.New("entry port conflicts with another managed pair")
		}
	}
	return nil
}
func (m *Manager) createInterface(ctx context.Context, r *record) error {
	exists, err := m.owned(ctx, r)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	// The single create operation installs the ownership alias atomically. A
	// crash cannot leave an unmarked link that cleanup would have to guess about.
	_, err = m.run(ctx, "ip", "link", "add", "name", r.Interface, "alias", r.alias(), "type", "wireguard")
	return err
}
func (m *Manager) configureKernel(ctx context.Context, r *record) error {
	if err := m.collisions(ctx, r); err != nil {
		return err
	}
	if err := m.createInterface(ctx, r); err != nil {
		return err
	}
	if _, err := m.run(ctx, "wg", "set", r.Interface, "private-key", m.keyPath(r.Config.PairID), "listen-port", strconv.Itoa(r.Config.ListenPort), "peer", r.Config.PeerPublicKey, "endpoint", r.Config.PeerEndpoint+":"+strconv.Itoa(r.Config.PeerPort), "allowed-ips", r.Config.PeerAddress, "persistent-keepalive", "25"); err != nil {
		return err
	}
	if _, err := m.run(ctx, "ip", "address", "replace", r.Config.LocalAddress, "dev", r.Interface); err != nil {
		return err
	}
	if _, err := m.run(ctx, "ip", "link", "set", "dev", r.Interface, "up"); err != nil {
		return err
	}
	// Never use route replace: that could overwrite an unrelated route.
	b, err := m.run(ctx, "ip", "-j", "-4", "route", "show", "exact", r.Config.PeerAddress)
	if err != nil {
		return err
	}
	var routes []struct {
		Dst string `json:"dst"`
		Dev string `json:"dev"`
	}
	if json.Unmarshal(b, &routes) != nil {
		return errors.New("invalid ip route response")
	}
	if len(routes) > 0 {
		for _, route := range routes {
			if route.Dev != r.Interface {
				return errors.New("peer route is not owned")
			}
		}
		return nil
	}
	_, err = m.run(ctx, "ip", "route", "add", r.Config.PeerAddress, "dev", r.Interface, "src", strings.TrimSuffix(r.Config.LocalAddress, "/32"))
	return err
}
func (m *Manager) cleanup(ctx context.Context, r *record) error {
	if p := m.proxies[r.Config.PairID]; p != nil {
		_ = p.close()
		delete(m.proxies, r.Config.PairID)
	}
	exists, err := m.owned(ctx, r)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	_, err = m.run(ctx, "ip", "link", "delete", "dev", r.Interface)
	return err
}
func (m *Manager) handshake(ctx context.Context, r *record) error {
	out, err := m.run(ctx, "wg", "show", r.Interface, "latest-handshakes")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || f[0] != r.Config.PeerPublicKey {
			continue
		}
		timestamp, e := strconv.ParseInt(f[1], 10, 64)
		if e == nil && timestamp > 0 {
			age := time.Since(time.Unix(timestamp, 0))
			if age >= -5*time.Second && age <= 3*time.Minute {
				return nil
			}
		}
	}
	return errors.New("WireGuard peer has no recent handshake")
}
