package wgrelay

import (
	"errors"
	"strings"
)

// RouteTarget exposes only owned tunnel routing, never keys. A v2 runtime cannot
// ask the sing-box overlay to dial a caller-supplied public SS address.
func (m *Manager) RouteTarget(id string, revision uint64) (device, server string, port int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return "", "", 0, ErrClosed
	}
	r := m.records[id]
	if r == nil || r.Config.Revision != revision || r.Config.Topology != "reality_ss_v2" || r.Config.Role != "entry" || r.Phase != "verified" || !r.TargetVerified {
		return "", "", 0, errors.New("verified v2 entry tunnel required")
	}
	return r.Interface, strings.TrimSuffix(r.Config.PeerAddress, "/32"), r.Config.TargetPort, nil
}
