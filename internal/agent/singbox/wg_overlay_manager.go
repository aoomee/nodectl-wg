package singbox

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"time"
)

// ApplyWGRoute validates with the installed binary before replacing the config
// and stopping the owned process. The runtime must serialize this operation with
// its command mutex and own the topology lease. Success verifies process liveness
// only, not end-to-end connectivity through the remote Shadowsocks server.
func (m *Manager) ApplyWGRoute(ctx context.Context, route WGRoute) error {
	// A delayed command must not stop or fence a newer authorized configuration.
	if current, err := m.config.GetWGRoute(); err == nil && current != nil {
		if route.Revision < current.Revision || (route.PairID != current.PairID && current.Mode != "direct") {
			return errors.New("stale or unrelated WG route command")
		}
	}
	if err := m.config.SetWGRoute(route); err != nil {
		return errors.Join(err, m.failClosedWGRoute(route))
	}
	if err := m.applyWGConfig(ctx); err != nil {
		return errors.Join(err, m.failClosedWGRoute(route))
	}
	return nil
}

// FenceWGRoute removes live authorization and installs a scoped reject rule.
// Legacy/direct state is unchanged. A failure always stops the owned child.
func (m *Manager) FenceWGRoute(ctx context.Context) error {
	route, err := m.config.GetWGRoute()
	if err != nil {
		return errors.Join(err, m.Stop())
	}
	if route == nil || route.Mode == "direct" {
		return nil
	}
	route.Mode = "blocked"
	return m.ApplyWGRoute(ctx, *route)
}

func (m *Manager) checkWGConfig(ctx context.Context, data []byte) error {
	path, err := stagePrivateFile(m.configPath, data)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(checkCtx, m.binaryPath, "check", "-c", path)
	configureProcessGuard(cmd)
	// Do not surface binary output: invalid configuration diagnostics may contain
	// credentials. The caller receives only the exit/context error.
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sing-box candidate check failed: %w", err)
	}
	return nil
}

func (m *Manager) applyWGConfig(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := m.config.GenerateConfig()
	if err != nil {
		return err
	}
	if err := m.checkWGConfig(ctx, data); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := writePrivateAtomic(m.configPath, data); err != nil {
		return err
	}
	if err := m.Stop(); err != nil {
		return err
	}
	// Command deadlines must never own the process lifetime. Shutdown/Stop and the
	// Linux parent-death signal remain the lifecycle owners.
	if err := m.StartAndVerify(context.Background(), 2*time.Second); err != nil {
		return err
	}
	return ctx.Err()
}

// failClosedWGRoute never restores an old direct configuration. A failed direct
// release receives a new blocked revision, fencing the attempted release. If
// persistence, generation, validation or restart fails, leave the proxy stopped.
func (m *Manager) failClosedWGRoute(attempt WGRoute) error {
	if err := m.Stop(); err != nil {
		return err
	}
	cm := m.config
	cm.wgMu.Lock()
	cm.wgAuthorized = nil
	cm.wgMu.Unlock()
	current, err := cm.GetWGRoute()
	if err != nil {
		return err
	}
	if current != nil {
		attempt = *current
	}
	if attempt.Mode == "direct" {
		if attempt.Revision == math.MaxUint64 {
			return errors.New("cannot fence exhausted WG revision")
		}
		attempt.Revision++
	}
	attempt.Mode = "blocked"
	if err := cm.SetWGRoute(attempt); err != nil {
		return err
	}
	data, err := cm.GenerateConfig()
	if err != nil {
		return err
	}
	// Persist the reject config even when the installed binary is missing/broken;
	// no later start may reuse the old direct configuration.
	if err := writePrivateAtomic(m.configPath, data); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := m.checkWGConfig(ctx, data); err != nil {
		return err
	}
	if err := m.StartAndVerify(context.Background(), 2*time.Second); err != nil {
		return errors.Join(err, m.Stop())
	}
	return nil
}
