package agent

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"nodectl/internal/agent/singbox"
	"nodectl/internal/agent/wgrelay"
)

type wgV2Request struct {
	PairID                string `json:"pair_id"`
	Revision              uint64 `json:"revision"`
	Method                string `json:"method,omitempty"`
	Password              string `json:"password,omitempty"`
	Port                  int    `json:"port,omitempty"`
	SSDigest              string `json:"ss_digest,omitempty"`
	ExpectedRealityDigest string `json:"expected_reality_digest,omitempty"`
}

func decodeWGV2(raw json.RawMessage) (wgV2Request, error) {
	var p wgV2Request
	if len(raw) > 8192 {
		return p, errors.New("invalid WG payload")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF {
		return p, errors.New("invalid WG payload")
	}
	id, e := hex.DecodeString(p.PairID)
	if e != nil || len(id) < 8 || len(id) > 16 || hex.EncodeToString(id) != p.PairID || p.Revision == 0 {
		return p, errors.New("invalid WG identity")
	}
	return p, nil
}
func (rt *Runtime) stopWGRouteLease() {
	rt.wgLeaseGeneration++
	if rt.wgRouteLease != nil {
		rt.wgRouteLease.Stop()
		rt.wgRouteLease = nil
	}
}
func (rt *Runtime) renewWGRouteLease() {
	rt.stopWGRouteLease()
	generation := rt.wgLeaseGeneration
	rt.wgRouteLease = time.AfterFunc(90*time.Second, func() {
		rt.commandMu.Lock()
		defer rt.commandMu.Unlock()
		if generation != rt.wgLeaseGeneration {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if rt.singboxMgr != nil {
			_ = rt.singboxMgr.FenceWGRoute(ctx)
		}
	})
}

// Called only over authenticated v2 transport under commandMu. Credentials never
// reach ordinary command logs; public replies contain only digests and status.
func (rt *Runtime) executeWGV2(ctx context.Context, cmd ServerCommand) (json.RawMessage, error) {
	p, err := decodeWGV2(cmd.Payload)
	if err != nil {
		return nil, err
	}
	rt.ensureSingboxManager()
	cm := rt.singboxMgr.GetConfigManager()
	status := wgrelay.Status{PairID: p.PairID, Revision: p.Revision, Role: "entry"}
	base := wgrelay.Payload{PairID: p.PairID, Revision: p.Revision}
	raw, _ := json.Marshal(base)
	switch cmd.Action {
	case "wg-v2-ss":
		if !rt.singboxMgr.Status().Running {
			return nil, errors.New("SS runtime is not running")
		}
		credentials, digest, e := cm.SSConfigCredentials()
		if e != nil {
			return nil, e
		}
		return json.Marshal(struct {
			Method   string `json:"method"`
			Password string `json:"password"`
			Port     int    `json:"port"`
			Digest   string `json:"digest"`
		}{credentials.Method, credentials.Password, credentials.Port, digest})
	case "wg-v2-guard", "wg-v2-block":
		rt.stopWGRouteLease()
		route, e := cm.GetWGRoute()
		if e != nil {
			return nil, e
		}
		next := singbox.WGRoute{PairID: p.PairID, Revision: p.Revision, Mode: "blocked"}
		if route != nil && route.PairID == p.PairID {
			next = *route
			next.Revision = p.Revision
			next.Mode = "blocked"
		}
		if err = rt.singboxMgr.ApplyWGRoute(ctx, next); err != nil {
			return nil, err
		}
		status.Phase = "blocked"
		if cmd.Action == "wg-v2-guard" {
			status.Phase = "guarded"
		}
		status.SourceDigest = cm.RealityConfigDigest()
	case "wg-v2-direct":
		rt.stopWGRouteLease()
		if rt.wgManager == nil {
			return nil, errors.New("WG cleanup acknowledgement required")
		}
		b, e := rt.wgManager.Execute(ctx, "wg-status", raw)
		if e != nil {
			return nil, e
		}
		var s wgrelay.Status
		if json.Unmarshal(b, &s) != nil || s.Phase != "removed" || s.Revision != p.Revision {
			return nil, errors.New("WG cleanup incomplete")
		}
		if err = rt.singboxMgr.ApplyWGRoute(ctx, singbox.WGRoute{PairID: p.PairID, Revision: p.Revision, Mode: "direct"}); err != nil {
			return nil, err
		}
		status.Phase = "direct"
	case "wg-v2-route", "wg-v2-status":
		if rt.wgManager == nil {
			return nil, errors.New("WG is not configured")
		}
		route, e := cm.GetWGRoute()
		if e != nil {
			return nil, e
		}
		if route == nil || route.PairID != p.PairID || route.Revision != p.Revision {
			return nil, errors.New("missing matching REALITY guard")
		}
		if cmd.Action == "wg-v2-status" && (route.Mode != "active" || !cm.WGRouteAuthorized(p.PairID, p.Revision) || !rt.singboxMgr.Status().Running) {
			return nil, errors.New("WG REALITY route inactive")
		}
		if p.ExpectedRealityDigest != "" && cm.RealityConfigDigest() != p.ExpectedRealityDigest {
			return nil, errors.New("REALITY configuration changed")
		}
		if _, err = rt.wgManager.Execute(ctx, "wg-verify", raw); err != nil {
			rt.stopWGRouteLease()
			_ = rt.singboxMgr.FenceWGRoute(ctx)
			return nil, err
		}
		device, server, port, e := rt.wgManager.RouteTarget(p.PairID, p.Revision)
		if e != nil {
			return nil, e
		}
		if cmd.Action == "wg-v2-route" {
			if p.Port != port || p.SSDigest == "" || p.ExpectedRealityDigest == "" {
				return nil, errors.New("SS or REALITY dependency mismatch")
			}
			next := singbox.WGRoute{PairID: p.PairID, Revision: p.Revision, Mode: "active", Interface: device, Server: server, Port: port, Method: p.Method, Password: p.Password, SourceDigest: p.ExpectedRealityDigest}
			if err = rt.singboxMgr.ApplyWGRoute(ctx, next); err != nil {
				return nil, err
			}
		} else if route.Interface != device || route.Server != server || route.Port != port || route.SourceDigest != cm.RealityConfigDigest() {
			rt.stopWGRouteLease()
			_ = rt.singboxMgr.FenceWGRoute(ctx)
			return nil, errors.New("active route dependency changed")
		}
		rt.renewWGRouteLease()
		status.Phase = "active"
		status.RouteActive = true
		status.TargetTCPVerified = true
		status.Interface = device
		status.SourceDigest = cm.RealityConfigDigest()
	default:
		return nil, errors.New("unknown v2 command")
	}
	return json.Marshal(status)
}
