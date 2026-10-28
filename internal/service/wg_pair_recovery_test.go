package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"nodectl/internal/agent/wgrelay"
	"nodectl/internal/database"
)

func TestWGRestartRevalidatesLivePairWithoutActivation(t *testing.T) {
	c, f := newWGTest(t)
	p := createWG(t, c)
	wgSteps(t, c, p.ID, 8)
	before := len(f.calls)
	if err := c.recover(); err != nil {
		t.Fatal(err)
	}
	row := wgStored(t, c, p.ID)
	if row.Status != "recovering" || row.RecoveryDeadline.IsZero() || !row.HealthCheckedAt.IsZero() {
		t.Fatal(wgDTO(row))
	}
	if len(c.subscriptionLinks(0)) != 0 || c.realitySubscriptionAllowed("entry") {
		t.Fatal("persisted active published before live proof")
	}
	wgSteps(t, c, p.ID, 1)
	if got := fmt.Sprint(f.calls[before:]); got != "[bbbbbbbbbbbb:wg-v2-ss bbbbbbbbbbbb:wg-verify aaaaaaaaaaaa:wg-v2-status]" {
		t.Fatal(got)
	}
	row = wgStored(t, c, p.ID)
	if row.Status != "active" || !row.RecoveryDeadline.IsZero() || len(c.subscriptionLinks(0)) != 1 || row.RestoreDirect {
		t.Fatal("live pair not recovered")
	}
}

func TestWGRecoveryWaitsForReconnectWithoutExtendingDeadline(t *testing.T) {
	c, f := newWGTest(t)
	p := createWG(t, c)
	wgSteps(t, c, p.ID, 8)
	if err := c.recover(); err != nil {
		t.Fatal(err)
	}
	deadline := wgStored(t, c, p.ID).RecoveryDeadline
	f.offline["aaaaaaaaaaaa"] = true
	before := len(f.calls)
	wgSteps(t, c, p.ID, 1)
	row := wgStored(t, c, p.ID)
	if row.Status != "recovering" || len(f.calls) != before || len(c.subscriptionLinks(0)) != 0 {
		t.Fatal("offline recovery issued commands or published")
	}
	now := row.NextRetryAt.Add(time.Second)
	c.now = func() time.Time { return now }
	if err := c.recover(); err != nil {
		t.Fatal(err)
	}
	if !wgStored(t, c, p.ID).RecoveryDeadline.Equal(deadline) {
		t.Fatal("restart extended recovery deadline")
	}
	f.offline["aaaaaaaaaaaa"] = false
	wgSteps(t, c, p.ID, 1)
	if wgStored(t, c, p.ID).Status != "active" {
		t.Fatal("reconnected pair not recovered")
	}
}

func TestWGRecoveryFailureKeepsFailClosed(t *testing.T) {
	for _, change := range []string{"expired", "revoked", "ss", "reality-digest", "landing-key", "inactive-agent", "bad-revision", "reservation"} {
		t.Run(change, func(t *testing.T) {
			c, f := newWGTest(t)
			p := createWG(t, c)
			wgSteps(t, c, p.ID, 8)
			if err := c.recover(); err != nil {
				t.Fatal(err)
			}
			before := len(f.calls)
			switch change {
			case "expired":
				now := wgStored(t, c, p.ID).RecoveryDeadline
				c.now = func() time.Time { return now }
				f.offline["aaaaaaaaaaaa"] = true
			case "revoked":
				c.db.Model(&database.AgentIdentity{}).Where("node_uuid = ?", "entry").Update("secret_hash", "")
			case "ss":
				f.ssDigest = "changed"
			case "reality-digest":
				s := f.states["aaaaaaaaaaaa"]
				s.SourceDigest = "changed"
				f.states["aaaaaaaaaaaa"] = s
			case "landing-key":
				s := f.states["bbbbbbbbbbbb"]
				s.PublicKey = "changed"
				f.states["bbbbbbbbbbbb"] = s
			case "inactive-agent":
				f.badRoute = true
			case "bad-revision":
				f.badRevision = true
			case "reservation":
				c.db.Model(&database.WGPairNode{}).Where("node_uuid = ?", "landing").Update("pair_id", "different-pair")
			}
			wgSteps(t, c, p.ID, 1)
			row := wgStored(t, c, p.ID)
			if row.Status != "cleanup_pending" || row.Phase != "block_a" || row.RestoreDirect || len(c.subscriptionLinks(0)) != 0 || c.realitySubscriptionAllowed("entry") {
				t.Fatal(wgDTO(row))
			}
			for _, call := range f.calls[before:] {
				if strings.HasSuffix(call, "wg-v2-route") || strings.HasSuffix(call, "wg-v2-direct") {
					t.Fatal("recovery reopened routing")
				}
			}
			var count int64
			c.db.Model(&database.WGPairNode{}).Count(&count)
			if count != 2 {
				t.Fatal("failure released reservations")
			}
		})
	}
}

func TestWGRecoveryFencesPreviousCoordinatorWork(t *testing.T) {
	c, f := newWGTest(t)
	p := createWG(t, c)
	wgSteps(t, c, p.ID, 8)
	c.send = func(ctx context.Context, id, action string, v interface{}) (json.RawMessage, error) {
		result, err := f.send(ctx, id, action, v)
		if action == "wg-v2-status" {
			if e := c.recover(); e != nil {
				return nil, e
			}
		}
		return result, err
	}
	if err := c.step(context.Background(), p.ID); err != ErrWGConflict {
		t.Fatalf("previous generation result=%v", err)
	}
	if row := wgStored(t, c, p.ID); row.Status != "recovering" || len(c.subscriptionLinks(0)) != 0 {
		t.Fatal("old coordinator published into recovery")
	}
	c.send = f.send
	wgSteps(t, c, p.ID, 1)
	if wgStored(t, c, p.ID).Status != "active" {
		t.Fatal("new generation could not verify")
	}
}

func TestWGRecoveryCannotConfirmAfterDeadline(t *testing.T) {
	c, f := newWGTest(t)
	p := createWG(t, c)
	wgSteps(t, c, p.ID, 8)
	if err := c.recover(); err != nil {
		t.Fatal(err)
	}
	deadline := wgStored(t, c, p.ID).RecoveryDeadline
	c.send = func(ctx context.Context, id, action string, v interface{}) (json.RawMessage, error) {
		result, err := f.send(ctx, id, action, v)
		if action == "wg-v2-status" {
			c.now = func() time.Time { return deadline }
		}
		return result, err
	}
	wgSteps(t, c, p.ID, 1)
	if wgStored(t, c, p.ID).Status != "cleanup_pending" || len(c.subscriptionLinks(0)) != 0 {
		t.Fatal("late recovery proof accepted")
	}
}

func TestWGRecoveryRejectsIncompleteActiveProof(t *testing.T) {
	for _, field := range []string{"reality_digest", "ss_digest", "peer_public_key", "applied_revision"} {
		t.Run(field, func(t *testing.T) {
			c, _ := newWGTest(t)
			p := createWG(t, c)
			wgSteps(t, c, p.ID, 8)
			var value interface{} = ""
			if field == "applied_revision" {
				value = 0
			}
			if err := c.db.Model(&database.WGPair{}).Where("id = ?", p.ID).Update(field, value).Error; err != nil {
				t.Fatal(err)
			}
			if err := c.recover(); err != nil {
				t.Fatal(err)
			}
			if row := wgStored(t, c, p.ID); row.Status != "cleanup_pending" || row.RestoreDirect {
				t.Fatal("incomplete proof recovered")
			}
		})
	}
}

func TestWGHealthProofRemainsAvailableWhileCheckIsPending(t *testing.T) {
	c, f := newWGTest(t)
	p := createWG(t, c)
	wgSteps(t, c, p.ID, 8)
	c.send = func(ctx context.Context, id, action string, v interface{}) (json.RawMessage, error) {
		if action == "wg-v2-ss" && len(c.subscriptionLinks(0)) != 1 {
			t.Error("health poll hid a fresh confirmed route")
		}
		return f.send(ctx, id, action, v)
	}
	wgSteps(t, c, p.ID, 1)
	// The old proof still expires even if the next remote operation has not finished.
	now := wgStored(t, c, p.ID).HealthCheckedAt.Add(31 * time.Second)
	c.now = func() time.Time { return now }
	if len(c.subscriptionLinks(0)) != 0 {
		t.Fatal("stale health proof published")
	}
}

func TestWGRouteStatusRequiresStoredRealityDigest(t *testing.T) {
	c, f := newWGTest(t)
	p := createWG(t, c)
	wgSteps(t, c, p.ID, 7)
	c.send = func(ctx context.Context, id, action string, v interface{}) (json.RawMessage, error) {
		b, err := f.send(ctx, id, action, v)
		if action == "wg-v2-route" {
			var s wgrelay.Status
			_ = json.Unmarshal(b, &s)
			s.SourceDigest = "wrong"
			b, _ = json.Marshal(s)
		}
		return b, err
	}
	wgSteps(t, c, p.ID, 1)
	if wgStored(t, c, p.ID).Status != "cleanup_pending" {
		t.Fatal("wrong source digest activated")
	}
}
