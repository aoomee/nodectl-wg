package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nodectl/internal/database"
)

func awaitWG(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal(what)
	}
}

func TestWGSlowCommandAllowsReadsAndDisable(t *testing.T) {
	c, f := newWGTest(t)
	p := createWG(t, c)
	wgSteps(t, c, p.ID, 7) // Next command activates A after fetching canonical SS.
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	var calls atomic.Int32
	c.send = func(ctx context.Context, id, action string, payload interface{}) (json.RawMessage, error) {
		if action == "wg-v2-route" {
			calls.Add(1)
			close(entered)
			// Model a success reply already in transit when cancellation arrives.
			<-release
		}
		return f.send(ctx, id, action, payload)
	}
	done := make(chan error, 1)
	go func() { done <- c.step(context.Background(), p.ID) }()
	awaitWG(t, entered, "activation did not start")
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _ = c.options("entry")
		_ = c.subscriptionLinks(0)
		_ = c.realitySubscriptionAllowed("entry")
	}()
	awaitWG(t, readDone, "slow agent blocked panel reads")
	// A second dispatcher cannot execute the same pair concurrently.
	if err := c.step(context.Background(), p.ID); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("duplicate activation")
	}
	stopDone := make(chan struct{})
	var stopErr error
	go func() {
		defer close(stopDone)
		_, stopErr = c.save(context.Background(), WGPairPush{UUID: "entry", Revision: 2, Enabled: false})
	}()
	awaitWG(t, stopDone, "slow agent blocked explicit disable")
	if stopErr != nil {
		t.Fatal(stopErr)
	}
	// The source is still waiting: disable must already be durable and hidden.
	if row := wgStored(t, c, p.ID); row.DesiredRevision != 2 || row.Enabled || row.Phase != "block_a" {
		t.Fatal(wgDTO(row))
	}
	if len(c.subscriptionLinks(0)) != 0 {
		t.Fatal("disabled link published")
	}
	release <- struct{}{}
	select {
	case err := <-done:
		if !errors.Is(err, ErrWGConflict) {
			t.Fatalf("stale completion=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("completion blocked")
	}
	if row := wgStored(t, c, p.ID); row.DesiredRevision != 2 || row.Status != "cleanup_pending" || !row.RestoreDirect {
		t.Fatal("old completion overwrote disable")
	}
	wgSteps(t, c, p.ID, 4)
	if !c.realitySubscriptionAllowed("entry") {
		t.Fatal("explicit cleanup did not finish")
	}
}

func TestWGDisableCancelsInflightRequest(t *testing.T) {
	c, _ := newWGTest(t)
	p := createWG(t, c)
	entered := make(chan struct{})
	cancelled := make(chan struct{})
	c.send = func(ctx context.Context, _, _ string, _ interface{}) (json.RawMessage, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	}
	done := make(chan error, 1)
	go func() { done <- c.step(context.Background(), p.ID) }()
	awaitWG(t, entered, "command did not start")
	if _, err := c.save(context.Background(), WGPairPush{UUID: "entry", Revision: 2}); err != nil {
		t.Fatal(err)
	}
	awaitWG(t, cancelled, "disable did not cancel request")
	if err := <-done; !errors.Is(err, ErrWGConflict) {
		t.Fatalf("completion=%v", err)
	}
}

func TestWGRevokeDuringCommandCannotPublish(t *testing.T) {
	c, f := newWGTest(t)
	p := createWG(t, c)
	wgSteps(t, c, p.ID, 7)
	c.send = func(ctx context.Context, id, action string, v interface{}) (json.RawMessage, error) {
		result, err := f.send(ctx, id, action, v)
		if action == "wg-v2-route" {
			if e := c.db.Model(&database.AgentIdentity{}).Where("node_uuid = ?", "entry").Update("secret_hash", "").Error; e != nil {
				return nil, e
			}
		}
		return result, err
	}
	wgSteps(t, c, p.ID, 1)
	if wgStored(t, c, p.ID).Status != "cleanup_pending" || len(c.subscriptionLinks(0)) != 0 {
		t.Fatal("revoked identity activated")
	}
}

func TestWGShutdownDuringCommitValidationPreservesIntent(t *testing.T) {
	c, f := newWGTest(t)
	p := createWG(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	replied := false
	c.send = func(ctx context.Context, id, action string, v interface{}) (json.RawMessage, error) {
		result, err := f.send(ctx, id, action, v)
		replied = true
		return result, err
	}
	c.ready = func(id string) bool {
		if replied {
			cancel()
		}
		return f.ready(id)
	}
	if err := c.step(ctx, p.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("shutdown result=%v", err)
	}
	if row := wgStored(t, c, p.ID); row.Status != "pending" || row.Phase != "guard_a" {
		t.Fatal("shutdown persisted an interrupted transition")
	}
}

func addWGPair(t *testing.T, c *wgPairCoordinator, index int) WGPairDTO {
	t.Helper()
	for _, role := range []string{"entry", "landing"} {
		var source database.NodePool
		if err := c.db.First(&source, "uuid = ?", role).Error; err != nil {
			t.Fatal(err)
		}
		source.UUID = fmt.Sprintf("%s-%d", role, index)
		prefix := "c"
		offset := 0
		if role == "landing" {
			prefix = "d"
			offset = 1
		}
		source.InstallID = fmt.Sprintf("%s%011d", prefix, index)
		source.IPV4 = fmt.Sprintf("198.51.100.%d", 10+index*2+offset)
		if err := c.db.Create(&source).Error; err != nil {
			t.Fatal(err)
		}
		if err := c.db.Create(&database.AgentIdentity{NodeUUID: source.UUID, InstallID: source.InstallID, Bound: true, SecretHash: strings.Repeat(prefix, 64)}).Error; err != nil {
			t.Fatal(err)
		}
	}
	p, err := c.save(context.Background(), WGPairPush{UUID: fmt.Sprintf("entry-%d", index), PeerUUID: fmt.Sprintf("landing-%d", index), Revision: 1, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWGDispatcherIsolatesSlowPairAndStopsWorkers(t *testing.T) {
	c, f := newWGTest(t)
	slow := createWG(t, c)
	fast := addWGPair(t, c, 1)
	c.now = time.Now
	entered, fastDone := make(chan struct{}), make(chan struct{})
	var active, maxActive atomic.Int32
	c.send = func(ctx context.Context, id, action string, v interface{}) (json.RawMessage, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := maxActive.Load(); n > old; old = maxActive.Load() {
			if maxActive.CompareAndSwap(old, n) {
				break
			}
		}
		if id == "aaaaaaaaaaaa" {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		result, err := f.send(ctx, id, action, v)
		if action == "wg-v2-route" {
			close(fastDone)
		}
		return result, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); c.run(ctx, 5*time.Millisecond, 2) }()
	t.Cleanup(func() { cancel(); awaitWG(t, done, "workers did not stop") })
	awaitWG(t, entered, "slow pair not scheduled")
	awaitWG(t, fastDone, "slow pair blocked healthy pair")
	cancel()
	awaitWG(t, done, "dispatcher did not join workers")
	if active.Load() != 0 || maxActive.Load() > 2 {
		t.Fatalf("workers active=%d peak=%d", active.Load(), maxActive.Load())
	}
	if row := wgStored(t, c, slow.ID); row.Status != "pending" || row.Phase != "guard_a" {
		t.Fatal("shutdown changed interrupted intent")
	}
	// Cancellation may arrive after the remote activation but before commit;
	// either state must remain fenced until it is acknowledged/rechecked.
	row := wgStored(t, c, fast.ID)
	if row.Status != "active" && row.Phase != "activate_a" {
		t.Fatal(wgDTO(row))
	}
}
