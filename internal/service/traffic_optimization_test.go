package service

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
	"nhooyr.io/websocket"
	"nodectl/internal/database"
)

func setupTrafficTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	old := database.DB
	dsn := filepath.Join(t.TempDir(), "traffic.db") + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&database.NodePool{}, &database.NodeTrafficStat{}, &database.SysConfig{}); err != nil {
		t.Fatal(err)
	}
	database.DB = db
	t.Cleanup(func() {
		database.DB = old
		_ = sqlDB.Close()
	})
	return db
}

func TestBatchTrafficSaveRankAndBatchedDelete(t *testing.T) {
	db := setupTrafficTestDB(t)

	n1 := database.NodePool{UUID: "u-1", InstallID: "inst-1", Name: "Node 1", RoutingType: 2}
	n2 := database.NodePool{UUID: "u-2", InstallID: "inst-2", Name: "Node 2", RoutingType: 2}
	if err := db.Create(&n1).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&n2).Error; err != nil {
		t.Fatal(err)
	}

	now := time.Now().Truncate(time.Minute)
	if err := SaveNodeTrafficTotalsBatch([]TrafficBatchItem{
		{InstallID: "inst-1", RXBytes: 1000, TXBytes: 500},
		{InstallID: "inst-2", RXBytes: 3000, TXBytes: 2000},
	}, now); err != nil {
		t.Fatalf("SaveNodeTrafficTotalsBatch failed: %v", err)
	}

	var got1, got2 database.NodePool
	db.First(&got1, "uuid = ?", "u-1")
	db.First(&got2, "uuid = ?", "u-2")
	if got1.TrafficDown != 1000 || got1.TrafficUp != 500 || got2.TrafficDown != 3000 || got2.TrafficUp != 2000 {
		t.Fatalf("unexpected totals: got1=(%d,%d) got2=(%d,%d)", got1.TrafficDown, got1.TrafficUp, got2.TrafficDown, got2.TrafficUp)
	}

	// Write two sample points for today so consumption rank computes deltas via day_key index.
	t1 := now.Add(-10 * time.Minute)
	if t1.Day() != now.Day() {
		t1 = now
	}
	if err := SaveNodeTrafficPointsBatch([]TrafficBatchItem{
		{InstallID: "inst-1", RXBytes: 1000, TXBytes: 500},
		{InstallID: "inst-2", RXBytes: 3000, TXBytes: 2000},
	}, t1); err != nil {
		t.Fatalf("first SaveNodeTrafficPointsBatch failed: %v", err)
	}
	if err := SaveNodeTrafficPointsBatch([]TrafficBatchItem{
		{InstallID: "inst-1", RXBytes: 1500, TXBytes: 800},
		{InstallID: "inst-2", RXBytes: 4000, TXBytes: 2500},
	}, now); err != nil {
		t.Fatalf("second SaveNodeTrafficPointsBatch failed: %v", err)
	}

	rank, err := GetTrafficConsumptionRank(10, now.Format("2006-01-02"))
	if err != nil {
		t.Fatalf("GetTrafficConsumptionRank failed: %v", err)
	}
	if len(rank.Items) != 2 || rank.Items[0].UUID != "u-2" || rank.Items[0].TotalBytes != 6500 {
		t.Fatalf("unexpected rank result: %+v", rank.Items)
	}

	// Verify DeleteNodeTrafficStatsBatched deletes in batches smaller than total count cleanly.
	deleted, err := database.DeleteNodeTrafficStatsBatched("u-1", 1)
	if err != nil {
		t.Fatalf("DeleteNodeTrafficStatsBatched failed: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("expected 2 deleted rows for u-1, got %d", deleted)
	}
	var remaining int64
	db.Model(&database.NodeTrafficStat{}).Where("node_uuid = ?", "u-2").Count(&remaining)
	if remaining != 2 {
		t.Fatalf("expected u-2 rows untouched (2), got %d", remaining)
	}
}

func TestTrafficHubUnsubscribeAfterCleanupDoesNotPanic(t *testing.T) {
	hub := &TrafficHub{
		nodes:       make(map[string]*NodeLiveState),
		idCache:     make(map[string]string),
		subscribers: make(map[string]map[chan FrontendPushMsg]struct{}),
		agentConns:  make(map[string]*websocket.Conn),
	}
	ch := make(chan FrontendPushMsg, 1)
	hub.subscribe("node-a", ch)

	// Simulate CleanupNodeState closing and removing subscribers for node-a.
	hub.subMu.Lock()
	for sub := range hub.subscribers["node-a"] {
		close(sub)
	}
	delete(hub.subscribers, "node-a")
	hub.subMu.Unlock()

	// Deferred unsubscribe from HandleTrafficLive must not double-close ch.
	hub.unsubscribe("node-a", ch)
}
