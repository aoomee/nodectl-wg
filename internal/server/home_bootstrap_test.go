package server

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"wirearc/internal/database"
)

func TestHomeBootstrapJSONContainsNodesTrafficAndMasksHTTP(t *testing.T) {
	wgTestDB(t)
	if err := database.DB.AutoMigrate(&database.NodeTrafficStat{}, &database.WGPair{}, &database.WGPairNode{}); err != nil {
		t.Fatalf("automigrate failed: %v", err)
	}

	now := time.Now().Truncate(time.Minute)
	n1 := database.NodePool{
		UUID:        "uuid-direct-1",
		InstallID:   "inst-direct-1",
		Name:        "001",
		Region:      "HK",
		RoutingType: 1,
		SortIndex:   1,
		TrafficUp:   2 * 1024 * 1024 * 1024,
		TrafficDown: 3 * 1024 * 1024 * 1024,
		Links:       map[string]string{"reality": "vless://secret@1.2.3.4:443"},
	}
	n2 := database.NodePool{
		UUID:        "uuid-land-2",
		InstallID:   "inst-land-2",
		Name:        "002",
		Region:      "HK",
		RoutingType: 2,
		SortIndex:   2,
		TrafficUp:   8 * 1024 * 1024 * 1024,
		TrafficDown: 9 * 1024 * 1024 * 1024,
		Links:       map[string]string{"ss": "ss://secret@5.6.7.8:8388"},
	}
	if err := database.DB.Create(&n1).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.DB.Create(&n2).Error; err != nil {
		t.Fatal(err)
	}
	dayKey := now.Year()*10000 + int(now.Month())*100 + now.Day()
	hourKey := now.Year()*1000000 + int(now.Month())*10000 + now.Day()*100 + now.Hour()
	twoHourKey := now.Year()*1000000 + int(now.Month())*10000 + now.Day()*100 + (now.Hour()/2)*2
	if err := database.DB.Create(&database.NodeTrafficStat{
		NodeUUID:   n2.UUID,
		ReportedAt: now,
		HourKey:    hourKey,
		TwoHourKey: twoHourKey,
		DayKey:     dayKey,
		TXBytes:    500 * 1024 * 1024,
		RXBytes:    600 * 1024 * 1024,
	}).Error; err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	raw := buildHomeBootstrapJSON(req, []database.NodePool{n1, n2})

	var decoded struct {
		Nodes struct {
			DirectNodes []database.NodePool `json:"direct_nodes"`
			LandNodes   []database.NodePool `json:"land_nodes"`
		} `json:"nodes"`
		Traffic struct {
			Date             string `json:"date"`
			SelectedNodeUUID string `json:"selected_node_uuid"`
			Rank             struct {
				Items []struct {
					UUID            string `json:"uuid"`
					TodayTotalBytes int64  `json:"today_total_bytes"`
					LiveTotalBytes  int64  `json:"live_total_bytes"`
					HasLiveTotal    bool   `json:"has_live_total"`
				} `json:"items"`
			} `json:"rank"`
		} `json:"traffic"`
	}
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("failed to parse bootstrap JSON: %v", err)
	}

	if len(decoded.Nodes.DirectNodes) != 1 || len(decoded.Nodes.LandNodes) != 1 {
		t.Fatalf("unexpected node split: direct=%d land=%d", len(decoded.Nodes.DirectNodes), len(decoded.Nodes.LandNodes))
	}
	if got := decoded.Nodes.DirectNodes[0].Links["reality"]; got == "vless://secret@1.2.3.4:443" {
		t.Fatalf("expected HTTP bootstrap node links to be masked, got raw secret")
	}
	if decoded.Traffic.SelectedNodeUUID != n2.UUID {
		t.Fatalf("expected highest live-total node %q selected, got %q", n2.UUID, decoded.Traffic.SelectedNodeUUID)
	}
	if len(decoded.Traffic.Rank.Items) != 2 {
		t.Fatalf("expected 2 rank items, got %d", len(decoded.Traffic.Rank.Items))
	}
	for _, it := range decoded.Traffic.Rank.Items {
		if !it.HasLiveTotal || it.LiveTotalBytes <= 0 {
			t.Fatalf("expected HasLiveTotal=true and LiveTotalBytes>0 for %s, got %+v", it.UUID, it)
		}
		if it.UUID == n2.UUID && it.TodayTotalBytes != 1100*1024*1024 {
			t.Fatalf("expected today delta 1100MiB for n2, got %d", it.TodayTotalBytes)
		}
	}
}
