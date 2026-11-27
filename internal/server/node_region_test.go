package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"nodectl/internal/database"
)

func TestAPIUpdateNodeRegionOverride(t *testing.T) {
	wgTestDB(t)
	if err := database.DB.AutoMigrate(&database.WGPair{}, &database.WGPairNode{}); err != nil {
		t.Fatalf("migrate wg tables failed: %v", err)
	}

	node := database.NodePool{
		UUID:        "node-region-test-1",
		InstallID:   "instregion01",
		Name:        "001",
		RoutingType: 1,
		IPV4:        "203.0.113.10",
		Region:      "SC",
	}
	if err := database.DB.Create(&node).Error; err != nil {
		t.Fatalf("create node failed: %v", err)
	}

	callUpdate := func(payload map[string]any) {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/update-node", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		apiUpdateNode(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp["status"] != "success" {
			t.Fatalf("expected success response, got: %s", rec.Body.String())
		}
	}

	// 1. Manually override region from SC -> HK
	callUpdate(map[string]any{
		"uuid":            node.UUID,
		"name":            "001",
		"routing_type":    1,
		"ipv4":            "203.0.113.10",
		"region_override": "hk",
		"links":           map[string]string{},
	})

	var got database.NodePool
	if err := database.DB.First(&got, "uuid = ?", node.UUID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Region != "HK" || !got.RegionManual {
		t.Fatalf("expected Region=HK RegionManual=true, got Region=%q RegionManual=%v", got.Region, got.RegionManual)
	}

	// 2. Subsequent update omitting region_override must keep manual HK override intact
	callUpdate(map[string]any{
		"uuid":         node.UUID,
		"name":         "001-renamed",
		"routing_type": 1,
		"ipv4":         "203.0.113.10",
		"links":        map[string]string{},
	})
	if err := database.DB.First(&got, "uuid = ?", node.UUID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Region != "HK" || !got.RegionManual {
		t.Fatalf("omitting region_override must preserve manual region, got Region=%q RegionManual=%v", got.Region, got.RegionManual)
	}

	// 3. Clearing region_override switches back to auto mode
	callUpdate(map[string]any{
		"uuid":            node.UUID,
		"name":            "001-renamed",
		"routing_type":    1,
		"ipv4":            "203.0.113.10",
		"region_override": "",
		"links":           map[string]string{},
	})
	if err := database.DB.First(&got, "uuid = ?", node.UUID).Error; err != nil {
		t.Fatal(err)
	}
	if got.RegionManual {
		t.Fatalf("expected RegionManual=false after clearing override")
	}
}
