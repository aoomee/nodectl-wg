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

func TestAPIUpdateNodeRegionAllowedDuringActiveWGPair(t *testing.T) {
	wgTestDB(t)
	if err := database.DB.AutoMigrate(&database.WGPair{}, &database.WGPairNode{}); err != nil {
		t.Fatalf("migrate wg tables failed: %v", err)
	}

	node := database.NodePool{
		UUID:        "node-wg-region-1",
		InstallID:   "instwgreg01",
		Name:        "001",
		RoutingType: 1,
		IPV4:        "203.0.113.11",
		Region:      "SC",
	}
	if err := database.DB.Create(&node).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.DB.Create(&database.WGPairNode{
		PairID:   "pair-active-1",
		NodeUUID: node.UUID,
	}).Error; err != nil {
		t.Fatal(err)
	}

	// 1. Ordinary /api/update-node remains blocked while WG pair is active.
	ordBody, _ := json.Marshal(map[string]any{
		"uuid":            node.UUID,
		"name":            "001",
		"routing_type":    1,
		"ipv4":            "203.0.113.11",
		"region_override": "HK",
		"links":           map[string]string{},
	})
	ordReq := httptest.NewRequest(http.MethodPost, "/api/update-node", bytes.NewReader(ordBody))
	ordRec := httptest.NewRecorder()
	apiUpdateNode(ordRec, ordReq)
	var ordResp map[string]any
	if err := json.Unmarshal(ordRec.Body.Bytes(), &ordResp); err != nil || ordResp["status"] != "error" {
		t.Fatalf("expected /api/update-node blocked during active WG pair, got: %s", ordRec.Body.String())
	}

	// 2. Dedicated /api/node/region succeeds immediately without pausing WG.
	regBody, _ := json.Marshal(map[string]any{
		"uuid":            node.UUID,
		"region_override": "hk",
	})
	regReq := httptest.NewRequest(http.MethodPost, "/api/node/region", bytes.NewReader(regBody))
	regRec := httptest.NewRecorder()
	apiUpdateNodeRegion(regRec, regReq)
	if regRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", regRec.Code, regRec.Body.String())
	}
	var regResp map[string]any
	if err := json.Unmarshal(regRec.Body.Bytes(), &regResp); err != nil || regResp["status"] != "success" {
		t.Fatalf("expected /api/node/region success during active WG pair, got: %s", regRec.Body.String())
	}

	var got database.NodePool
	if err := database.DB.First(&got, "uuid = ?", node.UUID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Region != "HK" || !got.RegionManual {
		t.Fatalf("expected Region=HK RegionManual=true, got Region=%q RegionManual=%v", got.Region, got.RegionManual)
	}
}
