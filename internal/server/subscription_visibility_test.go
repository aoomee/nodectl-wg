package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wirearc/internal/database"
	"wirearc/internal/service"
)

func TestSubscriptionHidesLandingByDefaultAllowsSelectionAndRename(t *testing.T) {
	wgTestDB(t)
	if err := database.DB.AutoMigrate(&database.WGPair{}, &database.WGPairNode{}, &database.AirportNode{}, &database.CustomNode{}); err != nil {
		t.Fatalf("migrate tables: %v", err)
	}

	directNode := database.NodePool{
		UUID:        "direct-1",
		InstallID:   "dir111111111",
		Name:        "香港直连",
		Region:      "HK",
		RoutingType: 1,
		IPV4:        "198.51.100.10",
		Links: map[string]string{
			"reality": "vless://11111111-2222-4333-8444-555555555555@198.51.100.10:443?security=reality&type=tcp&sni=example.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=1234#raw",
		},
	}
	landingNode := database.NodePool{
		UUID:        "landing-1",
		InstallID:   "lan222222222",
		Name:        "美国落地",
		Region:      "US",
		RoutingType: 2,
		IPV4:        "198.51.100.20",
		Links: map[string]string{
			"ss": "ss://YWVzLTI1Ni1nY206c2VjcmV0@198.51.100.20:8388#landing",
		},
	}
	if err := database.DB.Create(&directNode).Error; err != nil {
		t.Fatalf("create direct node: %v", err)
	}
	if err := database.DB.Create(&landingNode).Error; err != nil {
		t.Fatalf("create landing node: %v", err)
	}

	hasSSLine := func(text string) bool {
		for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "ss://") {
				return true
			}
		}
		return false
	}

	// 1. 默认 V2Ray 订阅：仅含直连节点，自动隐藏落地节点
	raw, err := service.GenerateV2RaySubBase64(false)
	if err != nil {
		t.Fatalf("GenerateV2RaySubBase64 failed: %v", err)
	}
	decodedBytes, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	decoded := string(decodedBytes)
	if !strings.Contains(decoded, "vless://") {
		t.Fatalf("expected direct reality link in default V2Ray sub, got: %s", decoded)
	}
	if hasSSLine(decoded) {
		t.Fatalf("expected landing node to be hidden by default in V2Ray sub, got: %s", decoded)
	}

	// 2. 通过 /api/sub/visibility 显式勾选落地节点并隐藏直连节点
	visBody, _ := json.Marshal(map[string]interface{}{
		"node_overrides": map[string]bool{
			"direct-1":  false,
			"landing-1": true,
		},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/sub/visibility", bytes.NewReader(visBody))
	apiUpdateSubVisibility(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("apiUpdateSubVisibility status=%d body=%s", rec.Code, rec.Body.String())
	}

	raw2, err := service.GenerateV2RaySubBase64(false)
	if err != nil {
		t.Fatalf("GenerateV2RaySubBase64(override) failed: %v", err)
	}
	decoded2Bytes, _ := base64.StdEncoding.DecodeString(raw2)
	decoded2 := string(decoded2Bytes)
	if strings.Contains(decoded2, "vless://") {
		t.Fatalf("expected unchecked direct node hidden, got: %s", decoded2)
	}
	if !hasSSLine(decoded2) {
		t.Fatalf("expected explicitly checked non-WG landing node included, got: %s", decoded2)
	}

	// 3. 当落地节点参与 WG 配对时，即使被勾选或开启 include_landing，其内部 SS 仍强制隐藏
	if err := database.DB.Create(&database.WGPair{
		ID:              "pair-landing-protect",
		EntryUUID:       "direct-1",
		PeerUUID:        "landing-1",
		TopologyVersion: 2,
		Status:          "active",
		Enabled:         true,
	}).Error; err != nil {
		t.Fatalf("create wg pair: %v", err)
	}
	includeTrue := true
	raw3, err := service.GenerateV2RaySubBase64WithOptions(false, &includeTrue)
	if err != nil {
		t.Fatalf("GenerateV2RaySubBase64WithOptions failed: %v", err)
	}
	decoded3Bytes, _ := base64.StdEncoding.DecodeString(raw3)
	if hasSSLine(string(decoded3Bytes)) {
		t.Fatalf("WG landing internal SS must never leak into V2Ray sub: %s", string(decoded3Bytes))
	}
	clashLanding, err := service.GenerateRawNodesYAML(2, false)
	if err != nil {
		t.Fatalf("GenerateRawNodesYAML(2) failed: %v", err)
	}
	if strings.Contains(clashLanding, "198.51.100.20") {
		t.Fatalf("WG landing internal SS must never leak into Clash landing raw sub: %s", clashLanding)
	}

	// 4. /api/node/rename 在节点处于 WG 配对中时仍可安全修改节点名称
	renameBody, _ := json.Marshal(map[string]string{
		"uuid": "direct-1",
		"name": "香港专线入口",
	})
	recRename := httptest.NewRecorder()
	reqRename := httptest.NewRequest(http.MethodPost, "/api/node/rename", bytes.NewReader(renameBody))
	apiRenameNode(recRename, reqRename)
	if recRename.Code != http.StatusOK {
		t.Fatalf("apiRenameNode status=%d body=%s", recRename.Code, recRename.Body.String())
	}
	var updated database.NodePool
	if err := database.DB.First(&updated, "uuid = ?", "direct-1").Error; err != nil {
		t.Fatalf("reload renamed node: %v", err)
	}
	if updated.Name != "香港专线入口" {
		t.Fatalf("expected renamed node '香港专线入口', got %q", updated.Name)
	}
}
