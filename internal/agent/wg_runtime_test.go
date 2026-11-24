package agent

import (
	"encoding/json"
	"testing"
)

func TestWGCommandRequiresValidConfigBeforeInitializing(t *testing.T) {
	for _, cfg := range []*Config{nil, {}, {InstallID: "aaaaaaaaaaaa", AgentToken: "secret", PanelURL: "http://panel.test", WSURL: "ws://panel.test/api/callback/traffic/ws"}} {
		rt := &Runtime{cfg: cfg}
		var results []CommandResult
		rt.handleCommand(ServerCommand{Action: "wg-prepare", Payload: json.RawMessage(`{}`)}, func(r CommandResult) { results = append(results, r) })
		if len(results) != 1 || results[0].Status != "error" {
			t.Fatalf("unexpected results: %#v", results)
		}
		if rt.wgManager != nil || rt.singboxMgr != nil {
			t.Fatal("unsafe command initialized services")
		}
	}

	// Direct Agent mode (InstallID present, no AgentToken) passes the config gate and reaches v2 payload decoding.
	rt := &Runtime{cfg: &Config{InstallID: "aaaaaaaaaaaa", PanelURL: "http://panel.test", WSURL: "ws://panel.test/api/callback/traffic/ws"}}
	var directResults []CommandResult
	rt.handleCommand(ServerCommand{Action: "wg-v2-status", Payload: json.RawMessage(`{}`)}, func(r CommandResult) { directResults = append(directResults, r) })
	if len(directResults) != 1 || directResults[0].Status != "error" || directResults[0].Message != "WG REALITY→SS 操作失败；保持阻断，请检查阶段状态及双端配置" {
		t.Fatalf("direct agent config gate rejected valid InstallID: %#v", directResults)
	}
}
