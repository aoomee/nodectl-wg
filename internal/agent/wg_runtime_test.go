package agent

import (
	"encoding/json"
	"testing"
)

func TestWGCommandRequiresSecureEnrollmentBeforeInitializing(t *testing.T) {
	for _, cfg := range []*Config{nil, {}, {AgentToken: "secret", PanelURL: "http://panel.test", WSURL: "ws://panel.test/api/callback/traffic/ws"}} {
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
}
