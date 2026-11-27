package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"
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

func TestReporterDirectAgentDispatchesWGCommandsOverWS(t *testing.T) {
	dispatched := make(chan ServerCommand, 1)
	replyCh := make(chan CommandResult, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"wirearc-agent"}})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "done")
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		cmdBytes, _ := json.Marshal(ServerCommand{
			Type:      "command",
			CommandID: "wg-direct-test-1",
			Action:    "wg-v2-guard",
			Payload:   json.RawMessage(`{"pair_id":"0123456789abcdef","revision":1}`),
		})
		if err := conn.Write(ctx, websocket.MessageText, cmdBytes); err != nil {
			return
		}
		_, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		var res CommandResult
		if json.Unmarshal(data, &res) == nil {
			replyCh <- res
		}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	rep := NewReporter(&Config{
		InstallID: "aaaaaaaaaaaa",
		PanelURL:  srv.URL,
		WSURL:     wsURL,
		// AgentToken intentionally empty: Direct Agent mode must dispatch wg-* commands.
	})
	rep.SetCommandHandler(func(cmd ServerCommand, reply func(CommandResult)) {
		dispatched <- cmd
		reply(CommandResult{Type: "result", Status: "ok", Data: json.RawMessage(`{"phase":"guarded"}`)})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rep.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer rep.Close()

	select {
	case cmd := <-dispatched:
		if cmd.Action != "wg-v2-guard" || cmd.CommandID != "wg-direct-test-1" {
			t.Fatalf("unexpected dispatched command: %#v", cmd)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("direct agent wg-v2-guard command was not dispatched to CommandHandler")
	}

	select {
	case res := <-replyCh:
		if res.Status != "ok" || res.CommandID != "wg-direct-test-1" {
			t.Fatalf("unexpected command reply: %#v", res)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for WS command result")
	}
}
