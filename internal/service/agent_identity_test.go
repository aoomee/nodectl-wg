package service

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"nhooyr.io/websocket"
	"nodectl/internal/database"
	"nodectl/internal/requestmeta"
	"nodectl/internal/testutil"
)

func identityTestDB(t *testing.T) *TrafficHub {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err = db.AutoMigrate(&database.NodePool{}, &database.AgentIdentity{}); err != nil {
		t.Fatal(err)
	}
	old := database.DB
	database.DB = db
	// Do not launch traffic persistence workers in credential unit tests.
	hubOnce.Do(func() { globalHub = &TrafficHub{} })
	oldHub := globalHub
	h := &TrafficHub{agentConns: map[string]*websocket.Conn{}, agentSessions: map[*websocket.Conn]agentSession{}, cmdResults: map[string]chan AgentCommandResult{}, cmdOwners: map[string]commandOwner{}, cmdLogs: map[string]*CommandLog{}}
	globalHub = h
	t.Cleanup(func() { globalHub = oldHub; database.DB = old; _ = sqlDB.Close() })
	for _, node := range []database.NodePool{{UUID: "node-a", InstallID: "aaaaaaaaaaaa"}, {UUID: "node-b", InstallID: "bbbbbbbbbbbb"}} {
		if err = db.Create(&node).Error; err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func TestWGAgentConnectionReadiness(t *testing.T) {
	h := identityTestDB(t)
	secret := enrollTestAgent(t)
	id := "aaaaaaaaaaaa"
	if WGAgentV2Status(id) != "offline" || WGAgentV2Ready(id) {
		t.Fatal("absent connection ready")
	}
	conn := &websocket.Conn{}
	h.agentConns[id] = conn
	if WGAgentV2Status(id) != "unauthenticated" {
		t.Fatal("legacy connection authenticated")
	}
	session := agentSession{installID: id, secretHash: agentHash(secret), authenticated: true, wg: true}
	h.agentSessions[conn] = session
	if WGAgentV2Status(id) != "unsupported" || WGAgentV2Ready(id) {
		t.Fatal("old Agent ready for v2")
	}
	session.wgV2 = true
	h.agentSessions[conn] = session
	if WGAgentV2Status(id) != "ready" || !WGAgentV2Ready(id) {
		t.Fatal("authenticated v2 connection unavailable")
	}
	if err := database.DB.Model(&database.AgentIdentity{}).Where("node_uuid = ?", "node-a").Update("secret_hash", "").Error; err != nil {
		t.Fatal(err)
	}
	if WGAgentV2Status(id) != "unauthenticated" || WGAgentV2Ready(id) {
		t.Fatal("revoked connection ready")
	}
}

func TestAuthenticatedAgentThroughHTTPSProxy(t *testing.T) {
	for _, kind := range []string{"go", "nginx"} {
		t.Run(kind, func(t *testing.T) {
			h := identityTestDB(t)
			secret := enrollTestAgent(t)
			if err := requestmeta.Configure("127.0.0.1"); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = requestmeta.Configure("") })
			finished := make(chan struct{}, 1)
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Use the production authentication and command correlation over a
				// real WebSocket, without launching traffic persistence workers.
				session, err := authenticateAgentRequest(r)
				if err != nil {
					http.Error(w, "invalid credentials", 401)
					return
				}
				if r.TLS != nil {
					t.Error("fixture must exercise HTTP upstream")
				}
				c, err := websocket.Accept(w, r, nil)
				if err != nil {
					return
				}
				defer c.CloseNow()
				defer func() { finished <- struct{}{} }()
				h.agentMu.Lock()
				h.agentConns[session.installID] = c
				h.agentSessions[c] = session
				h.agentMu.Unlock()
				for {
					_, b, err := c.Read(r.Context())
					if err != nil {
						return
					}
					var result AgentCommandResult
					if json.Unmarshal(b, &result) == nil {
						h.acceptAgentResult(c, session.installID, result)
					}
				}
			}))
			defer backend.Close()
			proxyURL, httpClient := testutil.HTTPSProxy(t, backend.URL, kind)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			headers := http.Header{"Authorization": {"Bearer " + secret}, AgentInstallIDHeader: {"aaaaaaaaaaaa"}, AgentCapabilityHeader: {WGRelayV2Capability}}
			client, _, err := websocket.Dial(ctx, "wss"+strings.TrimPrefix(proxyURL, "https"), &websocket.DialOptions{HTTPClient: httpClient, HTTPHeader: headers})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseNow()
			for !WGAgentV2Ready("aaaaaaaaaaaa") {
				select {
				case <-ctx.Done():
					t.Fatal("authenticated agent not ready")
				default:
					time.Sleep(time.Millisecond)
				}
			}
			result := make(chan error, 1)
			go func() {
				_, b, err := client.Read(ctx)
				if err != nil {
					result <- err
					return
				}
				var cmd AgentCommand
				if err := json.Unmarshal(b, &cmd); err != nil {
					result <- err
					return
				}
				b, _ = json.Marshal(AgentCommandResult{Type: "result", CommandID: cmd.CommandID, Status: "ok", Data: json.RawMessage(`{"ready":true}`)})
				result <- client.Write(ctx, websocket.MessageText, b)
			}()
			data, err := SendWGCommand(ctx, "aaaaaaaaaaaa", "wg-status", nil)
			if err != nil || string(data) != `{"ready":true}` {
				t.Fatalf("command=%s err=%v", data, err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if err := RevokeAgentIdentity("node-a"); err != nil {
				t.Fatal(err)
			}
			select {
			case <-finished:
			case <-ctx.Done():
				t.Fatal("revocation did not close the upstream connection")
			}
			if WGAgentReady("aaaaaaaaaaaa") {
				t.Fatal("revoked connection remains ready")
			}
			_, response, err := websocket.Dial(ctx, "wss"+strings.TrimPrefix(proxyURL, "https"), &websocket.DialOptions{HTTPClient: httpClient, HTTPHeader: headers})
			if err == nil || response == nil || response.StatusCode != 401 {
				t.Fatal("revoked credential reconnected")
			}
		})
	}
}
func enrollTestAgent(t *testing.T) string {
	t.Helper()
	token, _, err := IssueAgentEnrollment("node-a", false)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := RedeemAgentEnrollment("aaaaaaaaaaaa", token)
	if err != nil {
		t.Fatal(err)
	}
	return secret
}
func requestAgent(id, token string, tlsEnabled bool) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://panel.example/api/callback/traffic/ws", nil)
	if tlsEnabled {
		r.TLS = &tls.ConnectionState{}
	} else {
		r.TLS = nil
	}
	r.Header.Set(AgentInstallIDHeader, id)
	r.Header.Set(AgentCapabilityHeader, WGRelayCapability)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}
func TestAgentEnrollmentSingleUseAndNodeBinding(t *testing.T) {
	identityTestDB(t)
	token, expires, err := IssueAgentEnrollment("node-a", false)
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(expires) > 11*time.Minute || time.Until(expires) < 9*time.Minute {
		t.Fatal("unexpected expiry")
	}
	if _, err = RedeemAgentEnrollment("bbbbbbbbbbbb", token); err == nil {
		t.Fatal("token used by wrong node")
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := RedeemAgentEnrollment("aaaaaaaaaaaa", token); e == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful redemptions = %d", successes.Load())
	}
	var row database.AgentIdentity
	if err = database.DB.First(&row, "node_uuid = ?", "node-a").Error; err != nil {
		t.Fatal(err)
	}
	if !row.Bound || row.SecretHash == "" || row.SecretHash == token || row.EnrollmentHash != "" {
		t.Fatal("invalid stored identity")
	}
	if _, _, err = IssueAgentEnrollment("node-a", false); err == nil {
		t.Fatal("bound identity silently rotated")
	}
}
func TestAgentAuthenticationRevokeAndRotation(t *testing.T) {
	identityTestDB(t)
	secret := enrollTestAgent(t)
	for _, tc := range []struct {
		name, id, token string
		tls, ok         bool
	}{
		{"valid", "aaaaaaaaaaaa", secret, true, true},
		{"wrong token", "aaaaaaaaaaaa", strings.Repeat("0", 64), true, false},
		{"other install", "bbbbbbbbbbbb", secret, true, false},
		{"missing token", "aaaaaaaaaaaa", "", true, false},
		{"plaintext", "aaaaaaaaaaaa", secret, false, false},
		{"missing install", "", secret, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, e := authenticateAgentRequest(requestAgent(tc.id, tc.token, tc.tls))
			if (e == nil) != tc.ok {
				t.Fatalf("authentication error=%v", e)
			}
			if tc.ok && (!s.authenticated || !s.wg) {
				t.Fatal("missing authenticated capability")
			}
		})
	}
	if err := RevokeAgentIdentity("node-a"); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{secret, ""} {
		if _, err := authenticateAgentRequest(requestAgent("aaaaaaaaaaaa", token, true)); err == nil {
			t.Fatal("revoked identity accepted")
		}
	}
	if validAgentSession("aaaaaaaaaaaa", agentSession{}) {
		t.Fatal("revocation downgraded to legacy")
	}
	token, _, err := IssueAgentEnrollment("node-a", true)
	if err != nil {
		t.Fatal(err)
	}
	next, err := RedeemAgentEnrollment("aaaaaaaaaaaa", token)
	if err != nil {
		t.Fatal(err)
	}
	if next == secret {
		t.Fatal("secret reused")
	}
	if _, err = authenticateAgentRequest(requestAgent("aaaaaaaaaaaa", next, true)); err != nil {
		t.Fatal(err)
	}
	if _, err = authenticateAgentRequest(requestAgent("aaaaaaaaaaaa", secret, true)); err == nil {
		t.Fatal("old secret survived rotation")
	}
}
func TestAgentEnrollmentExpiryReplacementAndRevocation(t *testing.T) {
	identityTestDB(t)
	old, _, _ := IssueAgentEnrollment("node-a", false)
	token, _, err := IssueAgentEnrollment("node-a", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = RedeemAgentEnrollment("aaaaaaaaaaaa", old); err == nil {
		t.Fatal("superseded enrollment accepted")
	}
	database.DB.Model(&database.AgentIdentity{}).Where("node_uuid = ?", "node-a").Update("enrollment_expires_at", time.Now().Add(-time.Minute))
	if _, err = RedeemAgentEnrollment("aaaaaaaaaaaa", token); err == nil {
		t.Fatal("expired enrollment accepted")
	}
	token, _, err = IssueAgentEnrollment("node-a", false)
	if err != nil {
		t.Fatal(err)
	}
	if err = RevokeAgentIdentity("node-a"); err != nil {
		t.Fatal(err)
	}
	if _, err = RedeemAgentEnrollment("aaaaaaaaaaaa", token); err == nil {
		t.Fatal("revoked enrollment accepted")
	}
}
func TestAgentResultsRejectSpoofAndStaleDisconnect(t *testing.T) {
	h := identityTestDB(t)
	secret := enrollTestAgent(t)
	current, stale, other := new(websocket.Conn), new(websocket.Conn), new(websocket.Conn)
	h.agentConns["aaaaaaaaaaaa"] = current
	h.agentConns["bbbbbbbbbbbb"] = other
	h.agentSessions[current] = agentSession{installID: "aaaaaaaaaaaa", secretHash: agentHash(secret), authenticated: true, wg: true}
	ch := make(chan AgentCommandResult, 1)
	h.cmdResults["command"] = ch
	h.cmdOwners["command"] = commandOwner{installID: "aaaaaaaaaaaa", conn: current, wg: true}
	result := AgentCommandResult{Type: "result", CommandID: "command", Status: "ok", Data: json.RawMessage(`{"secret":"never-log"}`)}
	for _, tc := range []struct {
		conn *websocket.Conn
		id   string
	}{{other, "bbbbbbbbbbbb"}, {other, "aaaaaaaaaaaa"}, {stale, "aaaaaaaaaaaa"}, {current, "bbbbbbbbbbbb"}} {
		if h.acceptAgentResult(tc.conn, tc.id, result) {
			t.Fatal("spoofed result accepted")
		}
	}
	if len(ch) != 0 {
		t.Fatal("spoof reached waiter")
	}
	if h.unbindAgentConnectionIfCurrent(stale, "aaaaaaaaaaaa") || h.agentConns["aaaaaaaaaaaa"] != current {
		t.Fatal("stale disconnect removed replacement")
	}
	if !WGAgentReady("aaaaaaaaaaaa") {
		t.Fatal("authenticated current session not ready")
	}
	if !h.acceptAgentResult(current, "aaaaaaaaaaaa", result) {
		t.Fatal("valid result rejected")
	}
	if h.acceptAgentResult(current, "aaaaaaaaaaaa", result) {
		t.Fatal("replayed result accepted")
	}
	if got := <-ch; string(got.Data) != string(result.Data) {
		t.Fatal("result data lost")
	}
	if len(h.cmdLogs) != 0 {
		t.Fatal("WG secret leaked into logs")
	}
	// Revocation outside the connection cache also invalidates readiness/results.
	database.DB.Model(&database.AgentIdentity{}).Where("node_uuid = ?", "node-a").Update("secret_hash", "")
	if WGAgentReady("aaaaaaaaaaaa") {
		t.Fatal("revoked session still ready")
	}
	h.cmdResults["command"] = ch
	h.cmdOwners["command"] = commandOwner{installID: "aaaaaaaaaaaa", conn: current, wg: true}
	if h.acceptAgentResult(current, "aaaaaaaaaaaa", result) {
		t.Fatal("revoked result accepted")
	}
}
func TestSendWGCommandRoundTripAndCancellation(t *testing.T) {
	h := identityTestDB(t)
	secret := enrollTestAgent(t)
	serverConn := make(chan *websocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := websocket.Accept(w, r, nil)
		if e != nil {
			return
		}
		defer c.CloseNow()
		serverConn <- c
		for {
			_, b, e := c.Read(r.Context())
			if e != nil {
				return
			}
			var result AgentCommandResult
			if json.Unmarshal(b, &result) == nil {
				h.acceptAgentResult(c, "aaaaaaaaaaaa", result)
			}
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseNow()
	conn := <-serverConn
	h.agentMu.Lock()
	h.agentConns["aaaaaaaaaaaa"] = conn
	h.agentSessions[conn] = agentSession{installID: "aaaaaaaaaaaa", secretHash: agentHash(secret), authenticated: true, wg: true}
	h.agentMu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, data, e := client.Read(ctx)
		if e != nil {
			done <- e
			return
		}
		var cmd AgentCommand
		if e = json.Unmarshal(data, &cmd); e != nil {
			done <- e
			return
		}
		b, _ := json.Marshal(AgentCommandResult{Type: "result", CommandID: cmd.CommandID, Status: "ok", Data: json.RawMessage(`{"ready":true}`)})
		done <- client.Write(ctx, websocket.MessageText, b)
	}()
	result, err := SendWGCommand(ctx, "aaaaaaaaaaaa", "wg-status", map[string]string{"pair_id": "pair"})
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != `{"ready":true}` {
		t.Fatalf("unexpected result %s", result)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err = SendWGCommand(cancelled, "aaaaaaaaaaaa", "wg-status", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation=%v", err)
	}
	if _, err = SendWGCommand(ctx, "aaaaaaaaaaaa", "wg-shell", nil); err == nil {
		t.Fatal("unsupported action accepted")
	}
	// A command that receives no final result honors the caller's shorter deadline.
	short, stopShort := context.WithTimeout(ctx, 30*time.Millisecond)
	defer stopShort()
	if _, err = SendWGCommand(short, "aaaaaaaaaaaa", "wg-status", nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline=%v", err)
	}
	pending := make(chan AgentCommandResult, 1)
	h.cmdMu.Lock()
	if len(h.cmdOwners) != 0 || len(h.cmdResults) != 0 {
		t.Fatal("command correlation leaked")
	}
	h.cmdResults["pending"] = pending
	h.cmdOwners["pending"] = commandOwner{installID: "aaaaaaaaaaaa", conn: conn, wg: true}
	h.cmdMu.Unlock()
	if err = RevokeAgentIdentity("node-a"); err != nil {
		t.Fatal(err)
	}
	if WGAgentReady("aaaaaaaaaaaa") {
		t.Fatal("revoked connection remains ready")
	}
	select {
	case result := <-pending:
		if result.Status != "error" {
			t.Fatal("revocation did not fail pending command")
		}
	case <-ctx.Done():
		t.Fatal("revocation left pending command blocked")
	}
	h.agentMu.RLock()
	active := h.agentConns["aaaaaaaaaaaa"]
	h.agentMu.RUnlock()
	if active != nil {
		t.Fatal("revocation did not disconnect session")
	}
}
