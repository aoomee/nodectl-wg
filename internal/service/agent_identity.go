package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"nhooyr.io/websocket"
	"nodectl/internal/database"
	"nodectl/internal/requestmeta"
)

const WGRelayCapability = "wg-relay-v1"
const WGRelayV2Capability = "wg-reality-ss-v2"
const AgentCapabilityHeader = "X-NodeCtl-Capabilities"
const AgentInstallIDHeader = "X-NodeCtl-Install-ID"

var ErrAgentIdentity = errors.New("invalid or revoked agent credentials")

// Serializes credential changes with connection replacement in this process.
var agentIdentityMu sync.Mutex

func agentSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func agentHash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// IssueAgentEnrollment replaces any outstanding token. Rotation revokes the old
// secret immediately; a durable Bound tombstone is retained until re-enrollment.
func IssueAgentEnrollment(nodeUUID string, rotate bool) (string, time.Time, error) {
	agentIdentityMu.Lock()
	defer agentIdentityMu.Unlock()
	token, err := agentSecret()
	if err != nil {
		return "", time.Time{}, err
	}
	expires := time.Now().UTC().Add(10 * time.Minute)
	var node database.NodePool
	err = database.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("uuid = ?", nodeUUID).First(&node).Error; err != nil {
			return err
		}
		row := database.AgentIdentity{NodeUUID: node.UUID, InstallID: node.InstallID}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
			return err
		}
		updates := map[string]interface{}{"enrollment_hash": agentHash(token), "enrollment_expires_at": expires}
		if rotate {
			updates["secret_hash"] = ""
			updates["bound"] = true
		}
		if !rotate {
			var current database.AgentIdentity
			if err := tx.Where("node_uuid = ?", node.UUID).First(&current).Error; err != nil {
				return err
			}
			if current.Bound {
				return errors.New("agent already bound; explicit rotation required")
			}
		}
		return tx.Model(&database.AgentIdentity{}).Where("node_uuid = ? AND install_id = ?", node.UUID, node.InstallID).Updates(updates).Error
	})
	if err != nil {
		return "", time.Time{}, err
	}
	if rotate {
		GetTrafficHub().disconnectAgent(node.InstallID)
	}
	return token, expires, nil
}

func RedeemAgentEnrollment(installID, token string) (string, error) {
	if installID == "" || len(token) != 64 {
		return "", ErrAgentIdentity
	}
	agentIdentityMu.Lock()
	defer agentIdentityMu.Unlock()
	secret, err := agentSecret()
	if err != nil {
		return "", err
	}
	err = database.DB.Transaction(func(tx *gorm.DB) error {
		var node database.NodePool
		if err := tx.Where("install_id = ?", installID).First(&node).Error; err != nil {
			return ErrAgentIdentity
		}
		// Compare parsed instants too: SQLite stores timestamps as text and
		// timestamps written with different timezone offsets sort incorrectly.
		var identity database.AgentIdentity
		if err := tx.Where("node_uuid = ? AND install_id = ? AND enrollment_hash = ?", node.UUID, installID, agentHash(token)).First(&identity).Error; err != nil || !identity.EnrollmentExpiresAt.After(time.Now()) {
			return ErrAgentIdentity
		}
		result := tx.Model(&database.AgentIdentity{}).Where("node_uuid = ? AND install_id = ? AND enrollment_hash = ? AND enrollment_expires_at > ?", node.UUID, installID, agentHash(token), time.Now().UTC()).Updates(map[string]interface{}{"bound": true, "secret_hash": agentHash(secret), "enrollment_hash": "", "enrollment_expires_at": time.Time{}})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrAgentIdentity
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	GetTrafficHub().disconnectAgent(installID)
	return secret, nil
}

func RevokeAgentIdentity(nodeUUID string) error {
	agentIdentityMu.Lock()
	defer agentIdentityMu.Unlock()
	var node database.NodePool
	if err := database.DB.Where("uuid = ?", nodeUUID).First(&node).Error; err != nil {
		return err
	}
	row := database.AgentIdentity{NodeUUID: node.UUID, InstallID: node.InstallID, Bound: true}
	err := database.DB.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "node_uuid"}}, DoUpdates: clause.Assignments(map[string]interface{}{"bound": true, "secret_hash": "", "enrollment_hash": "", "enrollment_expires_at": time.Time{}})}).Create(&row).Error
	if err == nil {
		GetTrafficHub().disconnectAgent(node.InstallID)
	}
	return err
}

type agentSession struct {
	installID, secretHash   string
	authenticated, wg, wgV2 bool
}
type commandOwner struct {
	installID string
	conn      *websocket.Conn
	wg        bool
}

func validAgentSession(installID string, session agentSession) bool {
	if database.DB == nil {
		return false
	}
	var node database.NodePool
	if database.DB.Select("uuid", "install_id").Where("install_id = ?", installID).First(&node).Error != nil {
		return false
	}
	var id database.AgentIdentity
	err := database.DB.Where("install_id = ?", installID).First(&id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return !session.authenticated
	}
	if err != nil || id.NodeUUID != node.UUID {
		return false
	}
	if !id.Bound {
		return !session.authenticated
	}
	return session.authenticated && session.installID == installID && id.SecretHash != "" && id.SecretHash == session.secretHash
}

// Credentials require HTTPS, directly or through an explicitly trusted proxy.
// Untrusted forwarding headers cannot bypass the transport requirement.
func authenticateAgentRequest(r *http.Request) (agentSession, error) {
	auth := r.Header.Get("Authorization")
	id := strings.TrimSpace(r.Header.Get(AgentInstallIDHeader))
	s := agentSession{installID: id}
	if auth != "" {
		parts := strings.Fields(auth)
		if !requestmeta.IsSecure(r) || len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) != 64 || id == "" {
			return s, ErrAgentIdentity
		}
		s.authenticated = true
		s.secretHash = agentHash(parts[1])
		for _, cap := range strings.Split(r.Header.Get(AgentCapabilityHeader), ",") {
			if strings.TrimSpace(cap) == WGRelayV2Capability {
				s.wgV2 = true
				s.wg = true
			}
			if strings.TrimSpace(cap) == WGRelayCapability {
				s.wg = true
			}
		}
	}
	if id != "" && !validAgentSession(id, s) {
		return s, ErrAgentIdentity
	}
	return s, nil
}

func (h *TrafficHub) disconnectAgent(installID string) {
	h.agentMu.Lock()
	conn := h.agentConns[installID]
	delete(h.agentConns, installID)
	delete(h.agentSessions, conn)
	h.agentMu.Unlock()
	if conn != nil {
		h.failAgentCommands(conn)
		_ = conn.CloseNow()
	}
}
func (h *TrafficHub) failAgentCommands(conn *websocket.Conn) {
	h.cmdMu.Lock()
	defer h.cmdMu.Unlock()
	for id, owner := range h.cmdOwners {
		if owner.conn == conn {
			if ch := h.cmdResults[id]; ch != nil {
				select {
				case ch <- AgentCommandResult{Type: "result", CommandID: id, Status: "error", Message: "agent disconnected"}:
				default:
				}
			}
			delete(h.cmdResults, id)
			delete(h.cmdOwners, id)
		}
	}
}

func WGAgentReady(installID string) bool {
	agentIdentityMu.Lock()
	defer agentIdentityMu.Unlock()
	h := GetTrafficHub()
	h.agentMu.RLock()
	defer h.agentMu.RUnlock()
	c := h.agentConns[installID]
	s := h.agentSessions[c]
	return c != nil && s.authenticated && s.wg && validAgentSession(installID, s)
}

func WGAgentV2Ready(installID string) bool {
	agentIdentityMu.Lock()
	defer agentIdentityMu.Unlock()
	h := GetTrafficHub()
	h.agentMu.RLock()
	defer h.agentMu.RUnlock()
	c := h.agentConns[installID]
	s := h.agentSessions[c]
	return c != nil && s.authenticated && s.wgV2 && validAgentSession(installID, s)
}

func SendWGCommand(ctx context.Context, installID, action string, payload interface{}) (json.RawMessage, error) {
	switch action {
	case "wg-prepare", "wg-configure", "wg-verify", "wg-activate", "wg-remove", "wg-status", "wg-v2-guard", "wg-v2-block", "wg-v2-direct", "wg-v2-ss", "wg-v2-route", "wg-v2-status":
	default:
		return nil, errors.New("invalid WireGuard action")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	h := GetTrafficHub()
	agentIdentityMu.Lock()
	h.agentMu.RLock()
	conn := h.agentConns[installID]
	session := h.agentSessions[conn]
	if conn == nil || !session.authenticated || !session.wg || (strings.HasPrefix(action, "wg-v2-") && !session.wgV2) || !validAgentSession(installID, session) {
		h.agentMu.RUnlock()
		agentIdentityMu.Unlock()
		return nil, errors.New("authenticated WireGuard agent unavailable")
	}
	nonce, err := agentSecret()
	if err != nil {
		h.agentMu.RUnlock()
		agentIdentityMu.Unlock()
		return nil, err
	}
	id := "wg-" + nonce
	ch := make(chan AgentCommandResult, 8)
	h.cmdMu.Lock()
	if h.cmdOwners == nil {
		h.cmdOwners = make(map[string]commandOwner)
	}
	h.cmdResults[id] = ch
	h.cmdOwners[id] = commandOwner{installID: installID, conn: conn, wg: true}
	h.cmdMu.Unlock()
	h.agentMu.RUnlock()
	agentIdentityMu.Unlock()
	defer func() { h.cmdMu.Lock(); delete(h.cmdResults, id); delete(h.cmdOwners, id); h.cmdMu.Unlock() }()
	data, err := json.Marshal(AgentCommand{Type: "command", CommandID: id, Action: action, Payload: payload})
	if err != nil {
		return nil, err
	}
	writeCtx, writeCancel := context.WithTimeout(ctx, 5*time.Second)
	err = conn.Write(writeCtx, websocket.MessageText, data)
	writeCancel()
	if err != nil {
		return nil, err
	}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-ch:
			if result.Type != "result" {
				continue
			}
			if result.Status != "ok" {
				return nil, errors.New("WireGuard command failed")
			}
			return result.Data, nil
		}
	}
}

// A result belongs to the current connection and command owner, not merely to
// an attacker-supplied command_id. WG final data is never copied into SSE logs.
func (h *TrafficHub) acceptAgentResult(conn *websocket.Conn, installID string, result AgentCommandResult) bool {
	if result.Type != "result" && result.Type != "accepted" && result.Type != "progress" {
		return false
	}
	agentIdentityMu.Lock()
	defer agentIdentityMu.Unlock()
	h.agentMu.RLock()
	defer h.agentMu.RUnlock()
	if installID == "" || h.agentConns[installID] != conn {
		return false
	}
	h.cmdMu.Lock()
	owner, ok := h.cmdOwners[result.CommandID]
	if !ok || owner.installID != installID || owner.conn != conn {
		h.cmdMu.Unlock()
		return false
	}
	if owner.wg {
		session := h.agentSessions[conn]
		if !session.authenticated || !session.wg || !validAgentSession(installID, session) {
			h.cmdMu.Unlock()
			return false
		}
	}
	if ch := h.cmdResults[result.CommandID]; ch != nil && result.Type == "result" {
		select {
		case ch <- result:
		default:
		}
	}
	if result.Type == "result" {
		delete(h.cmdResults, result.CommandID)
		delete(h.cmdOwners, result.CommandID)
	}
	h.cmdMu.Unlock()
	if !owner.wg {
		h.appendCommandLog(result)
	}
	return true
}
