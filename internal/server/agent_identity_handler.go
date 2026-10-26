package server

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"

	"nodectl/internal/service"
)

// Admin handlers MUST be registered behind withAuthAndSecure. All credential
// operations also require real backend TLS; forwarded headers are not trusted.
func agentIdentityRequest(w http.ResponseWriter, r *http.Request, admin bool, body any) bool {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		agentIdentityError(w, 405, "method not allowed")
		return false
	}
	if r.TLS == nil {
		agentIdentityError(w, 400, "HTTPS required")
		return false
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		agentIdentityError(w, 415, "JSON required")
		return false
	}
	if admin {
		if r.Header.Get("X-NodeCtl-WG") != "1" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			agentIdentityError(w, 403, "request origin rejected")
			return false
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, e := url.Parse(origin)
			if e != nil || u.Scheme != "https" || u.Host != r.Host || u.User != nil {
				agentIdentityError(w, 403, "request origin rejected")
				return false
			}
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(body) != nil {
		agentIdentityError(w, 400, "invalid request")
		return false
	}
	if d.Decode(&struct{}{}) != io.EOF {
		agentIdentityError(w, 400, "invalid request")
		return false
	}
	return true
}
func agentIdentityError(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
func apiNodeAgentEnrollment(w http.ResponseWriter, r *http.Request) {
	var body struct {
		NodeUUID string `json:"node_uuid"`
		Rotate   bool   `json:"rotate"`
	}
	if !agentIdentityRequest(w, r, true, &body) {
		return
	}
	if body.NodeUUID == "" || len(body.NodeUUID) > 36 {
		agentIdentityError(w, 400, "invalid node")
		return
	}
	token, expires, err := service.IssueAgentEnrollment(body.NodeUUID, body.Rotate)
	if err != nil {
		agentIdentityError(w, 409, "cannot issue enrollment; verify node and rotation choice")
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"token": token, "expires_at": expires})
}
func apiNodeAgentRevoke(w http.ResponseWriter, r *http.Request) {
	var body struct {
		NodeUUID string `json:"node_uuid"`
	}
	if !agentIdentityRequest(w, r, true, &body) {
		return
	}
	if body.NodeUUID == "" || len(body.NodeUUID) > 36 {
		agentIdentityError(w, 400, "invalid node")
		return
	}
	if service.RevokeAgentIdentity(body.NodeUUID) != nil {
		agentIdentityError(w, 400, "cannot revoke agent identity")
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}
func apiAgentEnroll(w http.ResponseWriter, r *http.Request) {
	var body struct {
		InstallID string `json:"install_id"`
		Token     string `json:"token"`
	}
	if !agentIdentityRequest(w, r, false, &body) {
		return
	}
	if body.InstallID == "" || len(body.InstallID) > 12 || len(body.Token) != 64 {
		agentIdentityError(w, 401, "invalid enrollment credentials")
		return
	}
	token, err := service.RedeemAgentEnrollment(body.InstallID, body.Token)
	if err != nil {
		agentIdentityError(w, 401, "invalid enrollment credentials")
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
}
