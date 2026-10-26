package server

import (
	"encoding/json"
	"net/http"

	"nodectl/internal/service"
)

// Register both handlers behind withAuthAndSecure, just like identity mutations.
func apiWGPairOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		wgPairError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := r.URL.Query().Get("uuid")
	if id == "" || len(id) > 36 {
		wgPairError(w, 400, "invalid node")
		return
	}
	data, err := service.WGPairOptions(id)
	if err != nil {
		wgPairError(w, 409, "WireGuard options unavailable")
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "data": data})
}
func apiWGPairPush(w http.ResponseWriter, r *http.Request) {
	var request service.WGPairPush
	// Reuse bounded strict JSON, TLS, same-origin, and custom-header checks.
	if !agentIdentityRequest(w, r, true, &request) {
		return
	}
	if request.UUID == "" || len(request.UUID) > 36 || request.Revision < 1 || (request.Enabled && (request.PeerUUID == "" || len(request.PeerUUID) > 36 || request.EntryPort < 0 || request.EntryPort > 65535)) {
		wgPairError(w, 400, "invalid WireGuard pair request")
		return
	}
	data, err := service.SaveWGPair(r.Context(), request)
	if err != nil {
		wgPairError(w, 409, "pair conflict or unavailable dependencies; disable and finish cleanup before editing")
		return
	}
	// The transaction is committed, but activation is solely reconciler-owned.
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "data": map[string]interface{}{"pair": data}})
}
func wgPairError(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": message})
}
