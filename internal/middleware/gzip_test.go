package middleware

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGzipCompressesHTMLAndJSON(t *testing.T) {
	payload := strings.Repeat(`{"status":"success","data":"wirearc"}`, 64)
	handler := Gzip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/get-nodes", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected Content-Encoding gzip, got %q", rec.Header().Get("Content-Encoding"))
	}
	if rec.Body.Len() >= len(payload) {
		t.Fatalf("expected compressed body smaller than %d, got %d", len(payload), rec.Body.Len())
	}

	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("gzip.NewReader failed: %v", err)
	}
	defer zr.Close()
	decoded, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("read gzip body failed: %v", err)
	}
	if string(decoded) != payload {
		t.Fatalf("decoded payload mismatch")
	}
}

func TestGzipSkipsSSEAndUpgrade(t *testing.T) {
	sseHandler := Gzip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: ok\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/recent-logs/stream", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	sseHandler.ServeHTTP(rec, req)

	if rec.Header().Get("Content-Encoding") != "" {
		t.Fatalf("SSE response must not be gzipped, got %q", rec.Header().Get("Content-Encoding"))
	}
	if rec.Body.String() != "data: ok\n\n" {
		t.Fatalf("unexpected SSE body: %q", rec.Body.String())
	}

	wsReq := httptest.NewRequest(http.MethodGet, "/api/traffic/live", nil)
	wsReq.Header.Set("Accept-Encoding", "gzip")
	wsReq.Header.Set("Upgrade", "websocket")
	wsRec := httptest.NewRecorder()
	sseHandler.ServeHTTP(wsRec, wsReq)
	if wsRec.Header().Get("Content-Encoding") != "" {
		t.Fatalf("WebSocket upgrade request must bypass gzip")
	}
}
