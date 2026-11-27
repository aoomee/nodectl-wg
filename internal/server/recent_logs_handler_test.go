package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wirearc/internal/logger"
)

func TestClearRecentLogsTruncatesActiveAndBackupFiles(t *testing.T) {
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })

	logger.Init("info")
	logger.Log.Info("测试日志条目")

	backupPath := filepath.Join("data", "logs", "wirearc-2026-01-01T00-00-00.000.log.gz")
	if err := os.WriteFile(backupPath, []byte("backup"), 0644); err != nil {
		t.Fatal(err)
	}

	wGet := httptest.NewRecorder()
	apiClearRecentLogs(wGet, httptest.NewRequest(http.MethodGet, "/api/recent-logs/clear", nil))
	if wGet.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET, got %d", wGet.Code)
	}

	w := httptest.NewRecorder()
	apiClearRecentLogs(w, httptest.NewRequest(http.MethodPost, "/api/recent-logs/clear", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"success"`) {
		t.Fatalf("clear logs failed: status=%d body=%s", w.Code, w.Body.String())
	}

	data, err := os.ReadFile(filepath.Join("data", "logs", "wirearc.log"))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("expected empty active log file, got %d bytes", len(data))
	}
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Fatalf("expected rotated backup log to be deleted, stat err=%v", err)
	}

	// Verify logger cleanly reopens and writes at offset 0 after clearing.
	logger.Log.Info("清空后新日志")
	after, err := os.ReadFile(filepath.Join("data", "logs", "wirearc.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after), "清空后新日志") || strings.Contains(string(after), "\x00") {
		t.Fatalf("unexpected log content after clear: %q", string(after))
	}
}
