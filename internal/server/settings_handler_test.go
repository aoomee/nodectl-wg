package server

import (
	"bytes"
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gormlogger "gorm.io/gorm/logger"
	"nodectl/internal/database"
	"nodectl/internal/logger"
)

func settingsTest(t *testing.T) *bytes.Buffer {
	t.Helper()
	wgTestDB(t)
	previousLevel := logger.CurrentLevel()
	logger.SetLevel("info")
	t.Cleanup(func() { logger.SetLevel(previousLevel) })
	for _, row := range []database.SysConfig{{Key: "panel_url", Value: "https://old.test"}, {Key: "sub_token", Value: "OLD_SUB_SECRET"}, {Key: "proxy_socks5_pass", Value: "OLD_SOCKS_SECRET"}, {Key: "sys_log_level", Value: "info"}, {Key: "tg_bot_token", Value: "OLD_TG_SECRET"}} {
		if err := database.DB.Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
	var logs bytes.Buffer
	logger.Log = slog.New(slog.NewTextHandler(&logs, nil))
	database.DB.Logger = gormlogger.New(log.New(&logs, "", 0), gormlogger.Config{LogLevel: gormlogger.Info})
	return &logs
}

func saveSettings(t *testing.T, values map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	apiUpdateSettings(w, httptest.NewRequest(http.MethodPost, "/api/update-settings", bytes.NewReader(body)))
	return w
}

func settingValue(t *testing.T, key string) string {
	t.Helper()
	var row database.SysConfig
	if err := database.DB.First(&row, "key = ?", key).Error; err != nil {
		t.Fatal(err)
	}
	return row.Value
}

func TestSettingsFailureRollsBackWholeBatch(t *testing.T) {
	for _, kind := range []string{"validation", "read", "write", "ignored-write"} {
		t.Run(kind, func(t *testing.T) {
			logs := settingsTest(t)
			request := map[string]string{"sub_token": "NEW_SUB_SECRET", "sys_log_level": "debug", "tg_bot_token": "NEW_TG_SECRET"}
			switch kind {
			case "validation":
				request["login_ip_max_retries"] = "0"
			case "read":
				if err := database.DB.Migrator().DropTable(&database.SysConfig{}); err != nil {
					t.Fatal(err)
				}
			case "write":
				if err := database.DB.Exec(`CREATE TRIGGER reject_setting BEFORE UPDATE ON sys_config WHEN NEW.key='tg_bot_token' BEGIN SELECT RAISE(FAIL,'NEW_TG_SECRET'); END`).Error; err != nil {
					t.Fatal(err)
				}
			case "ignored-write":
				if err := database.DB.Exec(`CREATE TRIGGER ignore_setting BEFORE INSERT ON sys_config WHEN NEW.key='tg_bot_token' BEGIN SELECT RAISE(IGNORE); END`).Error; err != nil {
					t.Fatal(err)
				}
			}
			logs.Reset()
			w := saveSettings(t, request)
			var result struct{ Status string }
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if w.Code < 400 || result.Status != "error" {
				t.Fatal("failed batch reported success", w.Code, w.Body.String())
			}
			if logger.CurrentLevel() != "info" {
				t.Fatal("failed batch changed live logger")
			}
			for _, secret := range []string{"NEW_SUB_SECRET", "OLD_SUB_SECRET", "NEW_TG_SECRET", "OLD_TG_SECRET"} {
				if strings.Contains(logs.String(), secret) || strings.Contains(w.Body.String(), secret) {
					t.Fatal("credential leaked on failure")
				}
			}
			if kind != "read" && (settingValue(t, "sub_token") != "OLD_SUB_SECRET" || settingValue(t, "sys_log_level") != "info" || settingValue(t, "tg_bot_token") != "OLD_TG_SECRET") {
				t.Fatal("partial batch persisted")
			}
		})
	}
}

func TestSettingsSuccessMasksLogsAndCreatesMissingRows(t *testing.T) {
	logs := settingsTest(t)
	w := saveSettings(t, map[string]string{"sub_token": "NEW_SUB_SECRET", "proxy_socks5_pass": "NEW_SOCKS_SECRET", "panel_url": "https://user:URL_SECRET@example.test/path", "proxy_port_ss": "8388", "sys_log_level": "debug", "tg_bot_token": "********", "admin_password": "DO_NOT_WRITE"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"success"`) {
		t.Fatal(w.Body.String())
	}
	for _, secret := range []string{"OLD_SUB_SECRET", "NEW_SUB_SECRET", "OLD_SOCKS_SECRET", "NEW_SOCKS_SECRET", "URL_SECRET", "OLD_TG_SECRET", "DO_NOT_WRITE"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("settings value leaked into logs")
		}
	}
	if !strings.Contains(logs.String(), "sub_token") {
		t.Fatal("audit omitted changed key names")
	}
	if settingValue(t, "sub_token") != "NEW_SUB_SECRET" || settingValue(t, "proxy_port_ss") != "8388" || settingValue(t, "tg_bot_token") != "OLD_TG_SECRET" || logger.CurrentLevel() != "debug" {
		t.Fatal("settings not committed/applied")
	}
	var count int64
	database.DB.Model(&database.SysConfig{}).Where("key = ?", "admin_password").Count(&count)
	if count != 0 {
		t.Fatal("unknown security key accepted")
	}
	w = saveSettings(t, map[string]string{"proxy_port_ss": "8388"})
	if !strings.Contains(w.Body.String(), "设置无变化") {
		t.Fatal("unchanged setting saved again")
	}
}

func TestSettingsReadFailureIsNotEmptySuccess(t *testing.T) {
	settingsTest(t)
	if err := database.DB.Migrator().DropTable(&database.SysConfig{}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	apiGetSettings(w, httptest.NewRequest(http.MethodGet, "/api/get-settings", nil))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), `"error"`) {
		t.Fatal("read failure returned settings", w.Code, w.Body.String())
	}
}

func TestSettingsValidationDoesNotChangeRuntime(t *testing.T) {
	for key, value := range map[string]string{"sys_log_level": "invalid", "pref_traffic_stats_retention_days": "0", "pref_traffic_point_persist_interval_sec": "5", "login_ip_retry_window_sec": "1", "login_ip_block_ttl_sec": "86401", "tg_login_notify_mode": "unknown"} {
		t.Run(key, func(t *testing.T) {
			settingsTest(t)
			w := saveSettings(t, map[string]string{key: value, "sub_token": "NEW_SUB_SECRET"})
			if w.Code != 400 || settingValue(t, "sub_token") != "OLD_SUB_SECRET" || logger.CurrentLevel() != "info" {
				t.Fatal("validation allowed partial change")
			}
		})
	}
	settingsTest(t)
	w := saveSettings(t, map[string]string{"clash_public_rules_update_interval": "12", "pref_traffic_point_persist_interval_sec": "0", "auth_cookie_ttl_mode": "session"})
	if w.Code != 200 || settingValue(t, "clash_public_rules_update_interval") != "86400" || settingValue(t, "pref_traffic_point_persist_interval_sec") != "0" {
		t.Fatal("normalization changed")
	}
}
