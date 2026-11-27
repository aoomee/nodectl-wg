package service

import (
	"strings"
	"sync"
	"time"

	"wirearc/internal/database"
	"wirearc/internal/logger"
)

var (
	autoUpdateLoopOnce   sync.Once
	geoAutoUpdateMu      sync.Mutex
	mihomoAutoUpdateMu   sync.Mutex
	cfTunnelAutoUpdateMu sync.Mutex
	cfIPOptAutoUpdateMu  sync.Mutex
)

const (
	geoLastCheckDateKey      = "geo_auto_update_last_check_date"
	mihomoLastCheckDateKey   = "mihomo_auto_update_last_check_date"
	cfTunnelLastCheckDateKey = "cf_tunnel_auto_update_last_check_date"
	cfIPOptLastCheckDateKey  = "cf_ipopt_auto_update_last_check_date"
)

// StartAutoUpdateScheduler 启动 GeoIP / Mihomo / cloudflared / CloudflareST 自动更新调度器（仅启动一次）。
// 调度规则：每天凌晨 03:00（本地时区）后首次检查一次。
func StartAutoUpdateScheduler() {
	autoUpdateLoopOnce.Do(func() {
		go runAutoUpdateLoop()
	})
}

// TriggerGeoAutoUpdateCheckNow 立即触发一次 GeoIP 自动更新检查（异步）。
func TriggerGeoAutoUpdateCheckNow() {
	go runGeoAutoUpdate(time.Now())
}

// TriggerMihomoAutoUpdateCheckNow 立即触发一次 Mihomo 自动更新检查（异步）。
func TriggerMihomoAutoUpdateCheckNow() {
	go runMihomoAutoUpdate(time.Now())
}

// TriggerCFTunnelAutoUpdateCheckNow 立即触发一次 cloudflared 自动更新检查（异步）。
func TriggerCFTunnelAutoUpdateCheckNow() {
	go runCFTunnelAutoUpdate(time.Now())
}

// TriggerCFIPOptAutoUpdateCheckNow 立即触发一次 CloudflareST 自动更新检查（异步）。
func TriggerCFIPOptAutoUpdateCheckNow() {
	go runCFIPOptAutoUpdate(time.Now())
}

func runAutoUpdateLoop() {
	// 启动后先做一次轻量尝试（满足时间窗口才会执行）
	runAutoUpdateTick(time.Now())

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for now := range ticker.C {
		runAutoUpdateTick(now)
	}
}

func runAutoUpdateTick(now time.Time) {
	if shouldRunDailyAfterHour(geoLastCheckDateKey, now, 3) && isSysConfigEnabled("geo_auto_update") {
		go runGeoAutoUpdate(now)
	}

	if shouldRunDailyAfterHour(mihomoLastCheckDateKey, now, 3) && isSysConfigEnabled("mihomo_auto_update") {
		go runMihomoAutoUpdate(now)
	}

	if shouldRunDailyAfterHour(cfTunnelLastCheckDateKey, now, 3) && isSysConfigEnabled("cf_tunnel_auto_update") {
		go runCFTunnelAutoUpdate(now)
	}

	if shouldRunDailyAfterHour(cfIPOptLastCheckDateKey, now, 3) && isSysConfigEnabled("cf_ipopt_auto_update") {
		go runCFIPOptAutoUpdate(now)
	}
}

func shouldRunDailyAfterHour(lastCheckKey string, now time.Time, hour int) bool {
	if now.Hour() < hour {
		return false
	}

	today := now.Format("2006-01-02")
	last := strings.TrimSpace(getSysConfigValue(lastCheckKey))
	return last != today
}

func runGeoAutoUpdate(now time.Time) {
	geoAutoUpdateMu.Lock()
	defer geoAutoUpdateMu.Unlock()

	if !isSysConfigEnabled("geo_auto_update") {
		return
	}
	if GlobalGeoIP == nil {
		logger.Log.Warn("GeoIP 自动更新跳过：服务未初始化")
		return
	}

	markSysConfigValue(geoLastCheckDateKey, now.Format("2006-01-02"), "GeoIP 自动更新最近检查日期")

	localVersion := strings.TrimSpace(GlobalGeoIP.GetLocalVersion())
	remoteVersion, err := GlobalGeoIP.GetRemoteVersion()
	if err != nil {
		logger.Log.Warn("GeoIP 自动更新检查失败", "error", err)
		return
	}

	if localVersion != "" && localVersion == strings.TrimSpace(remoteVersion) {
		logger.Log.Debug("GeoIP 自动更新检查：已是最新版本", "version", localVersion)
		return
	}

	logger.Log.Info("GeoIP 自动更新：检测到新版本，开始更新", "local", localVersion, "remote", remoteVersion)
	if err := GlobalGeoIP.ForceUpdate(); err != nil {
		logger.Log.Error("GeoIP 自动更新失败", "error", err)
		return
	}
	logger.Log.Info("GeoIP 自动更新完成", "version", remoteVersion)
}

func runMihomoAutoUpdate(now time.Time) {
	mihomoAutoUpdateMu.Lock()
	defer mihomoAutoUpdateMu.Unlock()

	if !isSysConfigEnabled("mihomo_auto_update") {
		return
	}
	if GlobalMihomo == nil {
		logger.Log.Warn("Mihomo 自动更新跳过：服务未初始化")
		return
	}

	markSysConfigValue(mihomoLastCheckDateKey, now.Format("2006-01-02"), "Mihomo 自动更新最近检查日期")

	localVersion := strings.TrimSpace(GlobalMihomo.GetLocalVersion())
	remoteVersion, _, _, err := GlobalMihomo.GetRemoteVersion()
	if err != nil {
		logger.Log.Warn("Mihomo 自动更新检查失败", "error", err)
		return
	}

	if localVersion != "" && localVersion == strings.TrimSpace(remoteVersion) {
		logger.Log.Debug("Mihomo 自动更新检查：已是最新版本", "version", localVersion)
		return
	}

	logger.Log.Info("Mihomo 自动更新：检测到新版本，开始更新", "local", localVersion, "remote", remoteVersion)
	if err := GlobalMihomo.ForceUpdate(); err != nil {
		logger.Log.Error("Mihomo 自动更新失败", "error", err)
		return
	}
	logger.Log.Info("Mihomo 自动更新完成", "version", remoteVersion)
}

func runCFTunnelAutoUpdate(now time.Time) {
	cfTunnelAutoUpdateMu.Lock()
	defer cfTunnelAutoUpdateMu.Unlock()

	if !isSysConfigEnabled("cf_tunnel_auto_update") {
		return
	}

	// 检查 cloudflared 是否已安装
	exists, localVersion := CheckCloudflaredBinary()
	if !exists {
		logger.Log.Debug("cloudflared 自动更新跳过：二进制不存在")
		return
	}

	markSysConfigValue(cfTunnelLastCheckDateKey, now.Format("2006-01-02"), "cloudflared 自动更新最近检查日期")

	remoteVersion, err := GetCloudflaredRemoteVersion()
	if err != nil {
		logger.Log.Warn("cloudflared 自动更新检查失败", "error", err)
		return
	}

	cleanLocal := strings.TrimSpace(localVersion)
	cleanRemote := strings.TrimSpace(strings.TrimPrefix(remoteVersion, "v"))

	if cleanLocal != "" && cleanLocal == cleanRemote {
		logger.Log.Debug("cloudflared 自动更新检查：已是最新版本", "version", cleanLocal)
		return
	}

	logger.Log.Info("cloudflared 自动更新：检测到新版本，开始更新", "local", cleanLocal, "remote", cleanRemote)
	if err := ForceUpdateCloudflared(); err != nil {
		logger.Log.Error("cloudflared 自动更新失败", "error", err)
		return
	}
	logger.Log.Info("cloudflared 自动更新完成", "version", cleanRemote)
}

func runCFIPOptAutoUpdate(now time.Time) {
	cfIPOptAutoUpdateMu.Lock()
	defer cfIPOptAutoUpdateMu.Unlock()

	if !isSysConfigEnabled("cf_ipopt_auto_update") {
		return
	}

	// 检查 CloudflareST 是否已安装
	exists, localVersion, _ := IsCFIPOptBinaryExists()
	if !exists {
		logger.Log.Debug("CloudflareST 自动更新跳过：二进制不存在")
		return
	}

	markSysConfigValue(cfIPOptLastCheckDateKey, now.Format("2006-01-02"), "CloudflareST 自动更新最近检查日期")

	remoteVersion, err := GetCFIPOptRemoteVersion()
	if err != nil {
		logger.Log.Warn("CloudflareST 自动更新检查失败", "error", err)
		return
	}

	cleanLocal := strings.TrimSpace(strings.TrimPrefix(localVersion, "v"))
	cleanRemote := strings.TrimSpace(strings.TrimPrefix(remoteVersion, "v"))

	if cleanLocal != "" && cleanLocal == cleanRemote {
		logger.Log.Debug("CloudflareST 自动更新检查：已是最新版本", "version", cleanLocal)
		return
	}

	logger.Log.Info("CloudflareST 自动更新：检测到新版本，开始更新", "local", cleanLocal, "remote", cleanRemote)
	if err := ForceUpdateCFIPOpt(); err != nil {
		logger.Log.Error("CloudflareST 自动更新失败", "error", err)
		return
	}
	logger.Log.Info("CloudflareST 自动更新完成", "version", cleanRemote)
}

func isSysConfigEnabled(key string) bool {
	v := strings.ToLower(strings.TrimSpace(getSysConfigValue(key)))
	return v == "1" || v == "true"
}

func getSysConfigValue(key string) string {
	var cfg database.SysConfig
	tx := database.DB.Select("value").Where("key = ?", key).Limit(1).Find(&cfg)
	if tx.Error != nil || tx.RowsAffected == 0 {
		return ""
	}
	return cfg.Value
}

func markSysConfigValue(key, value, desc string) {
	cfg := database.SysConfig{Key: key, Value: value, Description: desc}
	result := database.DB.Where("key = ?", key).FirstOrCreate(&cfg)
	if result.RowsAffected == 0 {
		database.DB.Model(&database.SysConfig{}).Where("key = ?", key).Update("value", value)
	}
}
