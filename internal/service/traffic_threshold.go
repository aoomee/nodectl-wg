package service

import (
	"strings"
	"sync"

	"wirearc/internal/database"
	"wirearc/internal/logger"
)

type trafficThresholdRuntimeConfig struct {
	UUID      string
	InstallID string
	Name      string
	Limit     int64
	LimitType string
	Enabled   bool
	Percent   int
	Reached   bool
}

var (
	trafficThresholdMu    sync.RWMutex
	trafficThresholdCache = make(map[string]*trafficThresholdRuntimeConfig)
)

func InitTrafficThresholdCache() {
	var nodes []database.NodePool
	if err := database.DB.Select("uuid", "install_id", "name", "traffic_limit", "traffic_limit_type", "traffic_threshold_enabled", "traffic_threshold_percent", "traffic_threshold_reached").Find(&nodes).Error; err != nil {
		logger.Log.Warn("初始化阈值缓存失败", "error", err)
		return
	}

	next := make(map[string]*trafficThresholdRuntimeConfig, len(nodes))
	for _, n := range nodes {
		cfg := buildTrafficThresholdConfig(n)
		if cfg.InstallID == "" {
			continue
		}
		next[cfg.InstallID] = cfg
	}

	trafficThresholdMu.Lock()
	trafficThresholdCache = next
	trafficThresholdMu.Unlock()

	logger.Log.Debug("阈值停机配置已加载到内存", "count", len(next))
}

func UpdateNodeTrafficThresholdConfigFromNode(node database.NodePool) {
	cfg := buildTrafficThresholdConfig(node)
	if cfg.InstallID == "" {
		return
	}
	trafficThresholdMu.Lock()
	trafficThresholdCache[cfg.InstallID] = cfg
	trafficThresholdMu.Unlock()
}

func DeleteNodeTrafficThresholdConfig(installID string) {
	installID = strings.TrimSpace(installID)
	if installID == "" {
		return
	}
	trafficThresholdMu.Lock()
	delete(trafficThresholdCache, installID)
	trafficThresholdMu.Unlock()
}

func CheckAndHandleNodeTrafficThresholdRealtime(installID string, upBytes, downBytes int64) bool {
	installID = strings.TrimSpace(installID)
	if installID == "" {
		return false
	}

	cfg := getOrLoadTrafficThresholdConfig(installID)
	if cfg == nil {
		return false
	}

	node := &database.NodePool{
		UUID:                    cfg.UUID,
		InstallID:               cfg.InstallID,
		Name:                    cfg.Name,
		TrafficLimit:            cfg.Limit,
		TrafficLimitType:        cfg.LimitType,
		TrafficThresholdEnabled: cfg.Enabled,
		TrafficThresholdPercent: cfg.Percent,
		TrafficThresholdReached: cfg.Reached,
		TrafficUp:               upBytes,
		TrafficDown:             downBytes,
	}
	used := ComputeTrafficUsedByLimitType(upBytes, downBytes, cfg.LimitType)
	reached := CheckAndHandleNodeTrafficThreshold(node, used, "live-ws")
	return reached
}

func CheckAndHandleNodeTrafficThreshold(node *database.NodePool, usedBytes int64, source string) bool {
	if node == nil {
		return false
	}

	node.TrafficLimitType = NormalizeTrafficLimitType(node.TrafficLimitType)
	node.TrafficThresholdPercent = NormalizeTrafficThresholdPercent(node.TrafficThresholdPercent)
	UpdateNodeTrafficThresholdConfigFromNode(*node)

	enabled := node.TrafficThresholdEnabled && node.TrafficThresholdPercent > 0 && node.TrafficLimit > 0
	if !enabled {
		setNodeTrafficThresholdReached(node, false)
		return false
	}

	if usedBytes < 0 {
		usedBytes = ComputeTrafficUsedByLimitType(node.TrafficUp, node.TrafficDown, node.TrafficLimitType)
	}

	thresholdBytes := int64(float64(node.TrafficLimit) * float64(node.TrafficThresholdPercent) / 100.0)
	if thresholdBytes < 1 {
		thresholdBytes = 1
	}

	reachedNow := usedBytes >= thresholdBytes
	if !reachedNow {
		setNodeTrafficThresholdReached(node, false)
		return false
	}

	if !node.TrafficThresholdReached {
		// 从数据库查询节点的协议列表（reset-links 命令需要）
		var fullNode database.NodePool
		if err := database.DB.Select("links", "tunnel_enabled", "tunnel_id", "tunnel_domain", "tunnel_token", "disabled_links").Where("uuid = ?", node.UUID).First(&fullNode).Error; err != nil {
			logger.Log.Warn("阈值停机查询节点协议失败", "uuid", node.UUID, "error", err)
			return true
		}
		protocols := make([]string, 0, len(fullNode.Links))
		for proto := range fullNode.Links {
			protocols = append(protocols, proto)
		}
		if len(protocols) == 0 {
			logger.Log.Warn("阈值停机: 节点无已知协议，跳过重置", "uuid", node.UUID)
			return true
		}

		payload := map[string]interface{}{
			"protocols":                 protocols,
			"reason":                    "traffic-threshold-stop",
			"source":                    source,
			"traffic_threshold_percent": node.TrafficThresholdPercent,
			"traffic_used_bytes":        usedBytes,
			"traffic_limit_bytes":       node.TrafficLimit,
		}
		if _, err := FireCommandToNode(node.InstallID, "reset-links", payload); err != nil {
			logger.Log.Warn("阈值停机触发重置链接失败", "uuid", node.UUID, "install_id", node.InstallID, "error", err)
		} else {
			setNodeTrafficThresholdReached(node, true)
			go SendThresholdStopNotification(node.Name, node.TrafficThresholdPercent, usedBytes, thresholdBytes, node.TrafficLimit)
			logger.Log.Info("节点首次达到阈值，已触发重置链接", "uuid", node.UUID, "source", source, "percent", node.TrafficThresholdPercent, "used", usedBytes, "threshold", thresholdBytes, "limit", node.TrafficLimit)
		}
	}

	return true
}

func buildTrafficThresholdConfig(node database.NodePool) *trafficThresholdRuntimeConfig {
	return &trafficThresholdRuntimeConfig{
		UUID:      strings.TrimSpace(node.UUID),
		InstallID: strings.TrimSpace(node.InstallID),
		Name:      strings.TrimSpace(node.Name),
		Limit:     node.TrafficLimit,
		LimitType: NormalizeTrafficLimitType(node.TrafficLimitType),
		Enabled:   node.TrafficThresholdEnabled,
		Percent:   NormalizeTrafficThresholdPercent(node.TrafficThresholdPercent),
		Reached:   node.TrafficThresholdReached,
	}
}

func getOrLoadTrafficThresholdConfig(installID string) *trafficThresholdRuntimeConfig {
	trafficThresholdMu.RLock()
	if cfg, ok := trafficThresholdCache[installID]; ok && cfg != nil {
		copied := *cfg
		trafficThresholdMu.RUnlock()
		return &copied
	}
	trafficThresholdMu.RUnlock()

	var node database.NodePool
	if err := database.DB.Select("uuid", "install_id", "name", "traffic_limit", "traffic_limit_type", "traffic_threshold_enabled", "traffic_threshold_percent", "traffic_threshold_reached").Where("install_id = ?", installID).First(&node).Error; err != nil {
		return nil
	}

	cfg := buildTrafficThresholdConfig(node)
	if cfg.InstallID == "" {
		return nil
	}

	trafficThresholdMu.Lock()
	trafficThresholdCache[cfg.InstallID] = cfg
	trafficThresholdMu.Unlock()

	copied := *cfg
	return &copied
}

func setNodeTrafficThresholdReached(node *database.NodePool, reached bool) {
	if node == nil {
		return
	}
	if node.TrafficThresholdReached == reached {
		return
	}

	node.TrafficThresholdReached = reached
	if strings.TrimSpace(node.UUID) != "" {
		database.DB.Model(&database.NodePool{}).Where("uuid = ?", node.UUID).Update("traffic_threshold_reached", reached)
	}

	installID := strings.TrimSpace(node.InstallID)
	if installID == "" {
		return
	}

	trafficThresholdMu.Lock()
	if cfg, ok := trafficThresholdCache[installID]; ok && cfg != nil {
		cfg.Reached = reached
	}
	trafficThresholdMu.Unlock()
}
