// 路径: internal/service/traffic_history_count.go
// 流量历史记录条数管理模块
// 设计思路：
//   - NodePool.TrafficHistoryCount 为 nil（NULL）时，表示该节点是历史存量数据，需查库初始化
//   - 非 nil 时直接使用内存计数，写入+1、删除-N，避免每次都查库
//   - 为避免启动时一次性查询所有节点造成数据库压力，采用懒加载策略：
//     仅在前端请求该节点的计数时才触发初始化查询，且一个节点只查一次

package service

import (
	"sync"

	"wirearc/internal/database"
	"wirearc/internal/logger"
)

// trafficHistoryCountInitMu 保护并发初始化同一节点的计数
var trafficHistoryCountInitMu sync.Map // key: nodeUUID → *sync.Once

// EnsureTrafficHistoryCount 确保指定节点的 TrafficHistoryCount 已初始化。
// 如果字段为 NULL（历史存量节点），则查询数据库获取实际条数并写入。
// 此函数是幂等的，同一节点只会执行一次查库操作。
func EnsureTrafficHistoryCount(nodeUUID string) int64 {
	// 先快速检查是否已有值（大多数情况下直接返回）
	var node database.NodePool
	if err := database.DB.Select("traffic_history_count").Where("uuid = ?", nodeUUID).First(&node).Error; err != nil {
		return 0
	}
	if node.TrafficHistoryCount != nil {
		return *node.TrafficHistoryCount
	}

	// NULL 值：需要查库初始化，使用 sync.Once 确保同一节点只查一次
	onceVal, _ := trafficHistoryCountInitMu.LoadOrStore(nodeUUID, &sync.Once{})
	once := onceVal.(*sync.Once)

	var count int64
	once.Do(func() {
		// 查询该节点的历史流量记录条数
		if err := database.DB.Model(&database.NodeTrafficStat{}).
			Where("node_uuid = ?", nodeUUID).
			Count(&count).Error; err != nil {
			logger.Log.Warn("初始化节点流量历史计数失败", "node_uuid", nodeUUID, "error", err)
			count = 0
		}

		// 写入数据库
		if err := database.DB.Model(&database.NodePool{}).
			Where("uuid = ?", nodeUUID).
			Update("traffic_history_count", count).Error; err != nil {
			logger.Log.Warn("写入节点流量历史计数失败", "node_uuid", nodeUUID, "error", err)
		} else {
			logger.Log.Info("节点流量历史计数已初始化", "node_uuid", nodeUUID, "count", count)
		}
	})

	// Once 执行完后再读一次确保拿到最新值
	if err := database.DB.Select("traffic_history_count").Where("uuid = ?", nodeUUID).First(&node).Error; err != nil {
		return count
	}
	if node.TrafficHistoryCount != nil {
		return *node.TrafficHistoryCount
	}
	return count
}

// IncrementTrafficHistoryCount 原子递增指定节点的历史流量记录计数（+1）。
// 用于每次写入一条 NodeTrafficStat 记录后调用。
// 如果当前值为 NULL，则不在此处初始化（留给 EnsureTrafficHistoryCount 懒加载）。
func IncrementTrafficHistoryCount(nodeUUID string) {
	database.DB.Exec(
		"UPDATE node_pool SET traffic_history_count = COALESCE(traffic_history_count, 0) + 1 WHERE uuid = ?",
		nodeUUID,
	)
}

// BatchIncrementTrafficHistoryCount 批量递增一组节点的历史流量记录计数（每个节点 +1）。
func BatchIncrementTrafficHistoryCount(nodeUUIDs []string) {
	if len(nodeUUIDs) == 0 {
		return
	}
	database.DB.Exec(
		"UPDATE node_pool SET traffic_history_count = COALESCE(traffic_history_count, 0) + 1 WHERE uuid IN ?",
		nodeUUIDs,
	)
}

// DecrementTrafficHistoryCount 原子递减指定节点的历史流量记录计数。
// delta 为本次删除的记录条数。计数不会低于 0。
func DecrementTrafficHistoryCount(nodeUUID string, delta int64) {
	if delta <= 0 {
		return
	}
	// 使用 CASE WHEN 防止减为负数
	database.DB.Exec(
		"UPDATE node_pool SET traffic_history_count = CASE WHEN COALESCE(traffic_history_count, 0) > ? THEN COALESCE(traffic_history_count, 0) - ? ELSE 0 END WHERE uuid = ?",
		delta, delta, nodeUUID,
	)
}

// ResetTrafficHistoryCount 将指定节点的历史流量记录计数重置为 0。
// 用于清除该节点所有历史流量数据后调用。
func ResetTrafficHistoryCount(nodeUUID string) {
	zero := int64(0)
	database.DB.Model(&database.NodePool{}).
		Where("uuid = ?", nodeUUID).
		Update("traffic_history_count", zero)
}

// ClearNodeTrafficHistory 清除指定节点的所有历史流量数据并重置计数。
// 不影响 NodePool 中的累计流量（traffic_up / traffic_down）。
// 返回删除的记录条数和可能的错误。
func ClearNodeTrafficHistory(nodeUUID string) (int64, error) {
	deleted, err := database.DeleteNodeTrafficStatsBatched(nodeUUID, 1000)
	if err != nil {
		return deleted, err
	}

	// 重置计数为 0
	ResetTrafficHistoryCount(nodeUUID)

	// 清理 sync.Once 缓存，使得下次查询时重新初始化
	trafficHistoryCountInitMu.Delete(nodeUUID)

	logger.Log.Info("节点历史流量数据已清除", "node_uuid", nodeUUID, "deleted", deleted)
	return deleted, nil
}

// GetNodeTrafficHistoryCount 获取节点的历史流量记录条数。
// 如果计数未初始化（NULL），会触发懒加载查库。
func GetNodeTrafficHistoryCount(nodeUUID string) int64 {
	return EnsureTrafficHistoryCount(nodeUUID)
}

// BatchDecrementTrafficHistoryCountByCleanup 根据清理操作的删除结果，
// 按节点分别递减计数。用于全局过期清理场景。
// 参数 deletedByNode: map[nodeUUID]deletedCount
func BatchDecrementTrafficHistoryCountByCleanup(deletedByNode map[string]int64) {
	for nodeUUID, delta := range deletedByNode {
		if delta > 0 {
			DecrementTrafficHistoryCount(nodeUUID, delta)
		}
	}
}
