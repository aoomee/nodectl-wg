package service

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"wirearc/internal/database"

	"gorm.io/gorm"
)

const trafficCleanupMinInterval = 10 * time.Minute

var (
	trafficCleanupMu   sync.Mutex
	lastTrafficCleanup time.Time
)

func shouldRunTrafficCleanup(now time.Time) bool {
	trafficCleanupMu.Lock()
	defer trafficCleanupMu.Unlock()
	if !lastTrafficCleanup.IsZero() && now.Sub(lastTrafficCleanup) < trafficCleanupMinInterval {
		return false
	}
	lastTrafficCleanup = now
	return true
}

// TrafficBatchItem 批量落库单节点流量项
type TrafficBatchItem struct {
	InstallID string
	RXBytes   int64
	TXBytes   int64
}

func isNodeTrafficStatsPrimaryKeyConflict(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "node_traffic_stats_pkey") && strings.Contains(msg, "SQLSTATE 23505")
}

func saveNodeTrafficTotalOnce(installID string, rxBytes, txBytes int64, reportedAt time.Time) (bool, error) {
	now := time.Now()
	res := database.DB.Model(&database.NodePool{}).
		Where("install_id = ?", installID).
		Updates(map[string]interface{}{
			"traffic_down":      rxBytes,
			"traffic_up":        txBytes,
			"traffic_update_at": reportedAt,
			"updated_at":        now,
		})
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

// SaveNodeTrafficTotalsBatch 在单个事务内批量更新多个节点的累计流量，显著降低 SQLite 写锁与事务开销。
func SaveNodeTrafficTotalsBatch(items []TrafficBatchItem, reportedAt time.Time) error {
	if len(items) == 0 {
		return nil
	}
	if reportedAt.IsZero() {
		reportedAt = time.Now()
	}
	now := time.Now()
	return database.DB.Transaction(func(tx *gorm.DB) error {
		for _, item := range items {
			iid := strings.TrimSpace(item.InstallID)
			if iid == "" {
				continue
			}
			if err := tx.Model(&database.NodePool{}).
				Where("install_id = ?", iid).
				Updates(map[string]interface{}{
					"traffic_down":      item.RXBytes,
					"traffic_up":        item.TXBytes,
					"traffic_update_at": reportedAt,
					"updated_at":        now,
				}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func saveNodeTrafficPointsBatchOnce(items []TrafficBatchItem, reportedAt time.Time) error {
	installIDs := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		iid := strings.TrimSpace(item.InstallID)
		if iid == "" {
			continue
		}
		if _, ok := seen[iid]; ok {
			continue
		}
		seen[iid] = struct{}{}
		installIDs = append(installIDs, iid)
	}
	if len(installIDs) == 0 {
		return nil
	}

	var savedUUIDs []string
	hk := hourKey(reportedAt)
	thk := twoHourKey(reportedAt)
	dk := dayKey(reportedAt)

	err := database.DB.Transaction(func(tx *gorm.DB) error {
		var nodes []database.NodePool
		if err := tx.Select("uuid", "install_id").Where("install_id IN ?", installIDs).Find(&nodes).Error; err != nil {
			return err
		}
		if len(nodes) == 0 {
			return nil
		}
		uuidByInstall := make(map[string]string, len(nodes))
		for _, n := range nodes {
			uuidByInstall[n.InstallID] = n.UUID
		}

		records := make([]database.NodeTrafficStat, 0, len(nodes))
		savedUUIDs = make([]string, 0, len(nodes))
		for _, item := range items {
			iid := strings.TrimSpace(item.InstallID)
			uid, ok := uuidByInstall[iid]
			if !ok || uid == "" {
				continue
			}
			records = append(records, database.NodeTrafficStat{
				NodeUUID:   uid,
				ReportedAt: reportedAt,
				HourKey:    hk,
				TwoHourKey: thk,
				DayKey:     dk,
				TXBytes:    item.TXBytes,
				RXBytes:    item.RXBytes,
			})
			savedUUIDs = append(savedUUIDs, uid)
		}
		if len(records) == 0 {
			return nil
		}
		if err := tx.CreateInBatches(records, 100).Error; err != nil {
			return err
		}

		if shouldRunTrafficCleanup(reportedAt) {
			retentionDays := loadTrafficRetentionDays(tx)
			if err := cleanupExpiredTrafficStats(tx, reportedAt, retentionDays); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	if len(savedUUIDs) > 0 {
		BatchIncrementTrafficHistoryCount(savedUUIDs)
	}
	return nil
}

// SaveNodeTrafficPointsBatch 批量写入多个节点的历史流量采样点，并节流执行过期清理。
func SaveNodeTrafficPointsBatch(items []TrafficBatchItem, reportedAt time.Time) error {
	if len(items) == 0 {
		return nil
	}
	if reportedAt.IsZero() {
		reportedAt = time.Now()
	}
	err := saveNodeTrafficPointsBatchOnce(items, reportedAt)
	if err == nil {
		return nil
	}
	if !isNodeTrafficStatsPrimaryKeyConflict(err) {
		return err
	}
	if syncErr := database.SyncNodeTrafficStatSequence(); syncErr != nil {
		return fmt.Errorf("批量写入失败且序列同步失败: %v; 原始错误: %w", syncErr, err)
	}
	return saveNodeTrafficPointsBatchOnce(items, reportedAt)
}

func saveNodeTrafficPointOnce(installID string, rxBytes, txBytes int64, reportedAt time.Time) (bool, error) {
	found := false
	var savedNodeUUID string
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		var node database.NodePool
		if err := tx.Where("install_id = ?", installID).First(&node).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return nil
			}
			return err
		}
		found = true
		savedNodeUUID = node.UUID

		rec := database.NodeTrafficStat{
			NodeUUID:   node.UUID,
			ReportedAt: reportedAt,
			HourKey:    hourKey(reportedAt),
			TwoHourKey: twoHourKey(reportedAt),
			DayKey:     dayKey(reportedAt),
			TXBytes:    txBytes,
			RXBytes:    rxBytes,
		}
		if err := tx.Create(&rec).Error; err != nil {
			return err
		}

		retentionDays := loadTrafficRetentionDays(tx)
		if err := cleanupExpiredTrafficStats(tx, reportedAt, retentionDays); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return false, err
	}

	// 事务成功后递增历史流量记录计数
	if found && savedNodeUUID != "" {
		IncrementTrafficHistoryCount(savedNodeUUID)
	}

	return found, nil
}

type TrafficLandingNode struct {
	UUID             string `json:"uuid"`
	InstallID        string `json:"install_id"`
	Name             string `json:"name"`
	Region           string `json:"region"`
	TrafficLimit     int64  `json:"traffic_limit"`
	TrafficLimitType string `json:"traffic_limit_type"`
}

type TrafficConsumptionItem struct {
	UUID             string `json:"uuid"`
	InstallID        string `json:"install_id"`
	Name             string `json:"name"`
	Region           string `json:"region"`
	Offline          bool   `json:"offline"`
	TrafficLimit     int64  `json:"traffic_limit"`
	TrafficLimitType string `json:"traffic_limit_type"`
	TrafficUsedBytes int64  `json:"traffic_used_bytes"`
	TrafficUp        int64  `json:"traffic_up"`
	TrafficDown      int64  `json:"traffic_down"`
	TotalBytes       int64  `json:"total_bytes"`
	TodayTotalBytes  int64  `json:"today_total_bytes"`
	LiveTotalUp      int64  `json:"live_total_up"`
	LiveTotalDown    int64  `json:"live_total_down"`
	LiveTotalBytes   int64  `json:"live_total_bytes"`
	LiveRXRateBps    int64  `json:"live_rx_rate_bps"`
	LiveTXRateBps    int64  `json:"live_tx_rate_bps"`
	LiveLastAt       int64  `json:"live_last_at"`
	HasLiveTotal     bool   `json:"has_live_total"`
	UploadRatio      string `json:"upload_ratio"`
	TrafficUpdateAt  string `json:"traffic_update_at"`
}

type TrafficConsumptionRank struct {
	GeneratedAt string                   `json:"generated_at"`
	TotalUp     int64                    `json:"total_up"`
	TotalDown   int64                    `json:"total_down"`
	TotalBytes  int64                    `json:"total_bytes"`
	Items       []TrafficConsumptionItem `json:"items"`
}

type TrafficSeriesOptions struct {
	NodeUUID      string
	Hours         int
	IntervalHours int
	Mode          string // total | increment
	Date          string // YYYY-MM-DD
	Raw           bool   // true: 直接返回原始采样点
}

type TrafficSeriesPoint struct {
	Time       string `json:"time"`
	Label      string `json:"label"`
	UpBytes    int64  `json:"up_bytes"`
	DownBytes  int64  `json:"down_bytes"`
	TotalBytes int64  `json:"total_bytes"`
}

type TrafficSeriesResult struct {
	NodeUUID      string               `json:"node_uuid"`
	NodeName      string               `json:"node_name"`
	Mode          string               `json:"mode"`
	Hours         int                  `json:"hours"`
	IntervalHours int                  `json:"interval_hours"`
	GeneratedAt   string               `json:"generated_at"`
	Points        []TrafficSeriesPoint `json:"points"`
}

type hourlyAgg struct {
	Has      bool
	LastAt   time.Time
	LastUp   int64
	LastDown int64
	SumUp    int64
	SumDown  int64
}

func hourKey(t time.Time) int {
	return t.Year()*1000000 + int(t.Month())*10000 + t.Day()*100 + t.Hour()
}

func twoHourKey(t time.Time) int {
	h := t.Hour()
	h = (h / 2) * 2
	return t.Year()*1000000 + int(t.Month())*10000 + t.Day()*100 + h
}

func dayKey(t time.Time) int {
	return t.Year()*10000 + int(t.Month())*100 + t.Day()
}

func normalizeTrafficMode(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "increment" {
		return "increment"
	}
	return "total"
}

func normalizeTrafficHours(v int) int {
	if v <= 0 {
		return 24
	}
	if v > 24*14 {
		return 24 * 14
	}
	return v
}

func normalizeTrafficIntervalHours(v int) int {
	if v == 2 {
		return 2
	}
	return 1
}

func normalizeTrafficRetentionDays(v int) int {
	if v < 1 {
		return 30
	}
	if v > 3650 {
		return 3650
	}
	return v
}

func loadTrafficRetentionDays(tx *gorm.DB) int {
	var cfg database.SysConfig
	if err := tx.Where("key = ?", "pref_traffic_stats_retention_days").First(&cfg).Error; err != nil {
		return 30
	}
	days, err := strconv.Atoi(strings.TrimSpace(cfg.Value))
	if err != nil {
		return 30
	}
	return normalizeTrafficRetentionDays(days)
}

func cleanupExpiredTrafficStats(tx *gorm.DB, now time.Time, retentionDays int) error {
	cutoff := now.AddDate(0, 0, -normalizeTrafficRetentionDays(retentionDays))
	cutoffDayKey := dayKey(cutoff)

	// 先按节点统计即将被删除的记录数，用于后续递减计数
	type nodeDeleteCount struct {
		NodeUUID string `gorm:"column:node_uuid"`
		Cnt      int64  `gorm:"column:cnt"`
	}
	var counts []nodeDeleteCount
	tx.Model(&database.NodeTrafficStat{}).
		Select("node_uuid, COUNT(*) as cnt").
		Where("day_key < ?", cutoffDayKey).
		Group("node_uuid").
		Scan(&counts)

	// 执行删除
	if err := tx.Where("day_key < ?", cutoffDayKey).Delete(&database.NodeTrafficStat{}).Error; err != nil {
		return err
	}

	// 删除成功后，异步递减各节点的历史记录计数（不阻塞事务）
	if len(counts) > 0 {
		deletedByNode := make(map[string]int64, len(counts))
		for _, c := range counts {
			deletedByNode[c.NodeUUID] = c.Cnt
		}
		go BatchDecrementTrafficHistoryCountByCleanup(deletedByNode)
	}

	return nil
}

// SaveNodeTrafficTotalOnly 仅更新 node_pool 累计流量，不写历史点数据。
func SaveNodeTrafficTotalOnly(installID string, rxBytes, txBytes int64, reportedAt time.Time) (bool, error) {
	installID = strings.TrimSpace(installID)
	if installID == "" {
		return false, nil
	}
	if reportedAt.IsZero() {
		reportedAt = time.Now()
	}

	return saveNodeTrafficTotalOnce(installID, rxBytes, txBytes, reportedAt)
}

// SaveNodeTrafficPointOnly 仅写入历史点数据，不更新 node_pool 累计流量。
func SaveNodeTrafficPointOnly(installID string, rxBytes, txBytes int64, reportedAt time.Time) (bool, error) {
	installID = strings.TrimSpace(installID)
	if installID == "" {
		return false, nil
	}
	if reportedAt.IsZero() {
		reportedAt = time.Now()
	}

	found, err := saveNodeTrafficPointOnce(installID, rxBytes, txBytes, reportedAt)
	if err == nil {
		return found, nil
	}

	if !isNodeTrafficStatsPrimaryKeyConflict(err) {
		return false, err
	}

	// PostgreSQL 序列漂移自愈：同步序列后重试一次
	if syncErr := database.SyncNodeTrafficStatSequence(); syncErr != nil {
		return false, fmt.Errorf("写入失败且序列同步失败: %v; 原始错误: %w", syncErr, err)
	}

	return saveNodeTrafficPointOnce(installID, rxBytes, txBytes, reportedAt)
}

// GetTrafficLandingNodes 返回可用于统计的落地节点列表。
func GetTrafficLandingNodes() ([]TrafficLandingNode, error) {
	var nodes []database.NodePool
	if err := database.DB.
		Where("routing_type = ?", 2).
		Order("sort_index ASC, updated_at DESC").
		Find(&nodes).Error; err != nil {
		return nil, err
	}

	result := make([]TrafficLandingNode, 0, len(nodes))
	for _, n := range nodes {
		result = append(result, TrafficLandingNode{
			UUID:             n.UUID,
			InstallID:        n.InstallID,
			Name:             n.Name,
			Region:           strings.ToUpper(strings.TrimSpace(n.Region)),
			TrafficLimit:     n.TrafficLimit,
			TrafficLimitType: NormalizeTrafficLimitType(n.TrafficLimitType),
		})
	}
	return result, nil
}

func parseTrafficRankDate(raw string) (time.Time, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false, nil
	}
	t, err := time.ParseInLocation("2006-01-02", raw, time.Local)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("日期格式错误，需为 YYYY-MM-DD")
	}
	return t, true, nil
}

// GetTrafficConsumptionRank 返回节点流量消耗排行榜（支持按日期查询历史）。
func GetTrafficConsumptionRank(limit int, rankDate string) (*TrafficConsumptionRank, error) {
	if limit <= 0 {
		limit = 30
	}
	if limit > 200 {
		limit = 200
	}

	selectedDate, hasDate, err := parseTrafficRankDate(rankDate)
	if err != nil {
		return nil, err
	}
	if !hasDate {
		now := time.Now()
		y, m, d := now.Date()
		selectedDate = time.Date(y, m, d, 0, 0, 0, 0, now.Location())
		hasDate = true
	}

	var nodes []database.NodePool
	if err := database.DB.
		Select("uuid", "install_id", "name", "region", "traffic_limit", "traffic_limit_type", "traffic_up", "traffic_down", "traffic_update_at", "updated_at").
		Where("install_id <> ?", "").
		Order("updated_at DESC").
		Find(&nodes).Error; err != nil {
		return nil, err
	}

	dayStart := selectedDate
	targetDayKey := dayKey(dayStart)

	var samples []database.NodeTrafficStat
	if err := database.DB.
		Select("node_uuid", "reported_at", "tx_bytes", "rx_bytes").
		Where("day_key = ?", targetDayKey).
		Order("node_uuid ASC, reported_at ASC").
		Find(&samples).Error; err != nil {
		return nil, err
	}

	type trafficPair struct {
		up   int64
		down int64
	}

	prevRaw := make(map[string]trafficPair, len(nodes))
	baseline := make(map[string]trafficPair, len(nodes))
	upByNode := make(map[string]int64, len(nodes))
	downByNode := make(map[string]int64, len(nodes))
	lastAtByNode := make(map[string]time.Time, len(nodes))

	seenNode := make(map[string]struct{}, len(samples))
	for _, s := range samples {
		if _, ok := seenNode[s.NodeUUID]; ok {
			continue
		}
		seenNode[s.NodeUUID] = struct{}{}

		var b database.NodeTrafficStat
		res := database.DB.
			Select("tx_bytes", "rx_bytes").
			Where("node_uuid = ? AND reported_at < ?", s.NodeUUID, dayStart).
			Order("reported_at DESC").
			Limit(1).
			Find(&b)
		if res.Error != nil {
			return nil, res.Error
		}
		if res.RowsAffected > 0 {
			baseline[s.NodeUUID] = trafficPair{up: b.TXBytes, down: b.RXBytes}
		}
	}

	for _, s := range samples {
		currUp := s.TXBytes
		currDown := s.RXBytes

		base, hasBase := baseline[s.NodeUUID]
		prev, hasPrev := prevRaw[s.NodeUUID]

		deltaUp := currUp
		deltaDown := currDown
		if hasPrev {
			deltaUp = currUp - prev.up
			deltaDown = currDown - prev.down
		} else if hasBase {
			deltaUp = currUp - base.up
			deltaDown = currDown - base.down
		}

		if deltaUp < 0 {
			deltaUp = currUp
		}
		if deltaDown < 0 {
			deltaDown = currDown
		}

		upByNode[s.NodeUUID] += deltaUp
		downByNode[s.NodeUUID] += deltaDown
		prevRaw[s.NodeUUID] = trafficPair{up: currUp, down: currDown}

		if lastAtByNode[s.NodeUUID].IsZero() || s.ReportedAt.After(lastAtByNode[s.NodeUUID]) {
			lastAtByNode[s.NodeUUID] = s.ReportedAt
		}
	}

	liveSnapshots := GetTrafficLiveSnapshots()

	items := make([]TrafficConsumptionItem, 0, len(nodes))
	for _, n := range nodes {
		up := upByNode[n.UUID]
		down := downByNode[n.UUID]
		total := up + down
		limitType := NormalizeTrafficLimitType(n.TrafficLimitType)
		usedByLimit := ComputeTrafficUsedByLimitType(up, down, limitType)

		liveUp := n.TrafficUp
		liveDown := n.TrafficDown
		hasLiveTotal := liveUp > 0 || liveDown > 0
		var liveRXRate, liveTXRate, liveLastAt int64
		offline := true
		if snap, ok := liveSnapshots[n.InstallID]; ok {
			offline = snap.Offline
			liveUp = snap.TotalTXBytes
			liveDown = snap.TotalRXBytes
			hasLiveTotal = true
			liveRXRate = snap.RXRateBps
			liveTXRate = snap.TXRateBps
			liveLastAt = snap.LastLiveAt
		}

		ratio := "0.00"
		if up > 0 {
			ratio = fmt.Sprintf("%.2f", float64(down)/float64(up))
		}

		updateAt := "--"
		if t, ok := lastAtByNode[n.UUID]; ok && !t.IsZero() {
			updateAt = t.Format("2006-01-02 15:04")
		}

		items = append(items, TrafficConsumptionItem{
			UUID:             n.UUID,
			InstallID:        n.InstallID,
			Name:             n.Name,
			Region:           strings.ToUpper(strings.TrimSpace(n.Region)),
			Offline:          offline,
			TrafficLimit:     n.TrafficLimit,
			TrafficLimitType: limitType,
			TrafficUsedBytes: usedByLimit,
			TrafficUp:        up,
			TrafficDown:      down,
			TotalBytes:       total,
			TodayTotalBytes:  total,
			LiveTotalUp:      liveUp,
			LiveTotalDown:    liveDown,
			LiveTotalBytes:   liveUp + liveDown,
			LiveRXRateBps:    liveRXRate,
			LiveTXRateBps:    liveTXRate,
			LiveLastAt:       liveLastAt,
			HasLiveTotal:     hasLiveTotal,
			UploadRatio:      ratio,
			TrafficUpdateAt:  updateAt,
		})
	}

	sort.SliceStable(items, func(i, j int) bool {
		if items[i].TotalBytes == items[j].TotalBytes {
			if items[i].TrafficUpdateAt == items[j].TrafficUpdateAt {
				return items[i].Name < items[j].Name
			}
			return items[i].TrafficUpdateAt > items[j].TrafficUpdateAt
		}
		return items[i].TotalBytes > items[j].TotalBytes
	})

	if len(items) > limit {
		items = items[:limit]
	}

	var totalUp int64
	var totalDown int64
	for _, item := range items {
		totalUp += item.TrafficUp
		totalDown += item.TrafficDown
	}

	return &TrafficConsumptionRank{
		GeneratedAt: dayStart.Format("2006-01-02"),
		TotalUp:     totalUp,
		TotalDown:   totalDown,
		TotalBytes:  totalUp + totalDown,
		Items:       items,
	}, nil
}

// QueryTrafficSeries 查询节点流量时序统计（支持总量/增量，支持 1h/2h 粒度）。
func QueryTrafficSeries(opts TrafficSeriesOptions) (*TrafficSeriesResult, error) {
	nodeUUID := strings.TrimSpace(opts.NodeUUID)
	if nodeUUID == "" {
		return nil, fmt.Errorf("node_uuid 不能为空")
	}

	hours := normalizeTrafficHours(opts.Hours)
	intervalHours := normalizeTrafficIntervalHours(opts.IntervalHours)
	mode := normalizeTrafficMode(opts.Mode)
	selectedDate, hasDate, err := parseTrafficRankDate(opts.Date)
	if err != nil {
		return nil, err
	}

	var node database.NodePool
	if err := database.DB.Select("uuid", "name").Where("uuid = ?", nodeUUID).First(&node).Error; err != nil {
		return nil, err
	}

	now := time.Now()
	endHour := now.Truncate(time.Hour)
	startHour := endHour.Add(-time.Duration(hours-1) * time.Hour)
	if hasDate {
		hours = 24
		startHour = selectedDate
		endHour = selectedDate.Add(23 * time.Hour)
	}

	var samples []database.NodeTrafficStat
	if err := database.DB.
		Select("reported_at", "hour_key", "tx_bytes", "rx_bytes").
		Where("node_uuid = ? AND hour_key >= ? AND hour_key <= ?", nodeUUID, hourKey(startHour), hourKey(endHour)).
		Order("reported_at ASC").
		Find(&samples).Error; err != nil {
		return nil, err
	}

	var baseline database.NodeTrafficStat
	baselineUp := int64(0)
	baselineDown := int64(0)
	hasBaseline := false
	baselineRes := database.DB.
		Select("tx_bytes", "rx_bytes").
		Where("node_uuid = ? AND reported_at < ?", nodeUUID, startHour).
		Order("reported_at DESC").
		Limit(1).
		Find(&baseline)
	if baselineRes.Error != nil {
		return nil, baselineRes.Error
	}
	if baselineRes.RowsAffected > 0 {
		hasBaseline = true
		baselineUp = baseline.TXBytes
		baselineDown = baseline.RXBytes
	}

	if hasDate && opts.Raw {
		points := make([]TrafficSeriesPoint, 0, len(samples))
		prevUp := baselineUp
		prevDown := baselineDown
		hasPrev := hasBaseline

		for _, s := range samples {
			up := s.TXBytes
			down := s.RXBytes

			outUp := up
			outDown := down
			if mode == "increment" {
				if hasPrev {
					outUp = up - prevUp
					outDown = down - prevDown
					if outUp < 0 {
						outUp = up
					}
					if outDown < 0 {
						outDown = down
					}
				}
			}

			points = append(points, TrafficSeriesPoint{
				Time:       s.ReportedAt.Format(time.RFC3339),
				Label:      s.ReportedAt.Format("15:04"),
				UpBytes:    outUp,
				DownBytes:  outDown,
				TotalBytes: outUp + outDown,
			})

			prevUp = up
			prevDown = down
			hasPrev = true
		}

		return &TrafficSeriesResult{
			NodeUUID:      node.UUID,
			NodeName:      node.Name,
			Mode:          mode,
			Hours:         hours,
			IntervalHours: intervalHours,
			GeneratedAt:   now.Format(time.RFC3339),
			Points:        points,
		}, nil
	}

	// 使用 HourKey 整数（存储时基于本地时间计算）作为 map key，
	// 避免 SQLite 返回 UTC 时区的 ReportedAt 与本地时间 ts 比较失配导致所有桶为零。
	aggByHour := make(map[int]hourlyAgg, hours+2)
	prevUp := baselineUp
	prevDown := baselineDown
	hasPrev := hasBaseline

	for _, s := range samples {
		key := s.HourKey // 已在写入时用本地时间计算，与输出循环 hourKey(ts) 对齐
		agg := aggByHour[key]
		agg.Has = true

		upDelta := s.TXBytes
		downDelta := s.RXBytes
		if hasPrev {
			upDelta = s.TXBytes - prevUp
			downDelta = s.RXBytes - prevDown
			if upDelta < 0 {
				upDelta = s.TXBytes
			}
			if downDelta < 0 {
				downDelta = s.RXBytes
			}
		}
		agg.SumUp += upDelta
		agg.SumDown += downDelta

		if agg.LastAt.IsZero() || s.ReportedAt.After(agg.LastAt) {
			agg.LastAt = s.ReportedAt
			agg.LastUp = s.TXBytes
			agg.LastDown = s.RXBytes
		}
		aggByHour[key] = agg

		prevUp = s.TXBytes
		prevDown = s.RXBytes
		hasPrev = true
	}

	points := make([]TrafficSeriesPoint, 0, hours)
	runningUp := baselineUp
	runningDown := baselineDown

	for ts := startHour; !ts.After(endHour); ts = ts.Add(time.Duration(intervalHours) * time.Hour) {
		intervalEnd := ts.Add(time.Duration(intervalHours) * time.Hour)

		bucketUp := int64(0)
		bucketDown := int64(0)
		bucketLatestAt := time.Time{}
		bucketHasTotal := false

		for h := ts; h.Before(intervalEnd); h = h.Add(time.Hour) {
			agg, ok := aggByHour[hourKey(h)]
			if !ok || !agg.Has {
				continue
			}
			if mode == "increment" {
				bucketUp += agg.SumUp
				bucketDown += agg.SumDown
				continue
			}

			if !bucketHasTotal || agg.LastAt.After(bucketLatestAt) {
				bucketLatestAt = agg.LastAt
				bucketUp = agg.LastUp
				bucketDown = agg.LastDown
				bucketHasTotal = true
			}
		}

		if mode == "total" {
			if bucketHasTotal {
				runningUp = bucketUp
				runningDown = bucketDown
			} else {
				bucketUp = runningUp
				bucketDown = runningDown
			}
		}

		label := ts.Format("01-02 15:04")
		if intervalHours == 2 {
			label = fmt.Sprintf("%s~%s", ts.Format("15:00"), ts.Add(time.Hour).Format("15:00"))
		}

		points = append(points, TrafficSeriesPoint{
			Time:       ts.Format(time.RFC3339),
			Label:      label,
			UpBytes:    bucketUp,
			DownBytes:  bucketDown,
			TotalBytes: bucketUp + bucketDown,
		})
	}

	return &TrafficSeriesResult{
		NodeUUID:      node.UUID,
		NodeName:      node.Name,
		Mode:          mode,
		Hours:         hours,
		IntervalHours: intervalHours,
		GeneratedAt:   now.Format(time.RFC3339),
		Points:        points,
	}, nil
}
