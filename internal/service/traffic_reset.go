package service

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"wirearc/internal/database"
	"wirearc/internal/logger"
)

const (
	TrafficResetModeOff           = "off"
	TrafficResetModeFixedDay      = "fixed_day"
	TrafficResetModeCalendarMonth = "calendar_month"
	TrafficResetModeIntervalDays  = "interval_days"
)

var trafficResetLoopOnce sync.Once

// NormalizeNodeTrafficResetDay normalizes monthly reset day into [0, 31].
func NormalizeNodeTrafficResetDay(v int) int {
	if v < 0 {
		return 0
	}
	if v > 31 {
		return 31
	}
	return v
}

// NormalizeTrafficResetIntervalDays normalizes interval days into [1, 365].
func NormalizeTrafficResetIntervalDays(v int) int {
	if v < 1 {
		return 30
	}
	if v > 365 {
		return 365
	}
	return v
}

// ParseTrafficResetAnchorDate parses YYYY-MM-DD date and returns local day start.
func ParseTrafficResetAnchorDate(raw string) (*time.Time, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, nil
	}
	t, err := time.ParseInLocation("2006-01-02", s, time.Local)
	if err != nil {
		return nil, fmt.Errorf("traffic_reset_anchor_date must be YYYY-MM-DD")
	}
	anchor := dayStartLocal(t)
	return &anchor, nil
}

func dayStartLocal(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	y, m, d := t.In(time.Local).Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.Local)
}

// ResolveTrafficResetAnchor resolves interval reset anchor in local date.
// Priority:
// 1) explicit anchorAt
// 2) node createdAt
// 3) now
func ResolveTrafficResetAnchor(anchorAt *time.Time, createdAt time.Time, now time.Time) time.Time {
	if anchorAt != nil && !anchorAt.IsZero() {
		return dayStartLocal(*anchorAt)
	}
	if !createdAt.IsZero() {
		return dayStartLocal(createdAt)
	}
	if now.IsZero() {
		now = time.Now()
	}
	return dayStartLocal(now)
}

// NormalizeTrafficResetMode normalizes reset mode.
// Backward compatibility:
// - empty mode + reset_day > 0 => fixed_day
// - empty mode + reset_day <= 0 => off
func NormalizeTrafficResetMode(raw string, resetDay int) string {
	day := NormalizeNodeTrafficResetDay(resetDay)
	mode := strings.ToLower(strings.TrimSpace(raw))

	switch mode {
	case "":
		if day > 0 {
			return TrafficResetModeFixedDay
		}
		return TrafficResetModeOff
	case TrafficResetModeOff, "none", "disabled", "disable":
		return TrafficResetModeOff
	case TrafficResetModeFixedDay, "fixed", "monthly", "month_day", "day":
		if day <= 0 {
			return TrafficResetModeOff
		}
		return TrafficResetModeFixedDay
	case TrafficResetModeCalendarMonth, "natural_month", "calendar", "month_start":
		return TrafficResetModeCalendarMonth
	case TrafficResetModeIntervalDays, "interval", "days", "day_interval":
		return TrafficResetModeIntervalDays
	default:
		if day > 0 {
			return TrafficResetModeFixedDay
		}
		return TrafficResetModeOff
	}
}

// ResolveTrafficResetAtOnRuleChange initializes last reset timestamp when the
// reset rule is created or changed.
//
// For fixed-day mode, if the target day in the current month has not arrived
// yet, we anchor the last reset to the previous month so the upcoming day in
// this month can still trigger normally. If the target day has already arrived,
// we treat the current month as already initialized to avoid an immediate
// catch-up reset right after the rule change.
func ResolveTrafficResetAtOnRuleChange(mode string, resetDay int, now time.Time) *time.Time {
	if now.IsZero() {
		now = time.Now()
	}
	now = now.In(time.Local)

	switch NormalizeTrafficResetMode(mode, resetDay) {
	case TrafficResetModeIntervalDays, TrafficResetModeOff:
		return nil
	case TrafficResetModeCalendarMonth:
		resetAt := dayStartLocal(now)
		return &resetAt
	case TrafficResetModeFixedDay:
		resetDay = NormalizeNodeTrafficResetDay(resetDay)
		if resetDay <= 0 {
			return nil
		}

		targetDay := resetDay
		if targetDay > lastDayOfMonth(now) {
			targetDay = lastDayOfMonth(now)
		}
		if now.Day() < targetDay {
			prevMonth := now.AddDate(0, -1, 0)
			prevTargetDay := resetDay
			if prevTargetDay > lastDayOfMonth(prevMonth) {
				prevTargetDay = lastDayOfMonth(prevMonth)
			}
			resetAt := time.Date(prevMonth.Year(), prevMonth.Month(), prevTargetDay, 0, 0, 0, 0, now.Location())
			return &resetAt
		}

		resetAt := dayStartLocal(now)
		return &resetAt
	default:
		return nil
	}
}

// StartTrafficAutoResetLoop starts background traffic reset scheduler once.
func StartTrafficAutoResetLoop() {
	trafficResetLoopOnce.Do(func() {
		go runTrafficAutoResetLoop()
	})
}

func runTrafficAutoResetLoop() {
	// Run once at startup to avoid waiting for the first minute tick.
	handleTrafficAutoResetTick(time.Now())

	alignTimer := time.NewTimer(durationUntilNextMinuteBoundary(time.Now()))
	defer alignTimer.Stop()
	<-alignTimer.C
	handleTrafficAutoResetTick(time.Now())

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for now := range ticker.C {
		handleTrafficAutoResetTick(now)
	}
}

func durationUntilNextMinuteBoundary(now time.Time) time.Duration {
	if now.IsZero() {
		now = time.Now()
	}
	next := now.Truncate(time.Minute).Add(time.Minute)
	wait := next.Sub(now)
	if wait <= 0 {
		return time.Minute
	}
	return wait
}

func handleTrafficAutoResetTick(now time.Time) {
	var nodes []database.NodePool
	if err := database.DB.
		Select("uuid", "install_id", "name", "reset_day", "traffic_reset_mode", "traffic_reset_interval_days", "traffic_reset_anchor_at", "traffic_reset_at", "created_at").
		Where("install_id <> ?", "").
		Find(&nodes).Error; err != nil {
		logger.Log.Warn("traffic reset scan failed", "error", err)
		return
	}

	for _, node := range nodes {
		mode := NormalizeTrafficResetMode(node.TrafficResetMode, node.ResetDay)
		resetDay := NormalizeNodeTrafficResetDay(node.ResetDay)
		intervalDays := NormalizeTrafficResetIntervalDays(node.TrafficResetIntervalDays)

		if !shouldResetNodeTrafficNow(mode, resetDay, intervalDays, node.TrafficResetAt, node.TrafficResetAnchorAt, node.CreatedAt, now) {
			continue
		}

		if err := resetNodeTrafficCycle(&node, mode, resetDay, intervalDays, now); err != nil {
			logger.Log.Warn("node traffic auto reset failed",
				"uuid", node.UUID,
				"install_id", node.InstallID,
				"name", strings.TrimSpace(node.Name),
				"mode", mode,
				"error", err)
		}
	}
}

func shouldResetNodeTrafficNow(mode string, resetDay int, intervalDays int, lastResetAt *time.Time, anchorAt *time.Time, createdAt time.Time, now time.Time) bool {
	if now.IsZero() {
		now = time.Now()
	}
	now = now.In(time.Local)

	switch mode {
	case TrafficResetModeCalendarMonth:
		// From the 1st day onward, reset once per month if not done yet.
		return !wasResetInSameMonth(lastResetAt, now)
	case TrafficResetModeFixedDay:
		if resetDay <= 0 {
			return false
		}
		targetDay := resetDay
		lastDay := lastDayOfMonth(now)
		if targetDay > lastDay {
			targetDay = lastDay
		}
		// If scheduler was down on target day, allow catch-up later in the same month.
		if now.Day() < targetDay {
			return false
		}
		return !wasResetInCurrentFixedDayCycle(lastResetAt, now, targetDay)
	case TrafficResetModeIntervalDays:
		intervalDays = NormalizeTrafficResetIntervalDays(intervalDays)

		anchor := ResolveTrafficResetAnchor(anchorAt, createdAt, now)

		currCycle := intervalCycleIndex(anchor, dayStartLocal(now), intervalDays)
		if currCycle < 1 {
			return false
		}
		lastCycle := -1
		if lastResetAt != nil && !lastResetAt.IsZero() {
			lastCycle = intervalCycleIndex(anchor, dayStartLocal(*lastResetAt), intervalDays)
		}
		return currCycle > lastCycle
	default:
		return false
	}
}

func intervalCycleIndex(anchor, t time.Time, intervalDays int) int {
	intervalDays = NormalizeTrafficResetIntervalDays(intervalDays)
	if anchor.IsZero() || t.IsZero() {
		return -1
	}
	if t.Before(anchor) {
		return -1
	}
	days := localDateDiffDays(anchor, t)
	if days < 0 {
		return -1
	}
	return days / intervalDays
}

func localDateDiffDays(start, end time.Time) int {
	return localDateSerial(end) - localDateSerial(start)
}

func localDateSerial(t time.Time) int {
	y, m, d := t.In(time.Local).Date()
	// Use UTC midnight serial to avoid DST-related 23h/25h day skew.
	return int(time.Date(y, m, d, 0, 0, 0, 0, time.UTC).Unix() / 86400)
}

func wasResetInSameMonth(lastResetAt *time.Time, now time.Time) bool {
	if lastResetAt == nil || lastResetAt.IsZero() {
		return false
	}
	last := lastResetAt.In(now.Location())
	return last.Year() == now.Year() && last.Month() == now.Month()
}

func wasResetInCurrentFixedDayCycle(lastResetAt *time.Time, now time.Time, targetDay int) bool {
	if !wasResetInSameMonth(lastResetAt, now) {
		return false
	}
	last := lastResetAt.In(now.Location())
	return last.Day() >= targetDay
}

func lastDayOfMonth(t time.Time) int {
	y, m, _ := t.Date()
	loc := t.Location()
	return time.Date(y, m+1, 0, 0, 0, 0, 0, loc).Day()
}

func resetNodeTrafficCycle(node *database.NodePool, mode string, resetDay int, intervalDays int, now time.Time) error {
	if node == nil || strings.TrimSpace(node.UUID) == "" {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	now = now.In(time.Local)

	if err := database.DB.Model(&database.NodePool{}).
		Where("uuid = ?", node.UUID).
		Updates(map[string]interface{}{
			"traffic_up":                int64(0),
			"traffic_down":              int64(0),
			"traffic_update_at":         now,
			"traffic_threshold_reached": false,
			"traffic_reset_at":          now,
		}).Error; err != nil {
		return err
	}

	ResetNodeTrafficLiveState(node.InstallID, node.UUID, now)

	trafficThresholdMu.Lock()
	if cfg, ok := trafficThresholdCache[node.InstallID]; ok && cfg != nil {
		cfg.Reached = false
	}
	trafficThresholdMu.Unlock()

	logger.Log.Info("node traffic cycle reset",
		"uuid", node.UUID,
		"install_id", node.InstallID,
		"name", strings.TrimSpace(node.Name),
		"mode", mode,
		"reset_day", resetDay,
		"interval_days", intervalDays,
		"anchor_at", func() string {
			if node.TrafficResetAnchorAt == nil || node.TrafficResetAnchorAt.IsZero() {
				return ""
			}
			return node.TrafficResetAnchorAt.In(time.Local).Format("2006-01-02")
		}(),
		"reset_at", now.Format(time.RFC3339))

	return nil
}
