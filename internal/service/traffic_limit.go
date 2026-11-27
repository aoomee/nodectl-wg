package service

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

var trafficLimitInputRegexp = regexp.MustCompile(`(?i)^\s*([0-9]+(?:\.[0-9]+)?)\s*([kmgt]?b?|[kmgt])\s*$`)

// NormalizeTrafficLimitType 归一化流量限额计算类型。
// 支持: total | max | min | up | down（兼容中英文别名）
func NormalizeTrafficLimitType(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "", "total", "sum", "all", "总和":
		return "total"
	case "max", "最大":
		return "max"
	case "min", "最小":
		return "min"
	case "up", "upload", "上传":
		return "up"
	case "down", "download", "下载":
		return "down"
	default:
		return "total"
	}
}

func TrafficLimitTypeCN(v string) string {
	switch NormalizeTrafficLimitType(v) {
	case "max":
		return "最大"
	case "min":
		return "最小"
	case "up":
		return "上传"
	case "down":
		return "下载"
	default:
		return "总和"
	}
}

// ComputeTrafficUsedByLimitType 根据限额类型计算已用流量。
func ComputeTrafficUsedByLimitType(up, down int64, limitType string) int64 {
	t := NormalizeTrafficLimitType(limitType)
	switch t {
	case "max":
		if up > down {
			return up
		}
		return down
	case "min":
		if up < down {
			return up
		}
		return down
	case "up":
		return up
	case "down":
		return down
	default:
		return up + down
	}
}

// ParseTrafficLimitInputToBytes 解析“数字 + 单位”文本为字节数。
// 支持单位: B/K/KB/M/MB/G/GB/T/TB（大小写均可）。
// 识别失败时返回 0。
func ParseTrafficLimitInputToBytes(raw string) int64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	m := trafficLimitInputRegexp.FindStringSubmatch(raw)
	if len(m) != 3 {
		return 0
	}

	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil || n <= 0 {
		return 0
	}

	unit := strings.ToUpper(strings.TrimSpace(m[2]))
	multiplier := float64(1)
	switch unit {
	case "B":
		multiplier = 1
	case "K", "KB":
		multiplier = 1024
	case "M", "MB":
		multiplier = 1024 * 1024
	case "G", "GB":
		multiplier = 1024 * 1024 * 1024
	case "T", "TB":
		multiplier = 1024 * 1024 * 1024 * 1024
	default:
		return 0
	}

	v := n * multiplier
	if v <= 0 {
		return 0
	}
	if v >= float64(math.MaxInt64) {
		return math.MaxInt64
	}
	return int64(v)
}

// NormalizeTrafficThresholdPercent 归一化阈值百分比到 0-100。
// 0 表示不限制。
func NormalizeTrafficThresholdPercent(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
