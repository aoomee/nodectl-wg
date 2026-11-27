// 路径: internal/agent/logdedup.go
// 日志去重器：固定大小 ring-map，按 error_key 抑制重复错误日志
package agent

import (
	"fmt"
	"log"
	"sync"
	"time"
)

const (
	// 去重槽位数量
	dedupSlots = 64
	// 去重窗口期
	dedupWindow = 10 * time.Minute
)

// dedupEntry ring-map 中的单个条目
type dedupEntry struct {
	key       string    // error_key（模块+摘要）
	count     int       // 窗口期内重复次数
	firstSeen time.Time // 窗口起始时间
	lastMsg   string    // 最后一条完整消息（用于窗口结束汇总）
}

// LogDedup 固定大小 ring-map 日志去重器
// 同类错误在窗口期内仅首条打印，窗口结束后输出汇总
type LogDedup struct {
	mu      sync.Mutex
	entries [dedupSlots]dedupEntry
	index   map[string]int // key → slot index
	next    int            // 下一个可用槽位（环形）
}

// NewLogDedup 创建日志去重器
func NewLogDedup() *LogDedup {
	return &LogDedup{
		index: make(map[string]int, dedupSlots),
	}
}

// LogOrSuppress 尝试输出日志，返回 true 表示已输出，false 表示被抑制
// key: 去重键（如 "collector:read_error"）
// format + args: 与 log.Printf 相同
func (d *LogDedup) LogOrSuppress(key string, format string, args ...interface{}) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	msg := fmt.Sprintf(format, args...)

	if slot, exists := d.index[key]; exists {
		entry := &d.entries[slot]
		elapsed := now.Sub(entry.firstSeen)

		if elapsed < dedupWindow {
			// 仍在窗口期内，抑制
			entry.count++
			entry.lastMsg = msg
			return false
		}

		// 窗口到期，输出汇总并重置
		if entry.count > 0 {
			log.Printf("[Agent] 过去 %v 内 <%s> 重复 %d 次", dedupWindow, key, entry.count)
		}
		entry.count = 0
		entry.firstSeen = now
		entry.lastMsg = msg
		log.Print(msg)
		return true
	}

	// 新的 key，分配槽位
	slot := d.next

	// 如果该槽位已被占用，先驱逐旧条目
	if old := d.entries[slot]; old.key != "" {
		// 驱逐前输出汇总（如果有抑制的消息）
		if old.count > 0 {
			log.Printf("[Agent] 过去 %v 内 <%s> 重复 %d 次", dedupWindow, old.key, old.count)
		}
		delete(d.index, old.key)
	}

	d.entries[slot] = dedupEntry{
		key:       key,
		count:     0,
		firstSeen: now,
		lastMsg:   msg,
	}
	d.index[key] = slot
	d.next = (d.next + 1) % dedupSlots

	// 首次出现，正常输出
	log.Print(msg)
	return true
}

// Flush 输出所有未汇总的抑制计数（优雅退出时调用）
func (d *LogDedup) Flush() {
	d.mu.Lock()
	defer d.mu.Unlock()

	for i := range d.entries {
		entry := &d.entries[i]
		if entry.key != "" && entry.count > 0 {
			log.Printf("[Agent] 过去 %v 内 <%s> 重复 %d 次",
				time.Since(entry.firstSeen).Round(time.Second), entry.key, entry.count)
			entry.count = 0
		}
	}
}
