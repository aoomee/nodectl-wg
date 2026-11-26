// 路径: internal/agent/collector.go
package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Collector 网卡流量采集器
// 优化：使用常驻 FD + 固定栈缓冲实现零堆分配采样
type Collector struct {
	mu       sync.RWMutex
	iface    string    // 目标网卡名
	prevRX   int64     // 上次采集的 RX 计数器值
	prevTX   int64     // 上次采集的 TX 计数器值
	prevTime time.Time // 上次采集时间
	rxRate   int64     // 实时接收速率 (bytes/s)
	txRate   int64     // 实时发送速率 (bytes/s)
	// 零分配优化：常驻 FD 与固定缓冲
	rxFile *os.File // 常驻 rx_bytes FD
	txFile *os.File // 常驻 tx_bytes FD
	rxBuf  [32]byte // 固定栈缓冲，避免堆分配
	txBuf  [32]byte // 固定栈缓冲，避免堆分配
}

// NewCollector 创建采集器实例
func NewCollector(iface string) *Collector {
	return &Collector{
		iface: iface,
	}
}

// isVirtualInterface 判断网卡是否为回环/容器/隧道等虚拟接口（不应作为物理出口网卡采集）
func isVirtualInterface(name string) bool {
	if name == "" || name == "lo" {
		return true
	}
	prefixes := []string{
		"docker",
		"veth",
		"br-",
		"virbr",
		"wg",
		"nw", // WireArc / nodectl WG 内核隧道接口（nw<13hex>）
		"tun",
		"tap",
		"tailscale",
		"cni",
		"flannel",
		"cali",
		"podman",
		"zt",
		"utun",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// parseDefaultRouteInterface 从 /proc/net/route 内容中解析默认路由出口网卡名
func parseDefaultRouteInterface(routeContent string) string {
	lines := strings.Split(routeContent, "\n")
	for i, line := range lines {
		if i == 0 {
			continue // 跳过表头
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		iface := fields[0]
		dest := fields[1]
		// Destination == 00000000 表示 IPv4 默认路由 (0.0.0.0/0)
		if dest == "00000000" && !isVirtualInterface(iface) {
			return iface
		}
	}
	return ""
}

// detectInterface 自动检测物理出口网卡
// 优先级：1. /proc/net/route 默认路由非虚拟网卡 -> 2. eth0 -> 3. /sys/class/net 首个非虚拟接口
func detectInterface() (string, error) {
	if raw, err := os.ReadFile("/proc/net/route"); err == nil {
		if iface := parseDefaultRouteInterface(string(raw)); iface != "" {
			if _, statErr := os.Stat(filepath.Join("/sys/class/net", iface, "statistics/rx_bytes")); statErr == nil {
				return iface, nil
			}
		}
	}

	// 其次检测 eth0
	if _, err := os.Stat("/sys/class/net/eth0/statistics/rx_bytes"); err == nil {
		return "eth0", nil
	}

	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return "", fmt.Errorf("无法读取 /sys/class/net: %w", err)
	}

	for _, e := range entries {
		name := e.Name()
		if isVirtualInterface(name) {
			continue
		}
		// 确认该接口有 statistics 目录
		if _, err := os.Stat(filepath.Join("/sys/class/net", name, "statistics/rx_bytes")); err == nil {
			return name, nil
		}
	}

	return "", fmt.Errorf("未找到可用的网络接口")
}

// parseUint64Bytes 从 []byte 中解析十进制无符号整数（零分配）
// 扫描到 '\n'、'\r'、'\0' 或 n 字节末尾时停止
func parseUint64Bytes(buf []byte, n int) (int64, error) {
	var result uint64
	parsed := false
	for i := 0; i < n; i++ {
		ch := buf[i]
		if ch == '\n' || ch == '\r' || ch == 0 {
			break
		}
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("非法字符 '%c' at offset %d", ch, i)
		}
		digit := uint64(ch - '0')
		// 溢出检测
		if result > (^uint64(0))/10 {
			return 0, fmt.Errorf("数值溢出")
		}
		result = result*10 + digit
		if result < digit { // 加法溢出
			return 0, fmt.Errorf("数值溢出")
		}
		parsed = true
	}
	if !parsed {
		return 0, fmt.Errorf("空数据")
	}
	return int64(result), nil
}

// sysCounterPath 返回 sysfs 计数器的完整路径
func sysCounterPath(iface, counter string) string {
	return filepath.Join("/sys/class/net", iface, "statistics", counter)
}

// openSysCounter 打开 sysfs 计数器文件
func openSysCounter(iface, counter string) (*os.File, error) {
	path := sysCounterPath(iface, counter)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开 %s 失败: %w", path, err)
	}
	return f, nil
}

// readCounter 使用常驻 FD 零分配读取计数器值
// 若 FD 失效（网卡热插拔/容器 netns 变更），自动重新打开一次
func (c *Collector) readCounter(f **os.File, buf *[32]byte, counter string) (int64, error) {
	val, err := c.readCounterOnce(*f, buf)
	if err == nil {
		return val, nil
	}
	// FD 可能失效，尝试重新打开
	if *f != nil {
		(*f).Close()
	}
	newF, openErr := openSysCounter(c.iface, counter)
	if openErr != nil {
		*f = nil
		return 0, fmt.Errorf("重新打开 %s 失败: %w (原始错误: %v)", counter, openErr, err)
	}
	*f = newF
	return c.readCounterOnce(*f, buf)
}

// readCounterOnce 单次读取：ReadAt + parseUint64Bytes，零堆分配
func (c *Collector) readCounterOnce(f *os.File, buf *[32]byte) (int64, error) {
	if f == nil {
		return 0, fmt.Errorf("文件描述符为 nil")
	}
	n, err := f.ReadAt(buf[:], 0)
	if err != nil && n == 0 {
		return 0, fmt.Errorf("ReadAt 失败: %w", err)
	}
	return parseUint64Bytes(buf[:], n)
}

// Init 初始化采集器：解析网卡名、打开常驻 FD、读取基线值
func (c *Collector) Init() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	iface := c.iface
	if iface == "" || iface == "auto" {
		detected, err := detectInterface()
		if err != nil {
			return fmt.Errorf("自动检测网卡失败: %w", err)
		}
		iface = detected
	}
	c.iface = iface

	// 打开常驻 FD
	var err error
	c.rxFile, err = openSysCounter(iface, "rx_bytes")
	if err != nil {
		return err
	}
	c.txFile, err = openSysCounter(iface, "tx_bytes")
	if err != nil {
		c.rxFile.Close()
		c.rxFile = nil
		return err
	}

	// 使用零分配路径读取初始基线
	rx, err := c.readCounterOnce(c.rxFile, &c.rxBuf)
	if err != nil {
		return fmt.Errorf("读取 rx_bytes 基线失败: %w", err)
	}
	tx, err := c.readCounterOnce(c.txFile, &c.txBuf)
	if err != nil {
		return fmt.Errorf("读取 tx_bytes 基线失败: %w", err)
	}

	c.prevRX = rx
	c.prevTX = tx
	c.prevTime = time.Now()

	return nil
}

// Sample 采集一次数据点：更新速率与原始计数器基准
// 处理计数器回绕/重置场景（机器重启、网卡重建）
// 使用常驻 FD + 固定缓冲，零堆分配
func (c *Collector) Sample() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	rx, err := c.readCounter(&c.rxFile, &c.rxBuf, "rx_bytes")
	if err != nil {
		return err
	}
	tx, err := c.readCounter(&c.txFile, &c.txBuf, "tx_bytes")
	if err != nil {
		return err
	}

	now := time.Now()

	// 检测计数器回绕/重置（当前值 < 上次值）
	if rx < c.prevRX || tx < c.prevTX {
		c.prevRX = rx
		c.prevTX = tx
		c.prevTime = now
		c.rxRate = 0
		c.txRate = 0
		return nil
	}

	// 计算瞬时速率
	elapsed := now.Sub(c.prevTime).Seconds()
	if elapsed > 0 {
		c.rxRate = int64(float64(rx-c.prevRX) / elapsed)
		c.txRate = int64(float64(tx-c.prevTX) / elapsed)
	}

	// 保存当前采样作为下一次计算的基准
	c.prevRX = rx
	c.prevTX = tx
	c.prevTime = now

	return nil
}

// GetLiveSnapshot 一次加锁同时获取速率与原始计数器
func (c *Collector) GetLiveSnapshot() (rxRate, txRate, rxBytes, txBytes int64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rxRate, c.txRate, c.prevRX, c.prevTX
}

// Close 释放常驻 FD（由 Runtime.shutdown() 调用）
func (c *Collector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var firstErr error
	if c.rxFile != nil {
		if err := c.rxFile.Close(); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
		c.rxFile = nil
	}
	if c.txFile != nil {
		if err := c.txFile.Close(); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
		c.txFile = nil
	}
	return firstErr
}

// GetInterface 返回当前使用的网卡名
func (c *Collector) GetInterface() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.iface
}
