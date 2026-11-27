// 路径: internal/agent/updater_stub.go
//go:build !linux

package agent

import (
	"context"
	"time"
)

// Updater 非 Linux 平台的空实现桩
type Updater struct{}

// NewUpdater 非 Linux 返回空实例（无操作）
func NewUpdater() (*Updater, error) { return &Updater{}, nil }

// RecordStartup 非 Linux 不进行崩溃循环检测
func (u *Updater) RecordStartup() bool { return false }

// MarkHealthy 非 Linux 空操作
func (u *Updater) MarkHealthy() {}

// Run 非 Linux 空操作（立即返回）
func (u *Updater) Run(ctx context.Context) {}

// SetSkipBackgroundUpdate 非 Linux 空操作
func (u *Updater) SetSkipBackgroundUpdate(fn func() bool) {}

// TriggerCheck 非 Linux 不支持更新检查
func (u *Updater) TriggerCheck(ctx context.Context) error { return nil }

// TriggerCheckWithNotify 非 Linux 空操作
func (u *Updater) TriggerCheckWithNotify(ctx context.Context, onBeforeReexec func(targetVersion string)) error {
	return nil
}

// IsPostUpdatePending 非 Linux 恒为 false
func (u *Updater) IsPostUpdatePending() bool { return false }

// HealthTimeout 非 Linux 返回 0 表示禁用
func (u *Updater) HealthTimeout() time.Duration { return 0 }

// RollbackAndReexec 非 Linux 空操作（不会发生回滚）
func (u *Updater) RollbackAndReexec() {}

// ReexecSelf 非 Linux 空操作（不会就地重启）
func (u *Updater) ReexecSelf() {}
