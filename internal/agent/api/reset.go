// 路径: internal/agent/api/reset.go
// 协议重置处理模块
// 处理单个/批量协议重置：重新生成密钥/密码/UUID
// 注意：链接上报已迁移至 WebSocket 通道（runtime.go 中的 reportLinksUpdate），
// 本模块不再负责上报，仅负责凭据重置和配置重载。
package api

import (
	"context"
	"fmt"
	"log"

	"wirearc/internal/agent/singbox"
)

// ResetHandler 协议重置处理器
type ResetHandler struct {
	configMgr *singbox.ConfigManager
	manager   *singbox.Manager
	publicIP  string
}

// NewResetHandler 创建重置处理器
func NewResetHandler(configMgr *singbox.ConfigManager, manager *singbox.Manager, publicIP string) *ResetHandler {
	return &ResetHandler{
		configMgr: configMgr,
		manager:   manager,
		publicIP:  publicIP,
	}
}

// ResetProtocol 重置单个协议（重新生成凭据）
func (h *ResetHandler) ResetProtocol(ctx context.Context, protocol string) error {
	if !singbox.ValidateProtocolName(protocol) {
		return fmt.Errorf("未知协议: %s", protocol)
	}

	log.Printf("[Reset] 重置协议: %s", protocol)

	// 重新生成凭据
	if err := h.regenerateCredentials(protocol); err != nil {
		return fmt.Errorf("重新生成 %s 凭据失败: %w", protocol, err)
	}

	// 保存协议缓存
	if err := h.configMgr.SaveToCache(); err != nil {
		return fmt.Errorf("保存协议缓存失败: %w", err)
	}

	// 重新生成 sing-box 配置并重启
	if h.manager != nil {
		if err := h.manager.ReloadConfig(ctx); err != nil {
			return fmt.Errorf("重载配置失败: %w", err)
		}
	}

	// 链接上报已迁移至 WS 通道，由调用方（runtime.go reportLinksUpdate）负责

	log.Printf("[Reset] 协议 %s 重置完成", protocol)
	return nil
}

// ResetMultiple 批量重置多个协议
func (h *ResetHandler) ResetMultiple(ctx context.Context, protocols []string) error {
	if len(protocols) == 0 {
		return fmt.Errorf("协议列表不能为空")
	}

	log.Printf("[Reset] 批量重置协议: %v", protocols)

	// 逐个重新生成凭据
	for _, protocol := range protocols {
		if !singbox.ValidateProtocolName(protocol) {
			log.Printf("[Reset] 跳过未知协议: %s", protocol)
			continue
		}
		if err := h.regenerateCredentials(protocol); err != nil {
			return fmt.Errorf("重新生成 %s 凭据失败: %w", protocol, err)
		}
	}

	// 保存协议缓存
	if err := h.configMgr.SaveToCache(); err != nil {
		return fmt.Errorf("保存协议缓存失败: %w", err)
	}

	// 重新生成 sing-box 配置并重启（仅一次）
	if h.manager != nil {
		if err := h.manager.ReloadConfig(ctx); err != nil {
			return fmt.Errorf("重载配置失败: %w", err)
		}
	}

	// 链接上报已迁移至 WS 通道，由调用方（runtime.go reportLinksUpdate）负责

	log.Printf("[Reset] 批量重置完成: %v", protocols)
	return nil
}

// regenerateCredentials 为指定协议重新生成凭据（密码/UUID/密钥）
func (h *ResetHandler) regenerateCredentials(protocol string) error {
	pc := h.configMgr.Protocols

	switch protocol {
	case singbox.ProtoSS:
		password, err := singbox.GenerateSSPassword(pc.SS.Method)
		if err != nil {
			return err
		}
		pc.SS.Password = password

	case singbox.ProtoHY2:
		password, err := singbox.GeneratePassword(16)
		if err != nil {
			return err
		}
		pc.HY2.Password = password

	case singbox.ProtoTUIC:
		uuid, err := singbox.GenerateUUID()
		if err != nil {
			return err
		}
		password, err := singbox.GeneratePassword(16)
		if err != nil {
			return err
		}
		pc.TUIC.UUID = uuid
		pc.TUIC.Password = password

	case singbox.ProtoReality:
		uuid, err := singbox.GenerateUUID()
		if err != nil {
			return err
		}
		keyPair, err := singbox.GenerateRealityKeyPair()
		if err != nil {
			return err
		}
		shortID, err := singbox.GenerateShortID()
		if err != nil {
			return err
		}
		pc.Reality.UUID = uuid
		pc.Reality.PrivateKey = keyPair.PrivateKey
		pc.Reality.PublicKey = keyPair.PublicKey
		pc.Reality.ShortID = shortID

	case singbox.ProtoSocks5:
		username, err := singbox.GeneratePassword(12)
		if err != nil {
			return err
		}
		password, err := singbox.GeneratePassword(16)
		if err != nil {
			return err
		}
		pc.Socks5.Username = username
		pc.Socks5.Password = password

	case singbox.ProtoTrojan:
		password, err := singbox.GeneratePassword(16)
		if err != nil {
			return err
		}
		pc.Trojan.Password = password

	case singbox.ProtoAnyTLS:
		uuid, err := singbox.GenerateUUID()
		if err != nil {
			return err
		}
		pc.AnyTLS.Password = uuid

	// VMess 族：重置共用 UUID
	case singbox.ProtoVmessTCP, singbox.ProtoVmessWS, singbox.ProtoVmessHTTP,
		singbox.ProtoVmessQUIC, singbox.ProtoVmessWST, singbox.ProtoVmessHUT:
		uuid, err := singbox.GenerateUUID()
		if err != nil {
			return err
		}
		pc.VMess.UUID = uuid

	// VLESS-TLS 族：重置共用 UUID
	case singbox.ProtoVlessWST, singbox.ProtoVlessHUT:
		uuid, err := singbox.GenerateUUID()
		if err != nil {
			return err
		}
		pc.VlessTLS.UUID = uuid

	// Trojan-TLS 族：重置共用密码
	case singbox.ProtoTrojanWST, singbox.ProtoTrojanHUT:
		password, err := singbox.GeneratePassword(16)
		if err != nil {
			return err
		}
		pc.TrojanTLS.Password = password

	default:
		return fmt.Errorf("不支持重置的协议: %s", protocol)
	}

	return nil
}
