package service

import (
	"wirearc/internal/database"
	"wirearc/internal/logger"
	"strings"

	"gorm.io/gorm"
)

// DetectProtocolFromLink 从协议链接中检测协议类型
func DetectProtocolFromLink(link string) string {
	lower := strings.ToLower(strings.TrimSpace(link))
	switch {
	case strings.HasPrefix(lower, "vmess://"):
		return "vmess"
	case strings.HasPrefix(lower, "vless://"):
		return "vless"
	case strings.HasPrefix(lower, "trojan://"):
		return "trojan"
	case strings.HasPrefix(lower, "ss://"):
		return "ss"
	case strings.HasPrefix(lower, "ssr://"):
		return "ssr"
	case strings.HasPrefix(lower, "hy2://"), strings.HasPrefix(lower, "hysteria2://"):
		return "hysteria2"
	case strings.HasPrefix(lower, "hy://"), strings.HasPrefix(lower, "hysteria://"):
		return "hysteria"
	case strings.HasPrefix(lower, "tuic://"):
		return "tuic"
	case strings.HasPrefix(lower, "socks5://"):
		return "socks5"
	case strings.HasPrefix(lower, "anytls://"):
		return "anytls"
	case strings.HasPrefix(lower, "https://"), strings.HasPrefix(lower, "http://"):
		return "http"
	default:
		return "unknown"
	}
}

// DetectNameFromLink 从协议链接中解析节点名称
func DetectNameFromLink(link string) string {
	name := detectLinkNodeName(link)
	if name == "" || name == "unknown" {
		return "自定义节点"
	}
	return name
}

// ListCustomNodes 获取所有自定义节点
func ListCustomNodes() ([]database.CustomNode, error) {
	var nodes []database.CustomNode
	if err := database.DB.Order("created_at ASC").Find(&nodes).Error; err != nil {
		logger.Log.Error("获取自定义节点列表失败", "error", err)
		return nil, err
	}
	return nodes, nil
}

// AddCustomNode 添加自定义节点
func AddCustomNode(link string, routingType int) (*database.CustomNode, error) {
	link = strings.TrimSpace(link)
	protocol := DetectProtocolFromLink(link)
	name := DetectNameFromLink(link)

	node := &database.CustomNode{
		Link:        link,
		Name:        name,
		Protocol:    protocol,
		RoutingType: routingType,
	}

	if err := database.DB.Create(node).Error; err != nil {
		logger.Log.Error("添加自定义节点失败", "error", err)
		return nil, err
	}

	logger.Log.Info("自定义节点添加成功", "id", node.ID, "name", node.Name, "protocol", protocol, "routing_type", routingType)
	return node, nil
}

// UpdateCustomNode 更新自定义节点
func UpdateCustomNode(id string, link string, routingType int) error {
	link = strings.TrimSpace(link)
	protocol := DetectProtocolFromLink(link)
	name := DetectNameFromLink(link)

	updates := map[string]interface{}{
		"link":         link,
		"name":         name,
		"protocol":     protocol,
		"routing_type": routingType,
	}

	result := database.DB.Model(&database.CustomNode{}).Where("id = ?", id).Updates(updates)
	if result.Error != nil {
		logger.Log.Error("更新自定义节点失败", "error", result.Error, "id", id)
		return result.Error
	}
	if result.RowsAffected == 0 {
		logger.Log.Warn("更新自定义节点: 节点不存在", "id", id)
	}

	return nil
}

// DeleteCustomNode 删除自定义节点
func DeleteCustomNode(id string) error {
	result := database.DB.Where("id = ?", id).Delete(&database.CustomNode{})
	if result.Error != nil {
		logger.Log.Error("删除自定义节点失败", "error", result.Error, "id", id)
		return result.Error
	}
	logger.Log.Info("自定义节点已删除", "id", id)
	return nil
}

// BatchSaveCustomNodes 批量保存自定义节点（全量替换）
func BatchSaveCustomNodes(nodes []database.CustomNode) error {
	return database.DB.Transaction(func(tx *gorm.DB) error {
		// 先删除所有旧节点
		if err := tx.Where("1 = 1").Delete(&database.CustomNode{}).Error; err != nil {
			return err
		}
		// 批量插入新节点
		for i := range nodes {
			nodes[i].Protocol = DetectProtocolFromLink(nodes[i].Link)
			nodes[i].Name = DetectNameFromLink(nodes[i].Link)
			if err := tx.Create(&nodes[i]).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
