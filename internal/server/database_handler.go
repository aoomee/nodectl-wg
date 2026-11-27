package server

import (
	"encoding/json"
	"net/http"

	"wirearc/internal/database"
	"wirearc/internal/logger"
)

// ------------------- [数据库管理 API] -------------------

// apiGetDBStatus 获取当前数据库的状态信息
func apiGetDBStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	status := database.GetDBStatus()
	cfg := database.GetCurrentDBConfig()

	sendJSON(w, "success", map[string]interface{}{
		"data":   status,
		"config": cfg,
	})
}

// apiTestDBConnection 测试 PostgreSQL 数据库连接
func apiTestDBConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		User     string `json:"user"`
		Password string `json:"password"`
		DBName   string `json:"dbname"`
		SSLMode  string `json:"sslmode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求数据格式错误")
		return
	}

	if req.Host == "" || req.User == "" || req.DBName == "" {
		sendJSON(w, "error", "主机地址、用户名和数据库名不能为空")
		return
	}

	cfg := database.DBConfig{
		Type:     "postgres",
		Host:     req.Host,
		Port:     req.Port,
		User:     req.User,
		Password: req.Password,
		DBName:   req.DBName,
		SSLMode:  req.SSLMode,
	}

	version, err := database.TestPostgresConnection(cfg)
	if err != nil {
		logger.Log.Warn("PostgreSQL 连接测试失败", "host", req.Host, "error", err)
		sendJSON(w, "error", "连接失败: "+err.Error())
		return
	}

	logger.Log.Info("PostgreSQL 连接测试成功", "host", req.Host, "version", version)
	sendJSON(w, "success", map[string]interface{}{
		"message": "连接成功",
		"version": version,
	})
}

// apiSwitchDatabase 切换数据库引擎
func apiSwitchDatabase(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Type     string `json:"type"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		User     string `json:"user"`
		Password string `json:"password"`
		DBName   string `json:"dbname"`
		SSLMode  string `json:"sslmode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求数据格式错误")
		return
	}

	if req.Type != "sqlite" && req.Type != "postgres" {
		sendJSON(w, "error", "不支持的数据库类型")
		return
	}

	cfg := database.DBConfig{
		Type:     req.Type,
		Host:     req.Host,
		Port:     req.Port,
		User:     req.User,
		Password: req.Password,
		DBName:   req.DBName,
		SSLMode:  req.SSLMode,
	}

	// 如果切换到 postgres，先验证连接参数
	if req.Type == "postgres" {
		if req.Host == "" || req.User == "" || req.DBName == "" {
			sendJSON(w, "error", "PostgreSQL 连接参数不完整")
			return
		}
		if _, err := database.TestPostgresConnection(cfg); err != nil {
			sendJSON(w, "error", "PostgreSQL 连接验证失败: "+err.Error())
			return
		}
	}

	if err := database.SwitchDatabase(cfg); err != nil {
		logger.Log.Error("切换数据库失败", "type", req.Type, "error", err)
		sendJSON(w, "error", "切换失败: "+err.Error())
		return
	}

	logger.Log.Info("数据库已成功切换", "type", req.Type)
	sendJSON(w, "success", "数据库已成功切换为 "+req.Type)
}

// apiVacuumDatabase 对 PostgreSQL 执行 VACUUM 回收死元组占用的磁盘空间
func apiVacuumDatabase(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Table string `json:"table"` // 可选，指定表名；为空则 VACUUM 整个数据库
	}
	// 允许空 body
	_ = json.NewDecoder(r.Body).Decode(&req)

	var err error
	if req.Table != "" {
		err = database.VacuumTable(req.Table)
	} else {
		err = database.VacuumDatabase()
	}

	if err != nil {
		logger.Log.Warn("VACUUM 执行失败", "table", req.Table, "error", err)
		sendJSON(w, "error", err.Error())
		return
	}

	msg := "VACUUM 执行成功，已回收可用空间"
	if req.Table != "" {
		msg = "VACUUM " + req.Table + " 执行成功"
	}
	logger.Log.Info("VACUUM 执行成功", "table", req.Table)
	sendJSON(w, "success", msg)
}

// apiMigrateDatabase 从 SQLite 迁移数据到 PostgreSQL
func apiMigrateDatabase(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		User     string `json:"user"`
		Password string `json:"password"`
		DBName   string `json:"dbname"`
		SSLMode  string `json:"sslmode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, "error", "请求数据格式错误")
		return
	}

	if req.Host == "" || req.User == "" || req.DBName == "" {
		sendJSON(w, "error", "PostgreSQL 连接参数不完整")
		return
	}

	pgCfg := database.DBConfig{
		Type:     "postgres",
		Host:     req.Host,
		Port:     req.Port,
		User:     req.User,
		Password: req.Password,
		DBName:   req.DBName,
		SSLMode:  req.SSLMode,
	}

	// 先测试连接
	if _, err := database.TestPostgresConnection(pgCfg); err != nil {
		sendJSON(w, "error", "PostgreSQL 连接失败: "+err.Error())
		return
	}

	// 执行迁移
	if err := database.MigrateToPostgres(pgCfg); err != nil {
		logger.Log.Error("数据迁移失败", "error", err)
		sendJSON(w, "error", "迁移失败: "+err.Error())
		return
	}

	logger.Log.Info("数据迁移成功: SQLite → PostgreSQL")
	sendJSON(w, "success", "数据迁移成功！所有数据已从 SQLite 复制到 PostgreSQL。")
}
