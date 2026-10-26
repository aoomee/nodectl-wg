package main

import (
	"context"
	"embed"
	"nodectl/internal/database"
	"nodectl/internal/logger"
	"nodectl/internal/requestmeta"
	"nodectl/internal/server"
	"nodectl/internal/service"
	"nodectl/internal/version"
	"os"
	"os/signal"
	"syscall"
	"time"
)

//go:embed templates/*
var templatesFS embed.FS

func main() {
	// 0. 强制使用北京时间，避免容器/宿主机时区差异影响统计
	if loc, err := time.LoadLocation("Asia/Shanghai"); err == nil {
		time.Local = loc
		_ = os.Setenv("TZ", "Asia/Shanghai")
	}

	// 1. 初始化日志组件
	logger.Init(logger.LoadPersistedLogLevel())
	logger.Log.Debug("Nodectl Core 正在启动", "版本号", version.Version)
	if err := requestmeta.Configure(os.Getenv(requestmeta.TrustedProxiesEnv)); err != nil {
		logger.ConsoleAndLog.Error("可信反向代理配置无效，服务未启动", "error", err)
		os.Exit(1)
	}
	// 2.初始化数据库
	database.InitDB()

	wgCtx, stopWGPairs := context.WithCancel(context.Background())
	wgDone := make(chan struct{})
	go func() {
		defer close(wgDone)
		service.StartWGPairReconciler(wgCtx)
	}()
	defer stopWGPairs()

	// 2.5 初始化 CF 优选IP模块（必须在 logger 初始化之后）
	service.InitCFIPOpt()

	// 3. 注册 OS 信号处理 (SIGINT / SIGTERM)，确保退出时清理子进程 [FIX-10]
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)

	// 后台监听退出信号
	go func() {
		sig := <-sigChan
		logger.Log.Info("收到系统退出信号，开始优雅关闭...", "signal", sig.String())

		// [FIX-09] 正确退出顺序：先停 Tunnel → 等待存量请求 → 再停 Web Server
		// 步骤 1: 停止 cloudflared 子进程（断开公网入口）
		service.StopCFTunnel()

		// 停止 CF 优选任务子进程
		service.StopCFIPOptTask()

		// Allow the WG worker to stop its remote operation and clean temporary credentials.
		server.StopWGRelay()
		stopWGPairs()
		select {
		case <-wgDone:
		case <-time.After(25 * time.Second):
			logger.Log.Warn("WG 配对协调器尚未退出，未完成操作将在下次启动清理")
		}

		// 步骤 2: 等待存量请求完成 (graceful drain)
		time.Sleep(3 * time.Second)

		// 步骤 3: 优雅关闭 Web Server
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.GracefulShutdown(ctx)

		logger.Log.Info("Nodectl Core 已安全退出")
		os.Exit(0)
	}()

	// 4. 启动 Web 服务 (将打包好的前端模板传入)
	server.Start(templatesFS)
}
