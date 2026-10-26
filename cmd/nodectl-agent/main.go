// 路径: cmd/nodectl-agent/main.go
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"

	"nodectl/internal/agent"
)

func main() {
	// Subcommand has its own FlagSet; existing daemon flags remain unchanged.
	if len(os.Args) > 1 && os.Args[1] == "enroll" {
		fs := flag.NewFlagSet("enroll", flag.ExitOnError)
		path := fs.String("config", agent.DefaultConfigPath, "配置文件路径")
		token := fs.String("token", "", "one-time enrollment token (prefer NODECTL_ENROLLMENT_TOKEN or stdin)")
		_ = fs.Parse(os.Args[2:])
		if *token == "" {
			*token = os.Getenv("NODECTL_ENROLLMENT_TOKEN")
		}
		if *token == "" {
			fmt.Fprint(os.Stderr, "请输入一次性绑定令牌并按回车：")
			data, err := bufio.NewReader(io.LimitReader(os.Stdin, 66)).ReadString('\n')
			if err != nil && err != io.EOF {
				log.Fatal("cannot read enrollment token")
			}
			*token = strings.TrimSpace(data)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if err := agent.EnrollAgent(ctx, *path, *token); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Agent enrolled; permanent credential saved with mode 0600.")
		return
	}
	configPath := flag.String("config", agent.DefaultConfigPath, "配置文件路径")
	showVersion := flag.Bool("version", false, "显示版本号")
	flag.Parse()

	if *showVersion {
		fmt.Printf("nodectl-agent %s (commit=%s, built=%s)\n",
			agent.AgentVersion, agent.GitCommit, agent.BuildTime)
		os.Exit(0)
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
	log.SetPrefix("")

	// 统一日志：同时写入 stdout 和一个有大小上限的文件。
	// 服务管理器不要再把 stdout 重定向到同一个文件，否则每条日志会重复写入。
	agentLogPath := "/var/log/nodectl-agent.log"
	if dir := filepath.Dir(agentLogPath); dir != "" {
		if err := os.MkdirAll(dir, 0755); err == nil {
			logFile := &lumberjack.Logger{
				Filename:   agentLogPath,
				MaxSize:    20,
				MaxBackups: 5,
				MaxAge:     14,
				Compress:   true,
			}
			log.SetOutput(io.MultiWriter(os.Stdout, logFile))
		} else {
			log.Printf("[Agent] 无法创建日志目录 %s: %v (仅输出到 stdout)", dir, err)
		}
	}

	// 设置 GOMEMLIMIT（如果环境变量未覆盖，则使用 5 MiB 软上限）
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(5 << 20) // 5 MiB
	}

	// 设置 GOGC（如果环境变量未覆盖，则使用更激进的 10）
	// 说明：更小的 GOGC 会更频繁 GC，以换取更低内存占用。
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(10)
	}

	// 初始化自动更新器 + 崩溃循环检测
	updater, err := agent.NewUpdater()
	if err != nil {
		log.Printf("[Agent] 初始化更新器失败 (将禁用自动更新): %v", err)
	}
	if updater != nil {
		if needRestart := updater.RecordStartup(); needRestart {
			// 崩溃次数已达上限，RecordStartup 已将旧版本还原到 selfPath。
			// 优先通过 ReexecSelf() 就地加载旧二进制（同 PID，无需 systemd 重启）；
			// 若 execve 失败则 ReexecSelf 内部会调用 os.Exit(1) 由 systemd 兜底。
			log.Printf("[Agent] 连续崩溃已达阈值，已回滚到旧版本，尝试就地加载旧二进制...")
			updater.ReexecSelf() // 不会返回
		}
	}

	// 1. 加载配置
	cfg, err := agent.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("[Agent] 加载配置失败: %v", err)
	}

	// 2. 创建并启动运行时
	rt := agent.NewRuntime(cfg, updater)
	if err := rt.Run(); err != nil {
		log.Fatalf("[Agent] 运行时异常退出: %v", err)
	}
}
