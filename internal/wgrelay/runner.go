package wgrelay

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

//go:embed runner.py engine/*.py engine/vendor/*.sh
var engineFS embed.FS

type Result struct {
	Kind        string          `json:"kind"`
	Link        string          `json:"link,omitempty"`
	Diagnostics json.RawMessage `json:"diagnostics,omitempty"`
}
type Executor func(context.Context, Request, string, io.Writer) (Result, error)

func Python() string {
	if p := os.Getenv("NODECTL_WG_PYTHON"); p != "" {
		return p
	}
	return "python3"
}
func CheckRuntime() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, Python(), "-c", "import sys,paramiko; assert sys.version_info >= (3, 10)").Run(); err != nil {
		return fmt.Errorf("WG 需要 Python 3.10+ 和 Paramiko；请使用 WG 版 Docker 镜像，或设置 NODECTL_WG_PYTHON")
	}
	return nil
}

func Execute(ctx context.Context, r Request, folder string, output io.Writer) (Result, error) {
	var result Result
	code := filepath.Join(folder, "code")
	if err := fs.WalkDir(engineFS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		dest := filepath.Join(code, p)
		if d.IsDir() {
			return os.MkdirAll(dest, 0700)
		}
		b, err := engineFS.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dest, b, 0600)
	}); err != nil {
		return result, err
	}
	// Credentials travel through stdin; argv, environment and persistent jobs contain none.
	payload, err := json.Marshal(r)
	if err != nil {
		return result, err
	}
	defer clear(payload)
	cmd := exec.CommandContext(ctx, Python(), "-u", filepath.Join(code, "runner.py"), folder)
	cmd.Stdin = bytes.NewReader(payload)
	cmd.Stdout = output
	cmd.Stderr = output
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 45 * time.Second
	if err := cmd.Run(); err != nil {
		return result, fmt.Errorf("部署进程未成功完成：%w", err)
	}
	b, err := os.ReadFile(filepath.Join(folder, "result.json"))
	if err != nil {
		return result, err
	}
	if err = json.Unmarshal(b, &result); err != nil {
		return result, err
	}
	if result.Kind != r.Mode || (r.Mode == "deploy" && !strings.HasPrefix(result.Link, "vless://")) {
		return Result{}, fmt.Errorf("部署结果无效，未标记成功")
	}
	return result, nil
}
