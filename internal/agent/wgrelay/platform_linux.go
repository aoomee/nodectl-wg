//go:build linux

package wgrelay

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

var wgToolInstallMu sync.Mutex

func ensureWGTools() {
	wgToolInstallMu.Lock()
	defer wgToolInstallMu.Unlock()
	if _, err := exec.LookPath("ip"); err == nil {
		if _, err := exec.LookPath("wg"); err == nil {
			return
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	env := append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l")
	runPkg := func(name string, args ...string) bool {
		if _, err := exec.LookPath(name); err != nil {
			return false
		}
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = env
		_ = cmd.Run()
		return true
	}
	switch {
	case hasBinary("apt-get"):
		runPkg("apt-get", "update", "-qq")
		runPkg("apt-get", "install", "-y", "-qq", "--no-install-recommends", "iproute2", "wireguard-tools")
	case hasBinary("dnf"):
		runPkg("dnf", "install", "-y", "-q", "iproute", "wireguard-tools")
	case hasBinary("yum"):
		runPkg("yum", "install", "-y", "-q", "iproute", "wireguard-tools")
	case hasBinary("apk"):
		runPkg("apk", "add", "--no-cache", "iproute2", "wireguard-tools")
	}
}

func hasBinary(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func prerequisites() error {
	if os.Geteuid() != 0 {
		return ErrUnsupported
	}
	if s, err := os.Stat("/run/systemd/system"); err != nil || !s.IsDir() {
		return ErrUnsupported
	}
	if !hasBinary("ip") || !hasBinary("wg") {
		ensureWGTools()
	}
	for _, name := range []string{"ip", "wg"} {
		if !hasBinary(name) {
			return ErrUnsupported
		}
	}
	return nil
}
func lockState(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) }
func unlockState(f *os.File)     { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
func boundDial(ctx context.Context, device, source, destination string) (net.Conn, error) {
	ip := net.ParseIP(source)
	if ip == nil || ip.To4() == nil || device == "" {
		return nil, errors.New("invalid bound dial parameters")
	}
	d := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second, LocalAddr: &net.TCPAddr{IP: ip}, Control: func(_, _ string, raw syscall.RawConn) error {
		var bindErr error
		if err := raw.Control(func(fd uintptr) {
			bindErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
		}); err != nil {
			return err
		}
		return bindErr
	}}
	return d.DialContext(ctx, "tcp4", destination)
}
