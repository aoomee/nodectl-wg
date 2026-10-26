//go:build linux

package wgrelay

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func prerequisites() error {
	if os.Geteuid() != 0 {
		return ErrUnsupported
	}
	if s, err := os.Stat("/run/systemd/system"); err != nil || !s.IsDir() {
		return ErrUnsupported
	}
	for _, name := range []string{"ip", "wg"} {
		if _, err := exec.LookPath(name); err != nil {
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
