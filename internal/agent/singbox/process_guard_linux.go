//go:build linux

package singbox

import (
	"os/exec"
	"syscall"
)

// A managed proxy must not outlive the agent that owns its route lease.
func configureProcessGuard(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGTERM
}
