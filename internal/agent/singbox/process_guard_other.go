//go:build !linux

package singbox

import "os/exec"

func configureProcessGuard(cmd *exec.Cmd) {}
