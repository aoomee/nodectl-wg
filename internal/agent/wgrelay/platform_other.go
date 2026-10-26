//go:build !linux

package wgrelay

import (
	"context"
	"net"
	"os"
)

func prerequisites() error                                                { return ErrUnsupported }
func lockState(*os.File) error                                            { return ErrUnsupported }
func unlockState(*os.File)                                                {}
func boundDial(context.Context, string, string, string) (net.Conn, error) { return nil, ErrUnsupported }
