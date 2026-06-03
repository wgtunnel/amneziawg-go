//go:build linux || darwin || android

package conn

import (
	"runtime"

	"golang.org/x/sys/unix"
)

func setSocketOptions(fd uintptr) error {
	if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return err
	}

	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		_ = unix.SetsockoptInt(int(fd), unix.SOL_UDP, unix.UDP_GRO, 1)
	}

	return nil
}
