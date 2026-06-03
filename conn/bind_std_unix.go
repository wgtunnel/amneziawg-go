//go:build linux || darwin || android

package conn

import (
	"golang.org/x/sys/unix"
)

func setSocketOptions(fd uintptr) error {
	if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return err
	}

	// Mirror upstream wireguard-go buffer sizes
	_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, socketBufferSize)
	_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, socketBufferSize)

	return nil
}
