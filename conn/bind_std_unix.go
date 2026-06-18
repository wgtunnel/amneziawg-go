//go:build linux || darwin || android

package conn

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func init() {
	// register socket options to controlFns
	controlFns = append(controlFns, func(network, address string, c syscall.RawConn) error {
		var opErr error
		err := c.Control(func(fd uintptr) {
			if e := setSocketOptions(fd); e != nil {
			}
		})
		if err != nil {
			return err
		}
		return opErr
	})
}

func setSocketOptions(fd uintptr) error {
	if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return err
	}

	// Mirror upstream wireguard-go buffer sizes
	_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, socketBufferSize)
	_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, socketBufferSize)

	return nil
}
