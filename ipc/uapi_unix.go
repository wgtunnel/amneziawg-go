//go:build linux || darwin || freebsd || openbsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package ipc

import (
	"errors"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const (
	IpcErrorIO        = -int64(unix.EIO)
	IpcErrorProtocol  = -int64(unix.EPROTO)
	IpcErrorInvalid   = -int64(unix.EINVAL)
	IpcErrorPortInUse = -int64(unix.EADDRINUSE)
	IpcErrorUnknown   = -55 // ENOANO
)

func sockPath(socketDirectory, iface string) string {
	return filepath.Join(socketDirectory, iface+".sock") // Use filepath.Join for safe path construction
}

func UAPIOpen(rootdir string, name string) (*os.File, error) {
	socketDirectory := filepath.Join("/data/data", rootdir, "sockets") // Dynamically build using rootdir (package name)
	if err := os.MkdirAll(socketDirectory, 0o755); err != nil {
		return nil, err
	}

	socketPath := sockPath(socketDirectory, name)
	addr, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return nil, err
	}

	oldUmask := unix.Umask(0o077)
	defer unix.Umask(oldUmask)

	listener, err := net.ListenUnix("unix", addr)
	if err == nil {
		return listener.File()
	}

	// Test socket, if not in use cleanup and try again.
	if _, err := net.Dial("unix", socketPath); err == nil {
		return nil, errors.New("unix socket in use")
	}
	if err := os.Remove(socketPath); err != nil {
		return nil, err
	}
	listener, err = net.ListenUnix("unix", addr)
	if err != nil {
		return nil, err
	}
	return listener.File()
}
