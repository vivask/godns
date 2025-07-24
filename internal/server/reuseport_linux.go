//go:build linux
// +build linux

package server

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func setReusePort(c *net.UDPConn) error {
	f, err := c.File()
	if err != nil {
		return err
	}
	defer f.Close()
	fd := int(f.Fd())
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}
