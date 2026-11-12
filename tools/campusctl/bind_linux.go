//go:build linux

package main

import (
	"errors"
	"syscall"
)

func bindDevice(name string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		if name == "" {
			return errors.New("WAN interface unavailable")
		}
		var e error
		if err := c.Control(func(fd uintptr) {
			e = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, name)
		}); err != nil {
			return err
		}
		return e
	}
}
