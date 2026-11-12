//go:build !linux

package main

import "syscall"

func bindDevice(string) func(string, string, syscall.RawConn) error { return nil }
