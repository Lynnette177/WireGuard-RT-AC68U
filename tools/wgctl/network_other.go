//go:build !linux

package main

import "errors"

func networkUp(c *config, iface string) error {
	return errors.New("network configuration requires Linux on the router")
}
