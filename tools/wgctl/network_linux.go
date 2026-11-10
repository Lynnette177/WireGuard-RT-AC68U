//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

func sendNetworkRequest(req networkRequest) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, sa); err != nil {
		return err
	}
	tv := syscall.NsecToTimeval((5 * time.Second).Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	msg := make([]byte, 16+len(req.data))
	binary.LittleEndian.PutUint32(msg, uint32(len(msg)))
	binary.LittleEndian.PutUint16(msg[4:], req.kind)
	binary.LittleEndian.PutUint16(msg[6:], req.flags)
	binary.LittleEndian.PutUint32(msg[8:], 1)
	copy(msg[16:], req.data)
	if err := syscall.Sendto(fd, msg, 0, sa); err != nil {
		return err
	}
	buf := make([]byte, 65536)
	for {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		peer, ok := from.(*syscall.SockaddrNetlink)
		if !ok || peer.Pid != 0 {
			return errors.New("unexpected netlink sender")
		}
		messages, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range messages {
			if m.Header.Seq != 1 {
				continue
			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				if len(m.Data) < 4 {
					return errors.New("short netlink acknowledgement")
				}
				errno := int32(binary.LittleEndian.Uint32(m.Data))
				if errno == 0 {
					return nil
				}
				if errno > 0 {
					return errors.New("invalid netlink error")
				}
				return syscall.Errno(-errno)
			}
		}
	}
}
func networkUp(c *config, iface string) error {
	ni, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("find TUN interface: %w", err)
	}
	requests, err := networkRequests(c, ni.Index)
	if err != nil {
		return err
	}
	for _, p := range c.peers {
		for _, prefix := range p.allowed {
			if err := checkRoute(prefix.String()); err != nil {
				return err
			}
		}
	}
	for _, req := range requests {
		if err := sendNetworkRequest(req); err != nil {
			return fmt.Errorf("%s: %w", req.operation, err)
		}
	}
	return nil
}
