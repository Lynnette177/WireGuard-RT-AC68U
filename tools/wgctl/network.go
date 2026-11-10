package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Linux 2.6.36 rtnetlink ABI: include/linux/{rtnetlink,if_addr,if_link}.h.
// These wire layouts are shared with host tests; the target is little endian.
type networkRequest struct {
	kind, flags uint16
	data        []byte
	operation   string
}

func u32(n uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, n); return b }
func attribute(kind uint16, value []byte) []byte {
	n := 4 + len(value)
	b := make([]byte, (n+3)&^3)
	binary.LittleEndian.PutUint16(b, uint16(n))
	binary.LittleEndian.PutUint16(b[2:], kind)
	copy(b[4:], value)
	return b
}
func networkRequests(c *config, index int) ([]networkRequest, error) {
	if index <= 0 || c.mtu < 576 || c.mtu > 1500 {
		return nil, errors.New("invalid interface index or MTU")
	}
	var out []networkRequest
	for _, a := range c.addresses {
		if !a.Addr().Is4() {
			return nil, errors.New("only IPv4 interface addresses are supported")
		}
		addr := a.Addr().As4()
		body := []byte{2, 32, 0, 0} // AF_INET, /32, flags, RT_SCOPE_UNIVERSE
		body = append(body, u32(uint32(index))...)
		body = append(body, attribute(1, addr[:])...)                          // IFA_ADDRESS
		body = append(body, attribute(2, addr[:])...)                          // IFA_LOCAL (point-to-point TUN)
		out = append(out, networkRequest{20, 0x605, body, "set IPv4 address"}) // NEWADDR, REQUEST|ACK|CREATE|EXCL
	}
	body := make([]byte, 16) // ifinfomsg
	copy(body[4:], u32(uint32(index)))
	copy(body[8:], u32(1))                                   // IFF_UP
	copy(body[12:], u32(1))                                  // change IFF_UP only
	body = append(body, attribute(4, u32(uint32(c.mtu)))...) // IFLA_MTU
	out = append(out, networkRequest{16, 5, body, "set interface MTU/up"})
	for _, p := range c.peers {
		for _, prefix := range p.allowed {
			if !prefix.Addr().Is4() || prefix.Bits() == 0 || prefix != prefix.Masked() {
				return nil, errors.New("refusing noncanonical or default route")
			}
			addr := prefix.Addr().As4()
			// rtmsg: IPv4, dst length, src length, TOS, main table, static,
			// link scope, unicast. No gateway and no route-replacement flag.
			body := []byte{2, byte(prefix.Bits()), 0, 0, 254, 4, 253, 1, 0, 0, 0, 0}
			body = append(body, attribute(1, addr[:])...)            // RTA_DST
			body = append(body, attribute(4, u32(uint32(index)))...) // RTA_OIF
			body = append(body, attribute(6, u32(42760))...)         // RTA_PRIORITY
			out = append(out, networkRequest{24, 0x605, body, "add remote LAN route"})
		}
	}
	return out, nil
}

type routeEntry struct {
	iface  string
	prefix netip.Prefix
	metric uint64
}

func readRoutes(r io.Reader) ([]routeEntry, error) {
	s := bufio.NewScanner(r)
	var out []routeEntry
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) == 0 || f[0] == "Iface" {
			continue
		}
		if len(f) < 8 {
			return nil, errors.New("invalid /proc/net/route entry")
		}
		dst, e1 := strconv.ParseUint(f[1], 16, 32)
		mask, e2 := strconv.ParseUint(f[7], 16, 32)
		metric, e3 := strconv.ParseUint(f[6], 10, 32)
		if e1 != nil || e2 != nil || e3 != nil {
			return nil, errors.New("invalid kernel route fields")
		}
		bits, total := net.IPMask(u32(uint32(mask))).Size()
		if total != 32 {
			return nil, errors.New("invalid kernel route mask")
		}
		var a [4]byte
		copy(a[:], u32(uint32(dst)))
		out = append(out, routeEntry{f[0], netip.PrefixFrom(netip.AddrFrom4(a), bits).Masked(), metric})
	}
	return out, s.Err()
}
func kernelRoutes() ([]routeEntry, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readRoutes(f)
}
func checkRouteEntries(routes []routeEntry, subnet string) error {
	p, err := netip.ParsePrefix(subnet)
	if err != nil || !p.Addr().Is4() || p.Bits() == 0 || p != p.Masked() {
		return errors.New("refusing invalid or default VPN route")
	}
	for _, r := range routes {
		if r.prefix == p {
			return fmt.Errorf("existing route for %s on %s; refusing to replace it", subnet, r.iface)
		}
	}
	return nil
}
func checkRoute(subnet string) error {
	routes, err := kernelRoutes()
	if err != nil {
		return fmt.Errorf("cannot read kernel routing table: %w", err)
	}
	return checkRouteEntries(routes, subnet)
}
func networkStatus(iface string, out io.Writer) error {
	ni, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "interface: %s mtu: %d flags: %s\n", ni.Name, ni.MTU, ni.Flags)
	addresses, err := ni.Addrs()
	if err != nil {
		return err
	}
	for _, a := range addresses {
		fmt.Fprintln(out, "address:", a.String())
	}
	routes, err := kernelRoutes()
	if err != nil {
		return err
	}
	for _, r := range routes {
		if r.iface == iface {
			fmt.Fprintf(out, "route: %s dev %s metric %d\n", r.prefix, iface, r.metric)
		}
	}
	return nil
}
