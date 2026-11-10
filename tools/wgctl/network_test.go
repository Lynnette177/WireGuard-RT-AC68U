package main

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
)

func decodeAttributes(t *testing.T, b []byte) map[uint16][]byte {
	t.Helper()
	out := map[uint16][]byte{}
	for len(b) > 0 {
		if len(b) < 4 {
			t.Fatal("truncated attribute")
		}
		n := int(binary.LittleEndian.Uint16(b))
		if n < 4 || n > len(b) {
			t.Fatal("bad attribute length")
		}
		out[binary.LittleEndian.Uint16(b[2:])] = b[4:n]
		b = b[(n+3)&^3:]
	}
	return out
}

func TestNetworkConfigurationIsRestricted(t *testing.T) {
	c, err := parseConfig(strings.NewReader(sample()))
	if err != nil {
		t.Fatal(err)
	}
	if err := restrict(c, "192.168.20.0/24", "192.168.1.1"); err != nil {
		t.Fatal(err)
	}
	reqs, err := networkRequests(c, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 3 {
		t.Fatalf("expected address, link, route; got %d requests", len(reqs))
	}
	a, link, route := reqs[0], reqs[1], reqs[2]
	if a.kind != 20 || a.data[1] != 32 || binary.LittleEndian.Uint32(a.data[4:]) != 7 {
		t.Fatal("address must be /32 on target TUN")
	}
	attrs := decodeAttributes(t, a.data[8:])
	if !bytes.Equal(attrs[1], []byte{10, 20, 0, 3}) || !bytes.Equal(attrs[2], attrs[1]) {
		t.Fatal("wrong local/point-to-point address")
	}
	attrs = decodeAttributes(t, link.data[16:])
	if link.kind != 16 || binary.LittleEndian.Uint32(attrs[4]) != 1300 || binary.LittleEndian.Uint32(link.data[8:]) != 1 || binary.LittleEndian.Uint32(link.data[12:]) != 1 {
		t.Fatal("MTU/up flag mismatch")
	}
	if route.kind != 24 || route.data[1] != 24 || route.data[4] != 254 || route.flags&0x100 != 0 {
		t.Fatal("route must target main table, /24, without replacement")
	}
	attrs = decodeAttributes(t, route.data[12:])
	if !bytes.Equal(attrs[1], []byte{192, 168, 20, 0}) || binary.LittleEndian.Uint32(attrs[4]) != 7 || binary.LittleEndian.Uint32(attrs[6]) != 42760 {
		t.Fatal("route contains incorrect destination/interface/metric")
	}
	if _, ok := attrs[5]; ok {
		t.Fatal("route must not replace the default gateway")
	}
	c.peers[0].allowed = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	if _, err := networkRequests(c, 7); err == nil {
		t.Fatal("accepted default route")
	}
}

func TestKernelRouteReaderAndConflict(t *testing.T) {
	text := "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" +
		"eth0 00000000 0101A8C0 0003 0 0 0 00000000 0 0 0\n" +
		"br0 0001A8C0 00000000 0001 0 0 0 00FFFFFF 0 0 0\n" +
		"wg0 0014A8C0 00000000 0001 0 0 42760 00FFFFFF 0 0 0\n"
	routes, err := readRoutes(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 3 || routes[1].prefix.String() != "192.168.1.0/24" || routes[2].prefix.String() != "192.168.20.0/24" || routes[2].metric != 42760 {
		t.Fatal("kernel route byte order/parse mismatch")
	}
	if err := checkRouteEntries(routes[:2], "192.168.20.0/24"); err != nil {
		t.Fatal("default/LAN routes must be preserved without blocking deployment:", err)
	}
	if err := checkRouteEntries(routes, "192.168.20.0/24"); err == nil {
		t.Fatal("existing remote route must not be replaced")
	}
	if _, err := readRoutes(strings.NewReader("bad route")); err == nil {
		t.Fatal("accepted malformed kernel route")
	}
}

func TestNetworkRequestsIncludeVPNClientSubnet(t *testing.T) {
	c, err := parseConfig(strings.NewReader(strings.Replace(sample(), "192.168.20.0/24, 10.30.0.1/32", "192.168.20.0/24, 10.30.0.1/32, 10.20.0.0/24", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateConfiguredRoutes(c, "192.168.1.1"); err != nil {
		t.Fatal(err)
	}
	reqs, err := networkRequests(c, 7)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, req := range reqs {
		if req.kind == 24 {
			attrs := decodeAttributes(t, req.data[12:])
			var a [4]byte
			copy(a[:], attrs[1])
			got[netip.PrefixFrom(netip.AddrFrom4(a), int(req.data[1])).String()] = true
			if req.flags&0x100 != 0 || req.data[1] == 0 {
				t.Fatal("route replacement/default route is forbidden")
			}
		}
	}
	if len(got) != 3 || !got["192.168.20.0/24"] || !got["10.30.0.1/32"] || !got["10.20.0.0/24"] {
		t.Fatal("missing configured kernel route", got)
	}
}
