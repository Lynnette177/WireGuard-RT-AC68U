// wgctl is a small, standard-library-only WireGuard userspace UAPI client.
// It intentionally supports IPv4 site access, not wg-quick shell directives.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const version = "rtac68u-wgctl-3"

type peer struct {
	public, preshared, endpoint string
	allowed                     []netip.Prefix
	keepalive                   uint64
}
type config struct {
	private   string
	addresses []netip.Prefix
	mtu, port uint64
	peers     []peer
}

func keyHex(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return "", errors.New("expected a base64-encoded 32-byte key (value hidden)")
	}
	if strings.Trim(hex.EncodeToString(b), "0") == "" {
		return "", errors.New("all-zero key is not allowed (value hidden)")
	}
	return hex.EncodeToString(b), nil
}

func prefixes(s string, mask bool) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(s, ",") {
		p, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err != nil || !p.Addr().Is4() {
			return nil, errors.New("expected IPv4 CIDR prefixes")
		}
		if mask {
			p = p.Masked()
		}
		out = append(out, p)
	}
	return out, nil
}

var hostname = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]*$`)
var interfaceName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,14}$`)

func parseConfig(r io.Reader) (*config, error) {
	c := &config{mtu: 1300}
	section, line := "", 0
	seenInterface := false
	seen := map[string]bool{}
	scanner := bufio.NewScanner(io.LimitReader(r, 1024*1024+1))
	for scanner.Scan() {
		line++
		s := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "\ufeff"))
		if i := strings.IndexByte(s, '#'); i >= 0 {
			s = strings.TrimSpace(s[:i])
		}
		if s == "" || strings.HasPrefix(s, ";") {
			continue
		}
		if strings.HasPrefix(s, "[") {
			switch s {
			case "[Interface]":
				if seenInterface || len(c.peers) > 0 {
					return nil, fmt.Errorf("line %d: Interface must occur once before peers", line)
				}
				seenInterface = true
			case "[Peer]":
				if !seenInterface {
					return nil, fmt.Errorf("line %d: missing Interface section", line)
				}
				c.peers = append(c.peers, peer{})
			default:
				return nil, fmt.Errorf("line %d: unsupported section", line)
			}
			section = s
			seen = map[string]bool{}
			continue
		}
		k, v, ok := strings.Cut(s, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || section == "" || v == "" {
			return nil, fmt.Errorf("line %d: invalid or empty setting (value hidden)", line)
		}
		if seen[k] {
			return nil, fmt.Errorf("line %d: duplicate setting %s", line, k)
		}
		seen[k] = true
		var err error
		if section == "[Interface]" {
			switch k {
			case "PrivateKey":
				c.private, err = keyHex(v)
			case "Address":
				c.addresses, err = prefixes(v, false)
			case "MTU":
				c.mtu, err = strconv.ParseUint(v, 10, 16)
				if err == nil && (c.mtu < 576 || c.mtu > 1500) {
					err = errors.New("MTU must be 576..1500")
				}
			case "ListenPort":
				c.port, err = strconv.ParseUint(v, 10, 16)
			case "DNS": // Deliberately ignored; this deployment preserves router DNS.
			default:
				err = errors.New("unsupported Interface setting; shell hooks and full-tunnel options are not accepted")
			}
		} else {
			p := &c.peers[len(c.peers)-1]
			switch k {
			case "PublicKey":
				p.public, err = keyHex(v)
			case "PresharedKey":
				p.preshared, err = keyHex(v)
			case "AllowedIPs":
				p.allowed, err = prefixes(v, true)
			case "PersistentKeepalive":
				p.keepalive, err = strconv.ParseUint(v, 10, 16)
			case "Endpoint":
				var host, port string
				host, port, err = net.SplitHostPort(v)
				if err == nil {
					var pn uint64
					pn, err = strconv.ParseUint(port, 10, 16)
					if err == nil && pn == 0 {
						err = errors.New("endpoint port must be nonzero")
					}
					if ip, e := netip.ParseAddr(host); e == nil {
						if !ip.Is4() {
							err = errors.New("only IPv4 endpoints are supported")
						}
					} else if !hostname.MatchString(host) {
						err = errors.New("invalid endpoint hostname")
					}
				}
				if err == nil {
					p.endpoint = v
				}
			default:
				err = errors.New("unsupported Peer setting")
			}
		}
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid %s (value hidden)", line, k)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("cannot read configuration")
	}
	if c.private == "" || len(c.addresses) == 0 || len(c.peers) == 0 {
		return nil, errors.New("PrivateKey, Address and at least one Peer are required")
	}
	seenKeys := map[string]bool{}
	for i, p := range c.peers {
		if p.public == "" || len(p.allowed) == 0 || p.endpoint == "" {
			return nil, fmt.Errorf("Peer %d requires PublicKey, AllowedIPs and Endpoint", i+1)
		}
		if seenKeys[p.public] {
			return nil, errors.New("duplicate peer public key")
		}
		seenKeys[p.public] = true
	}
	return c, nil
}

// Optional legacy restriction for explicit -subnet callers. Normal deployment
// uses all configured IPv4 AllowedIPs instead of silently filtering the file.
func restrict(c *config, subnet, management string) error {
	p, err := netip.ParsePrefix(subnet)
	if err != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() == 0 {
		return errors.New("subnet must be a canonical IPv4 CIDR, excluding a default route")
	}
	m, err := netip.ParseAddr(management)
	if err != nil || !m.Is4() {
		return errors.New("management IP must be IPv4")
	}
	if p.Contains(m) {
		return errors.New("VPN subnet includes router management IP; refusing to replace the management route")
	}
	for _, a := range c.addresses {
		if a.Masked().Contains(m) {
			return errors.New("Interface Address overlaps router management IP")
		}
	}
	var kept []peer
	for _, old := range c.peers {
		next := old
		next.allowed = nil
		for _, a := range old.allowed {
			if a.Contains(p.Addr()) && a.Bits() <= p.Bits() {
				next.allowed = []netip.Prefix{p}
				break
			}
		}
		if len(next.allowed) > 0 {
			kept = append(kept, next)
		}
	}
	if len(kept) != 1 {
		return errors.New("exactly one peer must cover the requested remote subnet in AllowedIPs")
	}
	c.peers = kept
	return nil
}

func plan(c *config) string {
	var addresses, routes []string
	for _, a := range c.addresses {
		addresses = append(addresses, netip.PrefixFrom(a.Addr(), 32).String())
	}
	for _, p := range c.peers {
		for _, a := range p.allowed {
			routes = append(routes, a.String())
		}
	}
	sort.Strings(routes)
	// Every value is generated from validated numeric types, never raw config.
	return fmt.Sprintf("WG_ADDRESSES='%s'\nWG_ROUTES='%s'\nWG_MTU='%d'\n", strings.Join(addresses, " "), strings.Join(routes, " "), c.mtu)
}

func configuredRoutes(c *config) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	var routes []netip.Prefix
	for _, p := range c.peers {
		for _, a := range p.allowed {
			if !seen[a] {
				seen[a] = true
				routes = append(routes, a)
			}
		}
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].String() < routes[j].String() })
	return routes
}

func validateConfiguredRoutes(c *config, management string) error {
	m, err := netip.ParseAddr(management)
	if err != nil || !m.Is4() {
		return errors.New("management IP must be IPv4")
	}
	for _, a := range c.addresses {
		if a.Addr() == m {
			return errors.New("Interface Address equals router management IP")
		}
	}
	owners := map[netip.Prefix]int{}
	for i := range c.peers {
		var unique []netip.Prefix
		for _, a := range c.peers[i].allowed {
			if !a.Addr().Is4() || a.Bits() == 0 || a != a.Masked() {
				return errors.New("AllowedIPs must contain canonical IPv4 prefixes without a default route")
			}
			if a.Contains(m) {
				return errors.New("AllowedIPs includes router management IP; refusing to route the local LAN into WireGuard")
			}
			if owner, ok := owners[a]; ok {
				if owner != i {
					return errors.New("duplicate AllowedIPs prefix belongs to multiple peers")
				}
				continue
			}
			owners[a] = i
			unique = append(unique, a)
		}
		c.peers[i].allowed = unique
	}
	return nil
}

func request(c *config, resolve func(string) (string, error)) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "set=1\nprivate_key=%s\nlisten_port=%d\nreplace_peers=true\n", c.private, c.port)
	for _, p := range c.peers {
		ep, err := resolve(p.endpoint)
		if err != nil {
			return "", errors.New("cannot resolve peer endpoint using current router DNS")
		}
		endpointAddress, err := netip.ParseAddrPort(ep)
		if err != nil || !endpointAddress.Addr().Is4() {
			return "", errors.New("resolved endpoint is not IPv4")
		}
		for _, a := range configuredRoutes(c) {
			if a.Contains(endpointAddress.Addr()) {
				return "", errors.New("endpoint is inside the VPN destination subnet; this would create a routing loop")
			}
		}
		fmt.Fprintf(&b, "public_key=%s\n", p.public)
		if p.preshared != "" {
			fmt.Fprintf(&b, "preshared_key=%s\n", p.preshared)
		}
		fmt.Fprintf(&b, "endpoint=%s\npersistent_keepalive_interval=%d\nreplace_allowed_ips=true\n", ep, p.keepalive)
		for _, a := range p.allowed {
			fmt.Fprintf(&b, "allowed_ip=%s\n", a.String())
		}
	}
	b.WriteByte('\n')
	return b.String(), nil
}

func resolveEndpoint(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(ip.String(), port), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return "", errors.New("DNS lookup failed")
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}

func exchange(conn net.Conn, req string) ([]string, error) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, errors.New("cannot write UAPI request")
	}
	s := bufio.NewScanner(io.LimitReader(conn, 1024*1024))
	var lines []string
	gotErrno, done := false, false
	for s.Scan() {
		line := s.Text()
		if line == "" {
			done = true
			break
		}
		if strings.HasPrefix(line, "errno=") {
			gotErrno = true
			if line != "errno=0" {
				return nil, errors.New("WireGuard rejected the UAPI operation: " + line)
			}
		}
		lines = append(lines, line)
	}
	if s.Err() != nil || !gotErrno || !done {
		return nil, errors.New("incomplete UAPI response")
	}
	return lines, nil
}

func status(lines []string) string {
	var out strings.Builder
	i := 0
	for _, s := range lines {
		k, v, _ := strings.Cut(s, "=")
		switch k {
		case "listen_port":
			fmt.Fprintf(&out, "listen_port: %s\n", v)
		case "public_key":
			i++
			fmt.Fprintf(&out, "peer %d:\n", i)
		case "endpoint", "allowed_ip", "rx_bytes", "tx_bytes", "last_handshake_time_sec":
			fmt.Fprintf(&out, "  %s: %s\n", k, v)
		}
	}
	return out.String()
}

func verifyPackage(directory string) error {
	b, err := os.ReadFile(filepath.Join(directory, "SHA256SUMS"))
	if err != nil {
		return errors.New("cannot read package checksums")
	}
	count := 0
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 64 {
			return errors.New("invalid checksum manifest")
		}
		name := fields[1]
		if filepath.Base(name) != name || strings.ContainsAny(name, `/\`) || seen[name] {
			return errors.New("unsafe or duplicate manifest filename")
		}
		switch name {
		case "wireguard-go", "wgctl", "wg0.conf", "service.sh", "install.sh", "uninstall.sh":
		default:
			return errors.New("unexpected manifest filename")
		}
		seen[name] = true
		f, err := os.Open(filepath.Join(directory, name))
		if err != nil {
			return errors.New("missing package file")
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil || hex.EncodeToString(h.Sum(nil)) != fields[0] {
			return errors.New("package checksum mismatch: " + name)
		}
		count++
	}
	if count != 6 {
		return errors.New("incomplete package manifest")
	}
	return nil
}

func checkLAN(address, mask, subnet string) error {
	ip, err := netip.ParseAddr(address)
	nm := net.ParseIP(mask).To4()
	if err != nil || !ip.Is4() || nm == nil {
		return errors.New("invalid router LAN address or netmask")
	}
	bits, total := net.IPMask(nm).Size()
	if total != 32 {
		return errors.New("invalid router LAN netmask")
	}
	lan := netip.PrefixFrom(ip, bits).Masked()
	remote, err := netip.ParsePrefix(subnet)
	if err != nil || !remote.Addr().Is4() {
		return errors.New("invalid remote subnet")
	}
	if lan.Overlaps(remote) {
		return errors.New("remote subnet overlaps the local LAN; refusing to replace local connectivity")
	}
	return nil
}

func run(args []string, out io.Writer) error {
	if len(args) == 1 && args[0] == "--version" {
		fmt.Fprintln(out, version)
		return nil
	}
	if len(args) == 0 {
		return errors.New("usage: wgctl validate|plan|apply|show [options]")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	directory := f.String("directory", ".", "package directory")
	lanAddress := f.String("address", "", "LAN IPv4")
	lanMask := f.String("netmask", "", "LAN netmask")
	file := f.String("config", "/jffs/wireguard/wg0.conf", "config path")
	iface := f.String("interface", "wg0", "interface name")
	subnet := f.String("subnet", "", "optional restriction to one configured subnet")
	mgmt := f.String("management", "192.168.1.1", "router management IPv4")
	if err := f.Parse(args[1:]); err != nil || f.NArg() != 0 {
		return errors.New("invalid command options")
	}
	if !interfaceName.MatchString(*iface) {
		return errors.New("invalid interface name")
	}
	if args[0] == "verify" {
		return verifyPackage(*directory)
	}
	if args[0] == "link-exists" {
		_, err := net.InterfaceByName(*iface)
		return err
	}
	if args[0] == "network-status" {
		return networkStatus(*iface, out)
	}
	if args[0] == "show" {
		conn, err := net.DialTimeout("unix", "/var/run/wireguard/"+*iface+".sock", 5*time.Second)
		if err != nil {
			return errors.New("cannot connect to WireGuard UAPI socket")
		}
		lines, err := exchange(conn, "get=1\n\n")
		if err != nil {
			return err
		}
		fmt.Fprint(out, status(lines))
		return nil
	}
	if args[0] != "validate" && args[0] != "plan" && args[0] != "apply" && args[0] != "network-up" && args[0] != "check-lan" && args[0] != "route-check" {
		return errors.New("unsupported command")
	}
	r, err := os.Open(*file)
	if err != nil {
		return errors.New("cannot open configuration file")
	}
	defer r.Close()
	info, err := r.Stat()
	if err != nil || info.Size() > 1024*1024 {
		return errors.New("configuration exceeds 1 MiB")
	}
	c, err := parseConfig(r)
	if err != nil {
		return err
	}
	if *subnet != "" {
		if err := restrict(c, *subnet, *mgmt); err != nil {
			return err
		}
	}
	if err := validateConfiguredRoutes(c, *mgmt); err != nil {
		return err
	}
	switch args[0] {
	case "check-lan":
		for _, prefix := range configuredRoutes(c) {
			if err := checkLAN(*lanAddress, *lanMask, prefix.String()); err != nil {
				return err
			}
		}
	case "route-check":
		for _, prefix := range configuredRoutes(c) {
			if err := checkRoute(prefix.String()); err != nil {
				return err
			}
		}
	case "network-up":
		if err := networkUp(c, *iface); err != nil {
			return err
		}
		fmt.Fprintln(out, "Interface, MTU and remote LAN route configured without iproute2.")
	case "validate":
		fmt.Fprintln(out, "Configuration valid. DNS ignored; IPv4 AllowedIPs are used for peer configuration, routes and firewall rules.")
		for _, prefix := range configuredRoutes(c) {
			fmt.Fprintln(out, "Allowed subnet:", prefix)
		}
	case "plan":
		fmt.Fprint(out, plan(c))
	case "apply":
		req, err := request(c, resolveEndpoint)
		if err != nil {
			return err
		}
		conn, err := net.DialTimeout("unix", "/var/run/wireguard/"+*iface+".sock", 5*time.Second)
		if err != nil {
			return errors.New("cannot connect to WireGuard UAPI socket")
		}
		if _, err := exchange(conn, req); err != nil {
			return err
		}
		fmt.Fprintln(out, "Peer configuration applied; DNS unchanged.")
	}
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "wgctl:", err)
		os.Exit(1)
	}
}
