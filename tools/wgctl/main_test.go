package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackageIntegrity(t *testing.T) {
	d := t.TempDir()
	var manifest strings.Builder
	for _, name := range []string{"wireguard-go", "wgctl", "wg0.conf", "service.sh", "install.sh", "uninstall.sh"} {
		data := []byte("test:" + name)
		if err := os.WriteFile(filepath.Join(d, name), data, 0600); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&manifest, "%x  %s\n", sha256.Sum256(data), name)
	}
	if err := os.WriteFile(filepath.Join(d, "SHA256SUMS"), []byte(manifest.String()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyPackage(d); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "wg0.conf"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyPackage(d); err == nil {
		t.Fatal("accepted a modified config")
	}
}

func TestLANOverlap(t *testing.T) {
	if err := checkLAN("192.168.1.1", "255.255.255.0", "192.168.20.0/24"); err != nil {
		t.Fatal(err)
	}
	for _, mask := range []string{"255.255.0.0", "255.0.255.0", "invalid"} {
		if err := checkLAN("192.168.1.1", mask, "192.168.20.0/24"); err == nil {
			t.Fatalf("accepted overlapping or malformed LAN mask %s", mask)
		}
	}
}

func sample() string {
	key := func(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
	return fmt.Sprintf("[Interface]\r\nPrivateKey = %s\r\nAddress = 10.20.0.3/24\r\nDNS = 192.168.20.1\r\nMTU = 1300\r\n[Peer]\r\nPublicKey = %s\r\nPresharedKey = %s\r\nAllowedIPs = 192.168.20.0/24, 10.30.0.1/32\r\nEndpoint = vpn.example.test:51820\r\nPersistentKeepalive = 25\r\n", key(1), key(2), key(3))
}

func TestConfiguredVPNClientNetworksAreNotFiltered(t *testing.T) {
	text := strings.Replace(sample(), "192.168.20.0/24, 10.30.0.1/32", "192.168.20.0/24, 10.30.0.1/32, 10.20.0.0/24", 1)
	c, err := parseConfig(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateConfiguredRoutes(c, "192.168.1.1"); err != nil {
		t.Fatal(err)
	}
	req, err := request(c, func(string) (string, error) { return "203.0.113.5:51820", nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"192.168.20.0/24", "10.30.0.1/32", "10.20.0.0/24"} {
		if !strings.Contains(req, "allowed_ip="+prefix+"\n") || !strings.Contains(plan(c), prefix) {
			t.Fatalf("configured prefix %s was discarded", prefix)
		}
	}
	if strings.Count(req, "allowed_ip=") != 3 {
		t.Fatal("unexpected allowed IP count")
	}
	d := t.TempDir()
	path := filepath.Join(d, "wg.conf")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"plan", "-config", path}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "10.20.0.0/24") || strings.Contains(out.String(), "DNS") || strings.Contains(out.String(), c.private) {
		t.Fatal("default CLI plan lost VPN-client route, modified DNS, or exposed a key")
	}
	for _, bad := range []string{"0.0.0.0/0", "192.168.1.0/24", "192.168.0.0/16"} {
		other, err := parseConfig(strings.NewReader(strings.Replace(text, "10.20.0.0/24", bad, 1)))
		if err != nil {
			t.Fatal(err)
		}
		if err := validateConfiguredRoutes(other, "192.168.1.1"); err == nil {
			t.Fatalf("accepted unsafe route %s", bad)
		}
	}
}
func TestDeploymentRestriction(t *testing.T) {
	c, err := parseConfig(strings.NewReader("\ufeff" + sample()))
	if err != nil {
		t.Fatal(err)
	}
	if err := restrict(c, "192.168.20.0/24", "192.168.1.1"); err != nil {
		t.Fatal(err)
	}
	plan := plan(c)
	if strings.Contains(plan, "10.30.0.1") || strings.Contains(plan, "DNS") || strings.Contains(plan, "10.20.0.3/24") || strings.Contains(plan, c.private) {
		t.Fatal("plan leaked excluded route, DNS, connected network, or key")
	}
	if !strings.Contains(plan, "WG_ROUTES='192.168.20.0/24'") || !strings.Contains(plan, "10.20.0.3/32") {
		t.Fatal(plan)
	}
	req, err := request(c, func(s string) (string, error) { return "203.0.113.5:51820", nil })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(req, "10.30.0.1") || strings.Contains(req, "DNS") || strings.Count(req, "allowed_ip=") != 1 {
		t.Fatal("request contains excluded routes/DNS")
	}
	if !strings.HasSuffix(req, "\n\n") || !strings.HasPrefix(req, "set=1\n") || !strings.Contains(req, "persistent_keepalive_interval=25") {
		t.Fatal("invalid UAPI framing")
	}
	if _, err := request(c, func(string) (string, error) { return "192.168.20.1:51820", nil }); err == nil {
		t.Fatal("accepted an endpoint inside the VPN destination subnet")
	}
}
func TestValidationRejections(t *testing.T) {
	for name, mutate := range map[string]func(string) string{
		"bad private": func(s string) string {
			return strings.Replace(s, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "SECRET-INVALID-PRIVATE", 1)
		},
		"shell directive": func(s string) string { return strings.Replace(s, "MTU = 1300", "PostUp = echo secret", 1) },
		"injection": func(s string) string {
			return strings.Replace(s, "10.20.0.3/24", "10.20.0.3/32'; touch /tmp/injected; #", 1)
		},
		"bad endpoint": func(s string) string {
			return strings.Replace(s, "vpn.example.test:51820", "vpn.example.test;reboot:51820", 1)
		},
		"ipv6":      func(s string) string { return strings.Replace(s, "10.20.0.3/24", "fd00::3/128", 1) },
		"duplicate": func(s string) string { return strings.Replace(s, "MTU = 1300", "MTU = 1300\nMTU = 1400", 1) },
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseConfig(strings.NewReader(mutate(sample())))
			if err == nil {
				t.Fatal("expected rejection")
			}
			if strings.Contains(err.Error(), "SECRET-INVALID-PRIVATE") || strings.Contains(err.Error(), "echo secret") {
				t.Fatal("error exposed config value")
			}
		})
	}
}
func TestManagementRouteProtection(t *testing.T) {
	for _, subnet := range []string{"0.0.0.0/0", "192.168.1.0/24", "192.168.20.1/24", "10.99.0.0/24"} {
		c, err := parseConfig(strings.NewReader(sample()))
		if err != nil {
			t.Fatal(err)
		}
		if err := restrict(c, subnet, "192.168.1.1"); err == nil {
			t.Fatalf("accepted unsafe or uncovered subnet %s", subnet)
		}
	}
	c, err := parseConfig(strings.NewReader(strings.Replace(sample(), "192.168.20.0/24, 10.30.0.1/32", "0.0.0.0/0", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := restrict(c, "192.168.20.0/24", "192.168.1.1"); err != nil {
		t.Fatal(err)
	}
	if got := plan(c); !strings.Contains(got, "WG_ROUTES='192.168.20.0/24'") {
		t.Fatal(got)
	}
}
func TestUAPIExchangeAndRedactedStatus(t *testing.T) {
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		r := bufio.NewReader(server)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			if line == "\n" {
				break
			}
		}
		_, err := fmt.Fprint(server, "private_key=DO-NOT-PRINT\npublic_key=PEER-KEY\npreshared_key=DO-NOT-PRINT\nendpoint=203.0.113.5:51820\nlast_handshake_time_sec=12\nrx_bytes=15\ntx_bytes=30\nerrno=0\n\n")
		done <- err
	}()
	lines, err := exchange(client, "get=1\n\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	got := status(lines)
	if strings.Contains(got, "DO-NOT-PRINT") || strings.Contains(got, "PEER-KEY") || !strings.Contains(got, "rx_bytes: 15") {
		t.Fatal("status filtering failed")
	}
}
func TestUAPIErrors(t *testing.T) {
	for _, response := range []string{"errno=22\n\n", "rx_bytes=1\n\n", "errno=0\n"} {
		c, s := net.Pipe()
		go func() {
			defer s.Close()
			r := bufio.NewReader(s)
			for {
				line, err := r.ReadString('\n')
				if err != nil || line == "\n" {
					break
				}
			}
			fmt.Fprint(s, response)
		}()
		if _, err := exchange(c, "get=1\n\n"); err == nil {
			t.Fatal("accepted incomplete/error UAPI response")
		}
	}
}
