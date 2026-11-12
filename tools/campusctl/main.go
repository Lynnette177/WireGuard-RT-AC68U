package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const defaultDir = "/jffs/addons/campus-login"

type settings struct {
	Enabled    bool   `json:"enabled"`
	Interval   int    `json:"interval_minutes"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	CipherHash string `json:"cipher_hash"`
}
type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type publicStatus struct {
	Enabled          bool   `json:"enabled"`
	Interval         int    `json:"interval_minutes"`
	CredentialsSaved bool   `json:"credentials_saved"`
	State            string `json:"state"`
	CheckedAt        string `json:"checked_at,omitempty"`
	Message          string `json:"message,omitempty"`
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".campus-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(mode); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	if e := file.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}
func privateKey(dir string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(filepath.Join(dir, "web-private.pem"))
	if err != nil {
		return nil, errors.New("web encryption key unavailable")
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("invalid web encryption key")
	}
	k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid web encryption key")
	}
	return k, nil
}
func initialize(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, "web-private.pem")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
		if err := atomicWrite(path, b, 0600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	k, err := privateKey(dir)
	if err != nil {
		return err
	}
	pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, "web-public.b64"), []byte(base64.StdEncoding.EncodeToString(pub)), 0644)
}

func checkSite(dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, "site.json"))
	if err != nil {
		return errors.New("portal site configuration missing")
	}
	var site portalSite
	if json.Unmarshal(b, &site) != nil || net.ParseIP(site.IP) == nil || net.ParseIP(site.IP).To4() == nil || !validHost.MatchString(site.ServerName) {
		return errors.New("invalid portal site configuration")
	}
	ca, err := os.ReadFile(filepath.Join(dir, "campus_root_ca.pem"))
	if err != nil {
		return errors.New("portal CA certificate missing")
	}
	block, _ := pem.Decode(ca)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("invalid portal CA certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA {
		return errors.New("portal certificate is not a CA")
	}
	return nil
}

func verifyPackage(dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return errors.New("package checksums unavailable")
	}
	want := map[string]bool{"campusctl": true, "page.asp": true, "manager.sh": true, "install.sh": true, "site.json": true, "campus_root_ca.pem": true}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || !want[fields[1]] || seen[fields[1]] {
			return errors.New("invalid package manifest")
		}
		data, err := os.ReadFile(filepath.Join(dir, fields[1]))
		if err != nil {
			return errors.New("package file unavailable")
		}
		h := sha256.Sum256(data)
		if hex.EncodeToString(h[:]) != fields[0] {
			return errors.New("package checksum mismatch")
		}
		seen[fields[1]] = true
	}
	if len(seen) != len(want) {
		return errors.New("incomplete package manifest")
	}
	return nil
}
func loadSettings(dir string) (settings, error) {
	s := settings{Interval: 15}
	b, err := os.ReadFile(filepath.Join(dir, "settings.json"))
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if json.Unmarshal(b, &s) != nil || s.Interval < 1 || s.Interval > 1440 {
		return settings{}, errors.New("invalid saved settings")
	}
	return s, nil
}
func saveSettings(dir string, s settings) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, "settings.json"), b, 0600)
}
func readCustom(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read router addon settings")
	}
	if len(b) > 65536 {
		return nil, errors.New("router addon settings are too large")
	}
	m := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ok && strings.HasPrefix(key, "campuslogin_") {
			m[key] = strings.TrimSpace(value)
		}
	}
	return m, nil
}
func applySettings(dir, path string) (settings, error) {
	s, err := loadSettings(dir)
	if err != nil {
		return s, err
	}
	m, err := readCustom(path)
	if err != nil {
		return s, err
	}
	enabled := m["campuslogin_enabled"]
	if enabled != "0" && enabled != "1" {
		return s, errors.New("invalid enable setting")
	}
	interval, err := strconv.Atoi(m["campuslogin_interval"])
	if err != nil || interval < 1 || interval > 1440 {
		return s, errors.New("interval must be 1 to 1440 minutes")
	}
	if ciphertext := m["campuslogin_secret"]; ciphertext != "" {
		h := sha256.Sum256([]byte(ciphertext))
		digest := hex.EncodeToString(h[:])
		if digest != s.CipherHash {
			b, err := base64.StdEncoding.DecodeString(ciphertext)
			if err != nil {
				return s, errors.New("invalid encrypted credentials")
			}
			key, err := privateKey(dir)
			if err != nil {
				return s, err
			}
			plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, b, nil)
			if err != nil {
				return s, errors.New("cannot decrypt credentials; refresh the page and retry")
			}
			var c credentials
			if json.Unmarshal(plain, &c) != nil || c.Username == "" || c.Password == "" || len(c.Username) > 128 || len(c.Password) > 128 || strings.ContainsAny(c.Username+c.Password, "\x00\r\n") {
				return s, errors.New("invalid username or password")
			}
			s.Username, s.Password, s.CipherHash = c.Username, c.Password, digest
		}
	}
	s.Enabled = enabled == "1"
	s.Interval = interval
	if s.Enabled && (s.Username == "" || s.Password == "") {
		return s, errors.New("enter a username and password before enabling")
	}
	if err := saveSettings(dir, s); err != nil {
		return s, errors.New("cannot save settings")
	}
	return s, nil
}
func publishStatus(path string, s settings, state, message string) {
	if path == "" {
		return
	}
	value := publicStatus{Enabled: s.Enabled, Interval: s.Interval, CredentialsSaved: s.Username != "" && s.Password != "", State: state, Message: message}
	if state != "disabled" && state != "waiting" {
		value.CheckedAt = time.Now().Format(time.RFC3339)
	}
	b, err := json.Marshal(value)
	if err == nil {
		_ = atomicWrite(path, b, 0644)
	}
}
func nvram(key string) string {
	out, err := exec.Command("nvram", "get", key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
func cycle(dir, statusPath string) {
	s, err := loadSettings(dir)
	if err != nil {
		publishStatus(statusPath, s, "error", "无法读取设置")
		return
	}
	if !s.Enabled {
		publishStatus(statusPath, s, "disabled", "")
		return
	}
	publishStatus(statusPath, s, "checking", "")
	siteData, err := os.ReadFile(filepath.Join(dir, "site.json"))
	var site portalSite
	if err != nil || json.Unmarshal(siteData, &site) != nil {
		publishStatus(statusPath, s, "error", "认证服务器配置无效")
		return
	}
	p, err := newPortal(site, filepath.Join(dir, "campus_root_ca.pem"), nvram("wan0_ipaddr"), nvram("wan0_ifname"))
	if err != nil {
		publishStatus(statusPath, s, "error", "WAN 地址或证书不可用")
		return
	}
	state, err := p.check(s.Username, s.Password, func() bool {
		current, e := loadSettings(dir)
		return e == nil && current.Enabled && current.Username == s.Username && current.Password == s.Password
	})
	if state == "cancelled" {
		current, e := loadSettings(dir)
		if e == nil {
			if !current.Enabled {
				publishStatus(statusPath, current, "disabled", "")
			} else {
				publishStatus(statusPath, current, "waiting", "")
			}
		}
		return
	}
	if err != nil {
		publishStatus(statusPath, s, state, "认证未完成，请检查 WAN、证书或账号")
		return
	}
	publishStatus(statusPath, s, "online", "")
}
func daemon(dir, statusPath string) {
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(signals)
	for {
		cycle(dir, statusPath)
		s, err := loadSettings(dir)
		minutes := 15
		if err == nil {
			minutes = s.Interval
		}
		timer := time.NewTimer(time.Duration(minutes) * time.Minute)
		select {
		case sig := <-signals:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			if sig != syscall.SIGHUP {
				return
			}
		case <-timer.C:
		}
	}
}
func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: campusctl init|public-key|apply|daemon")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	dir := f.String("dir", defaultDir, "private addon directory")
	custom := f.String("custom", "/jffs/addons/custom_settings.txt", "router addon settings")
	statusPath := f.String("status", "/www/user/campus-login-status.json", "public status file")
	if err := f.Parse(args[1:]); err != nil || f.NArg() != 0 {
		return errors.New("invalid options")
	}
	switch args[0] {
	case "init":
		return initialize(*dir)
	case "check-site":
		return checkSite(*dir)
	case "probe":
		if err := checkSite(*dir); err != nil {
			return err
		}
		b, err := os.ReadFile(filepath.Join(*dir, "site.json"))
		if err != nil {
			return err
		}
		var site portalSite
		if json.Unmarshal(b, &site) != nil {
			return errors.New("invalid portal site configuration")
		}
		p, err := newPortal(site, filepath.Join(*dir, "campus_root_ca.pem"), nvram("wan0_ipaddr"), nvram("wan0_ifname"))
		if err != nil {
			return err
		}
		status, err := p.api("/cgi-bin/rad_user_info", nil)
		if err != nil {
			return err
		}
		switch field(status, "error") {
		case "ok":
			fmt.Fprintln(out, "Portal connection verified; current WAN IP is online.")
		case "not_online_error", "speed_limit_error":
			fmt.Fprintln(out, "Portal connection verified; current WAN IP is not confirmed online.")
		default:
			return errors.New("portal returned an unexpected status")
		}
		return nil
	case "verify":
		return verifyPackage(*dir)
	case "status":
		b, err := os.ReadFile(*statusPath)
		if err != nil {
			return errors.New("status unavailable")
		}
		_, err = out.Write(b)
		return err
	case "public-key":
		b, err := os.ReadFile(filepath.Join(*dir, "web-public.b64"))
		if err != nil {
			return errors.New("web public key unavailable")
		}
		_, err = io.Copy(out, bytes.NewReader(b))
		return err
	case "apply":
		s, err := applySettings(*dir, *custom)
		if err != nil {
			publishStatus(*statusPath, s, "error", "设置未保存，请检查输入")
			return err
		}
		state := "waiting"
		if !s.Enabled {
			state = "disabled"
		}
		publishStatus(*statusPath, s, state, "")
		return nil
	case "daemon":
		daemon(*dir, *statusPath)
		return nil
	default:
		return errors.New("invalid command")
	}
}
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "campusctl:", err)
		os.Exit(1)
	}
}
