package main

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const alphabet = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"

// xencode implements the 32-bit little-endian SRun user-info transform.
func xencode(data []byte, token string) []byte {
	if len(data) == 0 {
		return nil
	}
	n := (len(data) + 3) / 4
	buf := make([]byte, n*4)
	copy(buf, data)
	v := make([]uint32, n+1)
	for i := 0; i < n; i++ {
		v[i] = binary.LittleEndian.Uint32(buf[i*4:])
	}
	v[n] = uint32(len(data))
	kb := make([]byte, 16)
	copy(kb, []byte(token))
	var k [4]uint32
	for i := range k {
		k[i] = binary.LittleEndian.Uint32(kb[i*4:])
	}
	var sum uint32
	z := v[n]
	for q := 6 + 52/len(v); q > 0; q-- {
		sum += 0x9e3779b9
		e := (sum >> 2) & 3
		for p := range v {
			y := v[(p+1)%len(v)]
			mixed := ((z >> 5) ^ (y << 2)) + (((y >> 3) ^ (z << 4)) ^ (sum ^ y)) + (k[(uint32(p)&3)^e] ^ z)
			v[p] += mixed
			z = v[p]
		}
	}
	out := make([]byte, len(v)*4)
	for i, x := range v {
		binary.LittleEndian.PutUint32(out[i*4:], x)
	}
	return out
}

func loginParameters(username, password, token, ip, acid string) (url.Values, error) {
	info := struct {
		Username string `json:"username"`
		Password string `json:"password"`
		IP       string `json:"ip"`
		Acid     string `json:"acid"`
		Enc      string `json:"enc_ver"`
	}{username, password, ip, acid, "srun_bx1"}
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(info); err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(xencode([]byte(strings.TrimSuffix(b.String(), "\n")), token))
	standard := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	mapping := strings.NewReplacer(func() []string {
		v := make([]string, 0, 128)
		for i := range standard {
			v = append(v, string(standard[i]), string(alphabet[i]))
		}
		return v
	}()...)
	infoValue := "{SRBX1}" + mapping.Replace(encoded)
	mac := hmac.New(md5.New, []byte(token))
	mac.Write([]byte(password))
	digest := hex.EncodeToString(mac.Sum(nil))
	h := sha1.New()
	for _, part := range []string{username, digest, acid, ip, "200", "1", infoValue} {
		io.WriteString(h, token+part)
	}
	return url.Values{"action": {"login"}, "username": {username}, "password": {"{MD5}" + digest}, "os": {"Mac OS"}, "name": {"Macintosh"}, "double_stack": {"0"}, "chksum": {hex.EncodeToString(h.Sum(nil))}, "info": {infoValue}, "ac_id": {acid}, "ip": {ip}, "n": {"200"}, "type": {"1"}}, nil
}

type portalSite struct {
	IP         string `json:"ip"`
	ServerName string `json:"server_name"`
}
type portal struct {
	site    portalSite
	client  *http.Client
	referer string
	routeAC string
}

func newPortal(site portalSite, caFile, wanIP, wanIf string) (*portal, error) {
	if net.ParseIP(site.IP) == nil || net.ParseIP(site.IP).To4() == nil || !validHost.MatchString(site.ServerName) {
		return nil, errors.New("invalid portal configuration")
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, errors.New("cannot read portal CA certificate")
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid portal CA certificate")
	}
	addr := net.ParseIP(wanIP)
	if addr == nil || addr.To4() == nil || addr.IsUnspecified() {
		return nil, errors.New("WAN IPv4 address is unavailable")
	}
	d := &net.Dialer{Timeout: 12 * time.Second, LocalAddr: &net.TCPAddr{IP: addr}, Control: bindDevice(wanIf)}
	t := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: site.ServerName, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return d.DialContext(ctx, "tcp4", net.JoinHostPort(site.IP, "443"))
	}, TLSHandshakeTimeout: 12 * time.Second, DisableKeepAlives: true}
	p := &portal{site: site, referer: "https://" + site.IP + "/"}
	c := &http.Client{Transport: t, Timeout: 15 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.Hostname() != site.IP || (req.URL.Port() != "" && req.URL.Port() != "443") || req.URL.User != nil {
			return errors.New("portal redirect rejected")
		}
		if id := req.URL.Query().Get("ac_id"); digits.MatchString(id) {
			p.routeAC = id
		}
		return nil
	}}
	p.client = c
	return p, nil
}

var validHost = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]*$`)
var configBlock = regexp.MustCompile(`(?s)\bvar\s+CONFIG\s*=\s*\{(.*?)\n\s*\};`)
var pageIP = regexp.MustCompile(`\bip\s*:\s*["']([^"']+)["']`)
var pageAC = regexp.MustCompile(`\bac_id["']?\s*:\s*(?:["'](\d+)["']|(\d+)\b)`)
var challengePattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
var digits = regexp.MustCompile(`^\d+$`)

func (p *portal) get(path string, params url.Values) (string, *url.URL, error) {
	if path == "/" {
		p.routeAC = ""
	}
	u := url.URL{Scheme: "https", Host: p.site.IP, Path: path}
	if params != nil {
		u.RawQuery = params.Encode()
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", nil, errors.New("invalid portal request")
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
	req.Header.Set("Accept", "application/json, text/javascript, text/html, */*")
	req.Header.Set("Referer", p.referer)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Cookie", "lang=zh-CN")
	resp, err := p.client.Do(req)
	if err != nil {
		return "", nil, errors.New("portal connection or TLS verification failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", nil, fmt.Errorf("portal returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024+1))
	if err != nil || len(b) > 2*1024*1024 {
		return "", nil, errors.New("invalid portal response")
	}
	return strings.TrimPrefix(string(b), "\ufeff"), resp.Request.URL, nil
}
func (p *portal) api(path string, values url.Values) (map[string]any, error) {
	if values == nil {
		values = url.Values{}
	}
	callback := "campus_login_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	values.Set("callback", callback)
	values.Set("_", strconv.FormatInt(time.Now().UnixMilli(), 10))
	text, _, err := p.get(path, values)
	if err != nil {
		return nil, err
	}
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, callback) {
		text = strings.TrimPrefix(text, callback)
		text = strings.TrimSpace(text)
		if !strings.HasPrefix(text, "(") {
			return nil, errors.New("invalid portal callback")
		}
		text = strings.TrimSpace(strings.TrimSuffix(text, ";"))
		if !strings.HasSuffix(text, ")") {
			return nil, errors.New("invalid portal callback")
		}
		text = text[1 : len(text)-1]
	}
	var obj map[string]any
	if json.Unmarshal([]byte(text), &obj) != nil || obj == nil {
		return nil, errors.New("invalid portal response")
	}
	return obj, nil
}
func field(m map[string]any, k string) string { v, _ := m[k].(string); return v }
func validIP(s string) string {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil || ip.IsUnspecified() {
		return ""
	}
	return ip.To4().String()
}

// check performs at most one login submission. An uncertain response is only
// followed by status queries, never by a second authentication request.
func (p *portal) check(username, password string, maySubmit func() bool) (string, error) {
	status, err := p.api("/cgi-bin/rad_user_info", nil)
	if err != nil {
		return "error", err
	}
	if field(status, "error") == "ok" {
		return "online", nil
	}
	if v := field(status, "error"); v != "not_online_error" && v != "speed_limit_error" {
		return "error", errors.New("portal status request rejected")
	}
	page, route, err := p.get("/", nil)
	if err != nil {
		return "error", err
	}
	block := ""
	if m := configBlock.FindStringSubmatch(page); len(m) > 1 {
		block = m[1]
	}
	ip := validIP(field(status, "client_ip"))
	if ip == "" {
		ip = validIP(field(status, "online_ip"))
	}
	if ip == "" {
		if m := pageIP.FindStringSubmatch(block); len(m) > 1 {
			ip = validIP(m[1])
		}
	}
	acid := ""
	if m := pageAC.FindStringSubmatch(block); len(m) > 2 {
		acid = m[1]
		if acid == "" {
			acid = m[2]
		}
	}
	if acid == "" {
		v := route.Query().Get("ac_id")
		if digits.MatchString(v) {
			acid = v
		}
	}
	if acid == "" {
		acid = p.routeAC
	}
	if ip == "" || acid == "" {
		return "error", errors.New("portal did not provide an IP or access-controller ID")
	}
	p.referer = "https://" + p.site.IP + route.RequestURI()
	challenge, err := p.api("/cgi-bin/get_challenge", url.Values{"username": {username}, "ip": {ip}})
	if err != nil {
		return "error", err
	}
	token := field(challenge, "challenge")
	if field(challenge, "error") != "ok" || !challengePattern.MatchString(token) {
		return "error", errors.New("portal challenge rejected")
	}
	if replacement := validIP(field(challenge, "client_ip")); replacement != "" {
		ip = replacement
	}
	if maySubmit != nil && !maySubmit() {
		return "cancelled", nil
	}
	values, err := loginParameters(username, password, token, ip, acid)
	if err != nil {
		return "error", err
	}
	result, loginErr := p.api("/cgi-bin/srun_portal", values)
	if loginErr == nil && field(result, "error") != "ok" && field(result, "error") != "ip_already_online_error" && field(result, "res") != "ip_already_online_error" && field(result, "suc_msg") != "ip_already_online_error" && field(result, "error_msg") != "no_response_data_error" {
		return "error", errors.New("portal login rejected; check credentials and account status")
	}
	for i := 0; i < 5; i++ {
		if i > 0 {
			time.Sleep(3 * time.Second)
		}
		status, err = p.api("/cgi-bin/rad_user_info", nil)
		if err == nil && field(status, "error") == "ok" {
			return "online", nil
		}
	}
	return "uncertain", errors.New("login submitted, but online status could not be confirmed")
}
