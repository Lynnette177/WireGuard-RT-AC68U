package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoginParametersAgainstPythonReference(t *testing.T) {
	v, err := loginParameters("test-user", "example-password", strings.Repeat("a", 64), "10.20.0.3", "11")
	if err != nil {
		t.Fatal(err)
	}
	if v.Get("password") != "{MD5}495982878ce18256a187c7ef0d39ea83" || v.Get("chksum") != "03abaecc4ea4a841cc910c9cd9f25f253cb6d2a1" {
		t.Fatal("password digest or checksum differs from reference")
	}
	if v.Get("info") != "{SRBX1}nNOHd0Q+bc74t1ILkbEot0q9GgoP+FY/z+X8jo/PN7sPzJHP+D7JdhKp04F8wFv7OPz19i4//TlXBEUhKkgz/Bh+o0E4hmMRBVGsN92MPMgm6RvQR4DV9nCcF69hYmLPkU4WmXKVR8b4zp9S" {
		t.Fatal("SRun encoded info differs from reference")
	}
}

func TestPackageAndCACheck(t *testing.T) {
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic Test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"campusctl": []byte("binary"), "page.asp": []byte("page"), "manager.sh": []byte("manager"), "install.sh": []byte("installer"), "site.json": []byte(`{"ip":"192.0.2.1","server_name":"portal.example.test"}`), "campus_root_ca.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	var manifest strings.Builder
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		fmt.Fprintf(&manifest, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(manifest.String()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyPackage(dir); err != nil {
		t.Fatal(err)
	}
	if err := checkSite(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "page.asp"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyPackage(dir); err == nil {
		t.Fatal("accepted altered addon package")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLoginUncertainResponseOnlyChecksStatus(t *testing.T) {
	statusCalls, loginCalls := 0, 0
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var text string
		switch r.URL.Path {
		case "/cgi-bin/rad_user_info":
			statusCalls++
			state := "not_online_error"
			if statusCalls > 1 {
				state = "ok"
			}
			text = fmt.Sprintf(`%s({"error":"%s","client_ip":"10.20.0.3"})`, r.URL.Query().Get("callback"), state)
		case "/":
			text = "var CONFIG = {\nip: '10.20.0.3',\nac_id: '11'\n};"
		case "/cgi-bin/get_challenge":
			text = fmt.Sprintf(`%s({"error":"ok","challenge":"%s"})`, r.URL.Query().Get("callback"), strings.Repeat("a", 64))
		case "/cgi-bin/srun_portal":
			loginCalls++
			if r.URL.Query().Get("password") == "example-password" {
				t.Fatal("plaintext password sent to portal")
			}
			text = "malformed response"
		default:
			t.Fatal("unexpected portal path")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(text)), Header: make(http.Header), Request: r}, nil
	})
	p := portal{site: portalSite{IP: "192.0.2.1"}, client: &http.Client{Transport: transport}, referer: "https://192.0.2.1/"}
	state, err := p.check("test-user", "example-password", nil)
	if err != nil || state != "online" || loginCalls != 1 || statusCalls != 2 {
		t.Fatalf("state=%s err=%v login=%d status=%d", state, err, loginCalls, statusCalls)
	}
}

func TestDisabledDuringCheckDoesNotSubmitLogin(t *testing.T) {
	loginCalls := 0
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := ""
		switch r.URL.Path {
		case "/cgi-bin/rad_user_info":
			body = fmt.Sprintf(`%s({"error":"not_online_error","client_ip":"10.20.0.3"})`, r.URL.Query().Get("callback"))
		case "/":
			body = "var CONFIG = {\nip: '10.20.0.3',\nac_id: '11'\n};"
		case "/cgi-bin/get_challenge":
			body = fmt.Sprintf(`%s({"error":"ok","challenge":"%s"})`, r.URL.Query().Get("callback"), strings.Repeat("a", 64))
		case "/cgi-bin/srun_portal":
			loginCalls++
		default:
			t.Fatal("unexpected portal path")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: r}, nil
	})
	p := portal{site: portalSite{IP: "192.0.2.1"}, client: &http.Client{Transport: transport}, referer: "https://192.0.2.1/"}
	state, err := p.check("synthetic-user", "synthetic-password", func() bool { return false })
	if err != nil || state != "cancelled" || loginCalls != 0 {
		t.Fatalf("disabled login was submitted: state=%s err=%v count=%d", state, err, loginCalls)
	}
}

func TestIntermediateRedirectPreservesControllerID(t *testing.T) {
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := newPortal(portalSite{IP: "192.0.2.1", ServerName: "portal.example.test"}, ca, "127.0.0.1", "lo")
	if err != nil {
		t.Fatal(err)
	}
	statusCalls, loginCalls := 0, 0
	p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		h := make(http.Header)
		status := 200
		body := ""
		switch r.URL.Path {
		case "/cgi-bin/rad_user_info":
			statusCalls++
			state := "not_online_error"
			if statusCalls > 1 {
				state = "ok"
			}
			body = fmt.Sprintf(`%s({"error":"%s","client_ip":"10.20.0.3"})`, r.URL.Query().Get("callback"), state)
		case "/":
			status = 302
			h.Set("Location", "/route?ac_id=11")
		case "/route":
			status = 302
			h.Set("Location", "/final")
		case "/final":
			body = "var CONFIG = {\nip: '10.20.0.3'\n};"
		case "/cgi-bin/get_challenge":
			body = fmt.Sprintf(`%s({"error":"ok","challenge":"%s"})`, r.URL.Query().Get("callback"), strings.Repeat("a", 64))
		case "/cgi-bin/srun_portal":
			loginCalls++
			if r.URL.Query().Get("ac_id") != "11" {
				t.Fatal("intermediate access-controller ID was lost")
			}
			body = fmt.Sprintf(`%s({"error":"ok"})`, r.URL.Query().Get("callback"))
		default:
			t.Fatal("unexpected request")
		}
		return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})
	state, err := p.check("synthetic-user", "synthetic-password", nil)
	if err != nil || state != "online" || loginCalls != 1 {
		t.Fatalf("state=%s err=%v login=%d", state, err, loginCalls)
	}
}

func TestEncryptedWebSettingsAndSecretFreeStatus(t *testing.T) {
	dir := t.TempDir()
	if err := initialize(dir); err != nil {
		t.Fatal(err)
	}
	key, err := privateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := json.Marshal(credentials{Username: "synthetic-user", Password: "synthetic-password"})
	cipher, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, plain, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "custom.txt")
	content := "otheraddon_value retained\ncampuslogin_enabled 1\ncampuslogin_interval 7\ncampuslogin_secret " + base64.StdEncoding.EncodeToString(cipher) + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := applySettings(dir, path)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Enabled || s.Interval != 7 || s.Username != "synthetic-user" || s.Password != "synthetic-password" {
		t.Fatal("settings not applied")
	}
	statusPath := filepath.Join(dir, "status.json")
	publishStatus(statusPath, s, "online", "")
	b, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), s.Username) || strings.Contains(string(b), s.Password) || strings.Contains(content, s.Username) || strings.Contains(content, s.Password) {
		t.Fatal("credentials leaked into public status/settings")
	}
	if _, err := applySettings(dir, path); err != nil {
		t.Fatal("reapplying encrypted settings failed", err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(content, "campuslogin_interval 7", "campuslogin_interval 0", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := applySettings(dir, path); err == nil {
		t.Fatal("invalid interval accepted")
	}
	saved, err := loadSettings(dir)
	if err != nil || saved.Interval != 7 {
		t.Fatal("invalid update changed saved configuration")
	}
}
