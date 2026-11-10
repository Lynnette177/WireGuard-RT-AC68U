"""Offline installer/service integration tests. All router commands are mocked.

Uses Git for Windows sh; never opens a network connection or touches /jffs.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def find_sh():
    override = os.environ.get("WG68_TEST_SH")
    if override:
        return Path(override)
    git = shutil.which("git")
    candidates = []
    if git:
        candidates.append(Path(git).resolve().parent.parent / "bin/sh.exe")
    for variable in ("ProgramFiles", "ProgramFiles(x86)"):
        if os.environ.get(variable):
            candidates.append(Path(os.environ[variable]) / "Git/bin/sh.exe")
    shell = shutil.which("sh")
    if shell:
        candidates.append(Path(shell))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise RuntimeError("Install Git for Windows or set WG68_TEST_SH to sh.exe")


SH = find_sh()
PWSH = os.environ.get("WG68_TEST_POWERSHELL") or shutil.which("pwsh") or shutil.which("powershell")


def posix(p):
    p = Path(p).resolve()
    if not p.drive:
        return p.as_posix()
    return "/" + p.drive[0].lower() + p.as_posix()[2:]


class DeploymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / ".toolchains").mkdir(exist_ok=True)
        cls.mock_transport = ROOT / ".toolchains/mock-transport.exe"
        go = ROOT / ".toolchains/go1.23.12/go/bin/go.exe"
        if not go.is_file():
            installed_go = shutil.which("go")
            if not installed_go:
                raise RuntimeError("Install Go or run scripts/build-wgctl.ps1 first")
            go = Path(installed_go)
        env = dict(os.environ, GOTOOLCHAIN="go1.23.12", GOOS="windows", GOARCH="amd64", CGO_ENABLED="0")
        subprocess.run([str(go), "build", "-o", str(cls.mock_transport), str(ROOT / "tests/mock_transport.go")], env=env, check=True, capture_output=True, timeout=60)

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="wg68-test-", dir=ROOT / ".toolchains"))
        assert self.root.resolve().is_relative_to(ROOT.resolve())
        self.base = self.root / "jffs/wireguard"
        self.hooks = self.root / "jffs/scripts"
        self.stage = self.root / "stage"
        self.bin = self.root / "bin"
        self.state = self.root / "state"
        for p in (self.base, self.hooks, self.stage, self.bin, self.state):
            p.mkdir(parents=True, exist_ok=True)
        self.trace = self.root / "trace"
        self.env = dict(os.environ, PATH=posix(self.bin) + ":/usr/bin:/bin", TRACE=posix(self.trace),
                        TEST_BIN=posix(self.bin), WG68_BASE=posix(self.base), WG68_STATE=posix(self.state))
        for name, body in {
            "id": "echo 'id is unavailable on this firmware' >&2; exit 127",
            "nohup": "echo 'nohup is unavailable on this firmware' >&2; exit 127",
            "uname": "echo armv7l",
            "modprobe": "exit 0",
            "df": "echo 'Filesystem 1K-blocks Used Available Use% Mounted'; echo 'flash 64000 14000 50000 22% /jffs'",
            "nvram": "case \"$*\" in 'get lan_ifname') echo br0;; 'get lan_ipaddr') echo 192.168.1.1;; 'get lan_netmask') echo 255.255.255.0;; 'get jffs2_scripts') echo 0;; *) echo \"nvram $*\" >>\"$TRACE\";; esac",
            "ip": "echo 'ip is unavailable on this firmware' >&2; exit 127",
            "iptables": "echo \"iptables $*\" >>\"$TRACE\"; case \" $* \" in *' -D '*) exit 1;; esac; exit 0",
            "readlink": "echo \"$WG68_BASE/wireguard-go\"",
        }.items():
            self.write(self.bin / name, "#!/bin/sh\n" + body + "\n")
        for name in ("install.sh", "uninstall.sh"):
            text = (ROOT / "router" / name).read_text()
            text = text.replace("/jffs/wireguard", posix(self.base)).replace("/jffs/scripts", posix(self.hooks))
            text = text.replace("/dev/net/tun", "/dev/null")
            self.write(self.stage / name, text)
        for name, text in {
            "wgctl": "#!/bin/sh\ncase $1 in link-exists) exit 1;; esac\nexit 0\n",
            "wireguard-go": "#!/bin/sh\necho test-daemon\n",
            "wg0.conf": "synthetic test configuration, no real keys\n",
            "service.sh": "#!/bin/sh\necho \"new-service $*\" >>\"$TRACE\"\ncase $1 in start) [ \"${FAIL_NEW:-0}\" != 1 ] || exit 1; touch \"$WG68_STATE/running\";; stop) rm -f \"$WG68_STATE/running\";; status) test -f \"$WG68_STATE/running\";; esac\n",
            "SHA256SUMS": "mocked for shell tests; real verifier has Go tests\n",
        }.items():
            self.write(self.stage / name, text)

    def tearDown(self):
        target = self.root.resolve()
        assert target.is_relative_to((ROOT / ".toolchains").resolve())
        assert target.name.startswith("wg68-test-")
        shutil.rmtree(target)

    def write(self, path, text):
        path.write_bytes(text.encode("utf-8"))
        path.chmod(0o700)

    def shell(self, command, *, check=True, extra=None):
        command = 'PATH="$TEST_BIN:/usr/bin:/bin"; export PATH; ' + command
        result = subprocess.run([str(SH), "-c", command], cwd=self.stage,
                                env=dict(self.env, **(extra or {})), text=True,
                                capture_output=True, timeout=30)
        if check and result.returncode:
            self.fail(result.stdout + result.stderr)
        return result

    def test_install_repeat_and_restore_hooks(self):
        old_hook = '#!/bin/sh\necho ORIGINAL >>"$TRACE"\nexit 0\n'
        self.write(self.hooks / "firewall-start", old_hook)
        self.shell("sh ./install.sh")
        original = self.hooks / "firewall-start.wireguard-original"
        self.assertEqual(original.read_text(), old_hook)
        self.shell("sh ./install.sh")
        self.assertEqual(original.read_text(), old_hook)
        self.shell('sh "' + posix(self.hooks / "firewall-start") + '"')
        trace = self.trace.read_text()
        self.assertIn("ORIGINAL", trace)
        self.assertIn("new-service firewall", trace)
        self.shell('sh "' + posix(self.base / "uninstall.sh") + '"')
        self.assertEqual((self.hooks / "firewall-start").read_text(), old_hook)
        self.assertFalse((self.hooks / "services-start").exists())
        self.assertFalse((self.hooks / "wan-start").exists())
        self.assertTrue((self.base / "wg0.conf").exists())

    def test_failed_upgrade_restores_old_files_and_hooks(self):
        old_service = '#!/bin/sh\necho "old-service $*" >>"$TRACE"\nexit 0\n'
        old_hook = "#!/bin/sh\nexit 0\n"
        self.write(self.base / "service.sh", old_service)
        self.write(self.base / "wg0.conf", "old private config\n")
        self.write(self.hooks / "services-start", old_hook)
        result = self.shell("sh ./install.sh", check=False, extra={"FAIL_NEW": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.base / "service.sh").read_text(), old_service)
        self.assertEqual((self.base / "wg0.conf").read_text(), "old private config\n")
        self.assertEqual((self.hooks / "services-start").read_text(), old_hook)
        self.assertIn("old-service start", self.trace.read_text())

    def test_install_with_unreliable_command_lookup(self):
        installer = self.stage / "install.sh"
        text = installer.read_text().replace("set -eu\n", "set -eu\ncommand() { return 127; }\n", 1)
        self.write(installer, text)
        self.shell("sh ./install.sh")
        self.assertTrue((self.base / "wg0.conf").exists())
        self.assertIn("iptables -V", self.trace.read_text())

    def test_firewall_allows_remote_lan_connections_with_scoped_destinations(self):
        self.write(self.base / "service.sh", (ROOT / "router/service.sh").read_text())
        self.write(self.base / "wireguard-go", "unused")
        key = lambda b: base64.b64encode(bytes([b]) * 32).decode()
        self.write(self.base / "wg0.conf", f"[Interface]\nPrivateKey = {key(1)}\nAddress = 10.20.0.3/32\nDNS = 192.168.20.1\n[Peer]\nPublicKey = {key(2)}\nAllowedIPs = 192.168.20.0/24, 10.30.0.1/32, 10.20.0.0/24\nEndpoint = vpn.example.test:51820\n")
        self.write(self.base / "wgctl", '#!/bin/sh\nexec "' + posix(ROOT / "dist/wgctl-check.exe") + '" "$@"\n')
        command = 'echo $$ >"$WG68_STATE/pid"; touch "$WG68_STATE/ready"; sh "' + posix(self.base / "service.sh") + '" firewall'
        self.shell(command)
        trace = self.trace.read_text()
        self.assertIn("-o wg0 -d 192.168.20.0/24 -j ACCEPT", trace)
        allow = "-i wg0 -o br0 -s 192.168.20.0/24 -d 192.168.1.1/255.255.255.0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT"
        self.assertIn(allow, trace)
        self.assertLess(trace.index(allow), trace.index("-A WG68_FWD -i wg0 -j DROP"))
        self.assertNotIn("-A WG68_IN -i wg0 -s 192.168.20.0/24 -m state --state NEW", trace)
        self.assertIn("-s 192.168.1.1/255.255.255.0 -o wg0 -d 192.168.20.0/24 -j MASQUERADE", trace)
        self.assertIn("ESTABLISHED,RELATED", trace)
        for prefix in ("10.20.0.0/24", "10.30.0.1/32"):
            inbound = f"-i wg0 -o br0 -s {prefix} -d 192.168.1.1/255.255.255.0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT"
            self.assertIn(inbound, trace)
            self.assertLess(trace.index(inbound), trace.index("-A WG68_FWD -i wg0 -j DROP"))
            self.assertIn(f"-o wg0 -d {prefix} -j ACCEPT", trace)
            self.assertIn(f"-o wg0 -d {prefix} -j MASQUERADE", trace)
        self.assertNotIn("0.0.0.0/0", trace)
        self.assertNotIn("dnsmasq", trace)

    def test_offline_powershell_with_synthetic_config(self):
        key = lambda b: base64.b64encode(bytes([b]) * 32).decode()
        conf = self.root / "test.conf"
        self.write(conf, f"[Interface]\nPrivateKey = {key(1)}\nAddress = 10.20.0.3/32\nDNS = 192.168.20.1\nMTU = 1300\n[Peer]\nPublicKey = {key(2)}\nAllowedIPs = 192.168.20.0/24, 10.30.0.1/32\nEndpoint = vpn.example.test:51820\nPersistentKeepalive = 25\n")
        before = hashlib.sha256(conf.read_bytes()).digest()
        result = subprocess.run([PWSH, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ROOT / "deploy.ps1"),
                                 "-ConfigPath", str(conf), "-ValidateOnly"], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("No router connection was made", result.stdout)
        self.assertEqual(hashlib.sha256(conf.read_bytes()).digest(), before)
        self.assertNotIn(key(1), result.stdout + result.stderr)

    def test_router_override_controls_management_validation(self):
        key = lambda b: base64.b64encode(bytes([b]) * 32).decode()
        conf = self.root / "alternate-lan.conf"
        self.write(conf, f"[Interface]\nPrivateKey = {key(1)}\nAddress = 10.20.0.3/32\n[Peer]\nPublicKey = {key(2)}\nAllowedIPs = 192.168.1.0/24\nEndpoint = vpn.example.test:51820\n")
        result = subprocess.run([PWSH, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ROOT / "deploy.ps1"),
                                 "-ConfigPath", str(conf), "-RouterAddress", "192.168.100.1", "-ValidateOnly"], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("No router connection was made", result.stdout)

    def test_real_service_start_and_stop_with_mocked_router(self):
        run = self.root / "run"
        run.mkdir()
        sock = run / "wg0.sock"
        forward = self.root / "ip_forward"
        self.write(forward, "1\n")
        text = (ROOT / "router/service.sh").read_text()
        text = text.replace("set -u\n", "set -u\ncommand() { return 127; }\n", 1)
        text = text.replace("/dev/net/tun", "/dev/null")
        text = text.replace("/var/run/wireguard", posix(run))
        text = text.replace("/proc/sys/net/ipv4/ip_forward", posix(forward))
        # MSYS sockets differ from native Linux; a marker stands in for -S.
        text = text.replace('[ -S ', '[ -e ')
        self.write(self.base / "service.sh", text)
        self.write(self.base / "wg0.conf", "synthetic")
        self.write(self.base / "wgctl", "#!/bin/sh\necho \"wgctl $*\" >>\"$TRACE\"\ncase $1 in link-exists) exit 1;; plan) printf \"WG_ADDRESSES='10.20.0.3/32'\\nWG_ROUTES='192.168.20.0/24'\\nWG_MTU='1300'\\n\";; show) echo 'last_handshake_time_sec: 1';; esac\n")
        self.write(self.base / "wireguard-go", '#!/bin/sh\ntrap \'rm -f "' + posix(sock) + '"; exit 0\' TERM INT\ntouch "' + posix(sock) + '"\nwhile :; do sleep 1; done\n')
        command = 'sh "' + posix(self.base / "service.sh") + '" '
        try:
            self.shell(command + "start")
            self.assertTrue((self.state / "ready").exists())
            trace = self.trace.read_text()
            self.assertIn("wgctl network-up -config ", trace)
            self.assertIn("-interface wg0 -management 192.168.1.1", trace)
            self.assertNotIn("-subnet", trace)
            self.assertNotIn("ip route", trace)
            self.assertNotIn("default", trace)
            self.assertNotIn("10.30.0.1", trace)
            self.assertNotIn("dnsmasq", trace)
        finally:
            self.shell(command + "stop")
        self.assertFalse((self.state / "ready").exists())
        self.assertFalse(sock.exists())

    def transport_test(self, fail_scp=False):
        key = lambda b: base64.b64encode(bytes([b]) * 32).decode()
        config = self.root / "synthetic config.conf"
        text = f"[Interface]\nPrivateKey = {key(1)}\nAddress = 10.20.0.3/32\nDNS = 192.168.20.1\nMTU = 1300\n[Peer]\nPublicKey = {key(2)}\nAllowedIPs = 192.168.20.0/24, 10.30.0.1/32\nEndpoint = vpn.example.test:51820\nPersistentKeepalive = 25\n"
        self.write(config, text)
        for name in ("ssh.exe", "scp.exe"):
            shutil.copyfile(self.mock_transport, self.bin / name)
        trace = self.root / "transport.jsonl"
        archive = self.root / "captured.tar.gz"
        env = dict(os.environ, PATH=str(self.bin)+os.pathsep+os.environ["PATH"],
                   WG68_MOCK_TRACE=str(trace), WG68_MOCK_ARCHIVE=str(archive),
                   WG68_MOCK_FAIL="scp" if fail_scp else "")
        before = set(Path(tempfile.gettempdir()).glob("wg68-deploy-*"))
        result = subprocess.run([PWSH, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ROOT / "deploy.ps1"),
                                 "-ConfigPath", str(config)], env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
        if fail_scp:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Installed and started", result.stdout)
        calls = [json.loads(line) for line in trace.read_text().splitlines()]
        self.assertEqual(len(calls), 3, calls)
        self.assertEqual(Path(calls[1][0]).name.lower(), "scp.exe")
        self.assertIn("-O", calls[1])
        self.assertIn("admin@192.168.1.1", calls[0])
        self.assertIn("rm -rf '/tmp/wg68-deploy-", calls[2][-1])
        self.assertNotIn(key(1), result.stdout + result.stderr + trace.read_text())
        self.assertEqual(config.read_text(), text)
        after = set(Path(tempfile.gettempdir()).glob("wg68-deploy-*"))
        self.assertEqual(before, after, "deployment left a private temporary directory")
        with tarfile.open(archive, "r:gz") as package:
            self.assertEqual(set(package.getnames()), {"wireguard-go", "wgctl", "wg0.conf", "service.sh", "install.sh", "uninstall.sh", "SHA256SUMS"})
            self.assertEqual(package.extractfile("wg0.conf").read().decode(), text)
            sums = package.extractfile("SHA256SUMS").read().decode().splitlines()
            for entry in sums:
                expected, name = entry.split()
                self.assertEqual(hashlib.sha256(package.extractfile(name).read()).hexdigest(), expected)

    def test_packaging_and_upload_with_mock_transport(self):
        self.transport_test()

    def test_failed_upload_cleans_private_staging(self):
        self.transport_test(fail_scp=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
