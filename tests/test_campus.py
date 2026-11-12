"""Isolated addon installation tests; all router tools and paths are mocked."""
import os
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tarfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_deployment import ROOT, SH, PWSH, posix


class CampusInstallerTests(unittest.TestCase):
    def setUp(self):
        (ROOT / '.toolchains').mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix='campus-test-', dir=ROOT / '.toolchains'))
        assert self.root.resolve().is_relative_to(ROOT.resolve())
        self.base = self.root / 'addons/campus-login'
        self.hooks = self.root / 'scripts'
        self.web = self.root / 'web'
        self.stage = self.root / 'stage'
        self.bin = self.root / 'bin'
        self.tmp = self.root / 'tmp'
        self.firmware = self.root / 'firmware'
        for path in (self.hooks, self.web, self.stage, self.bin, self.tmp, self.firmware):
            path.mkdir(parents=True, exist_ok=True)
        self.trace = self.root / 'trace'
        self.env = dict(os.environ, TEST_BIN=posix(self.bin), TEST_BASE=posix(self.base), TEST_TRACE=posix(self.trace), TEST_WEB=posix(self.web))
        self.write(self.bin / 'uname', '#!/bin/sh\necho armv7l\n')
        self.write(self.bin / 'nvram', '#!/bin/sh\ncase "$*" in "get rc_support") echo am_addons;; "get lan_ipaddr") echo 192.168.1.1;; esac\n')
        self.write(self.bin / 'mount', '#!/bin/sh\necho "mount $*" >>"$TEST_TRACE"\n')
        self.write(self.bin / 'umount', '#!/bin/sh\necho "umount $*" >>"$TEST_TRACE"\n')
        self.write(self.bin / 'readlink', '#!/bin/sh\necho "$TEST_BASE/campusctl"\n')
        self.write(self.firmware / 'helper.sh', '#!/bin/sh\n')
        self.write(self.firmware / 'menuTree.js', 'var x=[\n{url: "Tools_OtherSettings.asp", tabName: "Other Settings"},\n];\n')
        for name in ('install.sh','manager.sh'):
            text = (ROOT / 'campus' / name).read_text(encoding='utf-8')
            for old, new in (
                ('PATH=/sbin:/bin:/usr/sbin:/usr/bin:/koolshare/bin', 'PATH="$TEST_BIN:/sbin:/bin:/usr/sbin:/usr/bin:/koolshare/bin"'),
                ('/jffs/addons/campus-login', posix(self.base)),
                ('/jffs/scripts', posix(self.hooks)),
                ('/www/require/modules/menuTree.js', posix(self.firmware / 'menuTree.js')),
                ('/usr/sbin/helper.sh', posix(self.firmware / 'helper.sh')),
                ('/www/user', posix(self.web)),
                ('/tmp/menuTree.js', posix(self.tmp / 'menuTree.js')),
                ('/tmp/campus-login', posix(self.tmp / 'campus-login')),
            ):
                text = text.replace(old, new)
            self.write(self.stage / name, text)
        self.write(self.stage / 'campusctl', '#!/bin/sh\ncase "$1" in init) [ "${TEST_INIT_FAIL:-0}" != 1 ] || exit 1; echo QUJDRA== > "$TEST_BASE/web-public.b64";; public-key) echo QUJDRA==;; daemon) echo "{}" > "$TEST_WEB/campus-login-status.json"; sleep 2;; esac\nexit 0\n')
        self.write(self.stage / 'page.asp', '<!-- CAMPUS_LOGIN_ADDON_ID -->\n__CAMPUS_PUBLIC_KEY__\n')
        self.write(self.stage / 'site.json', '{}\n')
        self.write(self.stage / 'campus_root_ca.pem', 'synthetic test certificate\n')
        self.write(self.stage / 'SHA256SUMS', 'mocked; real verifier is tested in Go\n')

    def tearDown(self):
        target = self.root.resolve()
        assert target.is_relative_to((ROOT / '.toolchains').resolve())
        assert target.name.startswith('campus-test-')
        shutil.rmtree(target)

    def write(self, path, text):
        path.write_bytes(text.encode('utf-8'))
        path.chmod(0o700)

    def shell(self, command, extra=None):
        command = 'PATH="$TEST_BIN:/usr/bin:/bin"; export PATH; ' + command
        return subprocess.run([str(SH), '-c', command], cwd=self.stage, env=dict(self.env, **(extra or {})), capture_output=True, text=True, timeout=30)

    def test_install_twice_preserves_existing_hooks(self):
        old = '#!/bin/sh\necho existing\nexit 0\n'
        for name in ('services-start','wan-start','service-event'):
            self.write(self.hooks / name, old)
        for _ in range(2):
            result=self.shell('sh ./install.sh')
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        for name in ('services-start','wan-start','service-event'):
            data=(self.hooks / name).read_text()
            self.assertEqual(data.count('# BEGIN CAMPUS_LOGIN_ADDON'),1)
            self.assertIn('echo existing\nexit 0',data)
        page=self.web / 'user1.asp'
        self.assertIn('QUJDRA==',page.read_text())
        self.assertIn('CAMPUS_LOGIN_ADDON_MENU',(self.tmp/'menuTree.js').read_text())

    def test_failed_initialization_restores_hooks(self):
        old='#!/bin/sh\necho keep-existing\nexit 0\n'
        self.write(self.hooks/'services-start',old)
        result=self.shell('sh ./install.sh',{'TEST_INIT_FAIL':'1'})
        self.assertNotEqual(result.returncode,0)
        self.assertIn('restoring previous addon files and hooks',result.stderr)
        self.assertEqual((self.hooks/'services-start').read_text(),old)
        self.assertFalse((self.hooks/'service-event').exists())

    def test_packaging_uploads_site_and_ca_without_credentials(self):
        go=ROOT/'.toolchains/go1.23.12/go/bin/go.exe'
        fake=self.root/'mock-transport.exe'
        env=dict(os.environ,GOTOOLCHAIN='local',GOOS='windows',GOARCH='amd64',CGO_ENABLED='0')
        subprocess.run([str(go),'build','-o',str(fake),str(ROOT/'tests/mock_transport.go')],env=env,check=True,capture_output=True,timeout=60)
        for name in ('ssh.exe','scp.exe'):
            shutil.copyfile(fake,self.bin/name)
        trace=self.root/'transport.jsonl';archive=self.root/'captured.tar.gz'
        env=dict(os.environ,PATH=str(self.bin)+os.pathsep+os.environ['PATH'],WG68_MOCK_TRACE=str(trace),WG68_MOCK_ARCHIVE=str(archive),WG68_MOCK_FAIL='')
        before=set(Path(tempfile.gettempdir()).glob('campus-deploy-*'))
        result=subprocess.run([PWSH,'-NoProfile','-ExecutionPolicy','Bypass','-File',str(ROOT/'campus/deploy-campus.ps1'),'-RouterAddress','192.168.1.1','-SitePath',str(self.stage/'site.json'),'-CaPath',str(self.stage/'campus_root_ca.pem')],env=env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        calls=[json.loads(line) for line in trace.read_text().splitlines()]
        self.assertEqual(len(calls),3)
        self.assertIn('-O',calls[1])
        self.assertEqual(before,set(Path(tempfile.gettempdir()).glob('campus-deploy-*')))
        with tarfile.open(archive,'r:gz') as package:
            self.assertEqual(set(package.getnames()),{'campusctl','page.asp','manager.sh','install.sh','site.json','campus_root_ca.pem','SHA256SUMS'})
            for line in package.extractfile('SHA256SUMS').read().decode().splitlines():
                digest,name=line.split()
                self.assertEqual(hashlib.sha256(package.extractfile(name).read()).hexdigest(),digest)
            for name in package.getnames():
                if name!='campusctl':
                    self.assertNotIn(b'PRIVATE KEY',package.extractfile(name).read())


if __name__ == '__main__':
    unittest.main(verbosity=2)
