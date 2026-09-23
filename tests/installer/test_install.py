"""Offline installer contract tests. Download and platform commands are fixtures."""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

INSTALLER = Path(__file__).resolve().parents[2] / 'install.sh'


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'mock-bin'
        self.bin.mkdir()
        self.dest = self.root / 'install with spaces'
        self.dest.mkdir()
        self.original = self.dest / 'cloakrs'
        self.original.write_text('previous installation')
        self.env = os.environ.copy()
        self.env.update(PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        CLOAKRS_INSTALL_DIR=str(self.dest), CLOAKRS_VERSION='latest',
                        CLOAKRS_REPO='kadir/cloakrs', FIXTURES=str(self.root),
                        TEST_OS='Darwin', TEST_ARCH='arm64')
        self.command('uname', '#!/bin/sh\ncase "$1" in -s) echo "$TEST_OS";; -m) echo "$TEST_ARCH";; esac\n')
        self.command('curl', f'#!{sys.executable}\n' + '''import os, pathlib, shutil, sys
args = sys.argv[1:]
url = next(x for x in args if x.startswith('https://'))
root = pathlib.Path(os.environ['FIXTURES'])
with (root/'requests').open('a') as f: f.write(url+'\\n')
if os.environ.get('FAIL_DOWNLOAD') == '1': sys.exit(22)
source = root / url.rsplit('/', 1)[1]
if not source.exists(): sys.exit(22)
shutil.copyfile(source, args[args.index('-o') + 1])
''')
        self.fixture()

    def command(self, name, text):
        p = self.bin / name
        p.write_text(text)
        p.chmod(0o755)

    def fixture(self, target='aarch64-apple-darwin', member='cloakrs', version='0.3.1'):
        self.archive_name = f'cloakrs-v0.3.1-{target}.tar.gz'
        archive = self.root / self.archive_name
        payload = f'#!/bin/sh\nprintf "cloakrs {version}\\n"\n'.encode()
        with tarfile.open(archive, 'w:gz') as t:
            entry = tarfile.TarInfo(member)
            entry.size = len(payload)
            entry.mode = 0o755
            t.addfile(entry, io.BytesIO(payload))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.manifest = self.root / 'SHA256SUMS.txt'
        self.manifest.write_text(f'{digest}  {self.archive_name}\n' + '0'*64 + '  unrelated.zip\n')

    def run_installer(self, ok=True):
        result = subprocess.run(['sh', str(INSTALLER)], env=self.env,
                                capture_output=True, text=True)
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(subprocess.check_output([str(self.original), '--version'], text=True).strip(), 'cloakrs 0.3.1')
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(self.original.read_text(), 'previous installation')
        return result

    def test_latest_uses_manifest_then_pins_archive_tag(self):
        self.run_installer()
        urls = (self.root / 'requests').read_text().splitlines()
        self.assertTrue(urls[0].endswith('/latest/download/SHA256SUMS.txt'))
        self.assertTrue(urls[1].endswith('/download/v0.3.1/' + self.archive_name))

    def test_pinned_versions_with_and_without_v(self):
        for version in ['0.3.1', 'v0.3.1']:
            self.env['CLOAKRS_VERSION'] = version
            self.run_installer()
        self.assertNotIn('/latest/', (self.root / 'requests').read_text())

    def test_all_supported_platform_targets(self):
        for system, arch, target in [
            ('Darwin', 'x86_64', 'x86_64-apple-darwin'),
            ('Linux', 'x86_64', 'x86_64-unknown-linux-musl'),
            ('Linux', 'aarch64', 'aarch64-unknown-linux-gnu'),
        ]:
            with self.subTest(target=target):
                self.env.update(TEST_OS=system, TEST_ARCH=arch)
                self.fixture(target=target)
                self.run_installer()

    def test_tampering_does_not_replace_existing_binary(self):
        with (self.root/self.archive_name).open('ab') as f: f.write(b'changed')
        self.run_installer(ok=False)

    def test_missing_duplicate_and_invalid_checksums_fail(self):
        original = self.manifest.read_text()
        for contents in ['', original + original, f'not-a-hash  {self.archive_name}\n']:
            self.manifest.write_text(contents)
            self.run_installer(ok=False)

    def test_archive_paths_are_rejected(self):
        self.fixture(member='../cloakrs')
        self.run_installer(ok=False)

    def test_wrong_binary_version_is_rejected(self):
        self.fixture(version='0.0.0')
        self.run_installer(ok=False)

    def test_download_failure_preserves_installation(self):
        self.env['FAIL_DOWNLOAD'] = '1'
        self.run_installer(ok=False)

    def test_unsupported_platform_fails_before_download(self):
        self.env['TEST_ARCH'] = 'mips'
        self.run_installer(ok=False)
        self.assertFalse((self.root/'requests').exists())

    def test_invalid_version_and_repository_fail_before_download(self):
        for key, value in [('CLOAKRS_VERSION', '../bad'), ('CLOAKRS_REPO', 'owner/repo/extra')]:
            old = self.env[key]
            self.env[key] = value
            self.run_installer(ok=False)
            self.env[key] = old
        self.assertFalse((self.root/'requests').exists())


if __name__ == '__main__':
    unittest.main()
