#!/usr/bin/env python3
"""Check published archives and real installer behavior on a native runner."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import zipfile


def download(url):
    for attempt in range(3):
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'cloakrs-release-smoke'})
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read()
        except OSError:
            if attempt == 2:
                raise
            time.sleep(2)


def check_binary(binary, version, directory):
    actual = subprocess.check_output([str(binary), '--version'], text=True).strip()
    if actual != 'cloakrs ' + version:
        raise RuntimeError(f'Unexpected version: {actual}')
    source = directory / 'input.txt'
    source.write_text('Contact jane@example.com\n', encoding='utf-8')
    result = subprocess.run([str(binary), 'scan', str(source), '--output-format', 'json'],
                            capture_output=True, text=True)
    if result.returncode != 1:
        raise RuntimeError(f'Unexpected scan exit: {result.returncode}: {result.stderr}')
    report = json.loads(result.stdout)
    if report['total_findings'] != 1 or report['findings_by_type'] != {'Email': 1}:
        raise RuntimeError('Email detection smoke failed')
    if report['findings'][0]['masked_value'] != 'Contact [EMAIL]':
        raise RuntimeError('Email masking smoke failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--target', required=True, choices=[
        'x86_64-unknown-linux-gnu', 'x86_64-unknown-linux-musl',
        'aarch64-unknown-linux-gnu', 'x86_64-apple-darwin',
        'aarch64-apple-darwin', 'x86_64-pc-windows-msvc'])
    parser.add_argument('--repo', default='kadir/cloakrs')
    args = parser.parse_args()
    if not re.fullmatch(r'v[0-9][A-Za-z0-9._-]*', args.tag):
        parser.error('invalid release tag')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repo):
        parser.error('invalid repository')
    windows = args.target.endswith('windows-msvc')
    filename = f'cloakrs-{args.tag}-{args.target}.' + ('zip' if windows else 'tar.gz')
    base = f'https://github.com/{args.repo}/releases/download/{args.tag}'
    manifest = download(base + '/SHA256SUMS.txt').decode('utf-8')
    checksums = [fields[0] for line in manifest.splitlines()
                 if len(fields := line.split()) == 2 and fields[1].lstrip('*') == filename]
    if len(checksums) != 1 or not re.fullmatch(r'[0-9a-fA-F]{64}', checksums[0]):
        raise RuntimeError('Expected one valid checksum for this archive')
    data = download(base + '/' + filename)
    if hashlib.sha256(data).hexdigest() != checksums[0].lower():
        raise RuntimeError('Archive checksum mismatch')
    with tempfile.TemporaryDirectory(prefix='cloakrs-release-') as temporary:
        directory = Path(temporary)
        binary = directory / ('cloakrs.exe' if windows else 'cloakrs')
        if windows:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                if archive.namelist() != ['cloakrs.exe']:
                    raise RuntimeError('Unexpected ZIP contents')
                binary.write_bytes(archive.read('cloakrs.exe'))
        else:
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
                members = archive.getmembers()
                if len(members) != 1 or members[0].name != 'cloakrs' or not members[0].isfile():
                    raise RuntimeError('Unexpected tar contents')
                with archive.extractfile(members[0]) as source, binary.open('wb') as dest:
                    shutil.copyfileobj(source, dest)
            binary.chmod(0o755)
        check_binary(binary, args.tag[1:], directory)
        print(f'Published archive OK: {filename}', flush=True)
        if not windows:
            installer = Path(__file__).resolve().parents[2] / 'install.sh'
            for version in (args.tag, 'latest'):
                destination = directory / version
                env = dict(os.environ, CLOAKRS_REPO=args.repo, CLOAKRS_VERSION=version,
                           CLOAKRS_INSTALL_DIR=str(destination))
                subprocess.run(['sh', str(installer)], env=env, check=True)
                check_binary(destination / 'cloakrs', args.tag[1:], directory)
                print(f'Published installer OK: {version}', flush=True)


if __name__ == '__main__':
    main()
