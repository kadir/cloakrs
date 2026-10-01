"""Validate release artifacts and install them into dependency-free environments."""

import argparse
from collections import Counter
from email.parser import BytesParser
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import venv
import zipfile

from packaging.tags import sys_tags
from packaging.utils import parse_wheel_filename
from packaging.version import Version

BINDING = Path(__file__).resolve().parent
PLATFORMS = {
    "manylinux_2_17_x86_64",
    "manylinux_2_17_aarch64",
    "macosx_11_0_x86_64",
    "macosx_11_0_arm64",
    "win_amd64",
}


def version():
    manifest = tomllib.loads((BINDING / "Cargo.toml").read_text(encoding="utf-8"))
    return str(Version(manifest["package"]["version"]))


def check_metadata(data, expected):
    info = BytesParser().parsebytes(data)
    assert info["Name"] == "cloakrs"
    assert info["Version"] == expected
    assert info["Requires-Python"] == ">=3.11"
    assert not info.get_all("Requires-Dist")
    assert info["License-Expression"] == "MIT"
    assert "# cloakrs for Python" in info.get_payload()


def check_dist(directory):
    expected = version()
    paths = list(directory.iterdir())
    wheels = sorted(directory.glob("*.whl"))
    sources = list(directory.glob("*.tar.gz"))
    assert len(wheels) == 5 and len(sources) == 1 and len(paths) == 6, (
        "A release requires exactly five platform wheels and one source archive"
    )
    platforms = Counter()
    for wheel in wheels:
        name, wheel_version, _, tags = parse_wheel_filename(wheel.name)
        assert name == "cloakrs" and str(wheel_version) == expected
        assert all(t.interpreter == "cp311" and t.abi == "abi3" for t in tags)
        supported = {t.platform for t in tags} & PLATFORMS
        assert len(supported) == 1, f"Unexpected wheel platform: {wheel.name}"
        platforms.update(supported)
        with zipfile.ZipFile(wheel) as archive:
            names = set(archive.namelist())
            assert {"cloakrs/__init__.py", "cloakrs/_native.pyi", "cloakrs/py.typed"} <= names
            assert any(n.startswith("cloakrs/_native") and n.endswith((".so", ".pyd")) for n in names)
            assert any(n.endswith("/licenses/LICENSE.md") for n in names)
            metadata = [n for n in names if n.endswith(".dist-info/METADATA")]
            assert len(metadata) == 1
            check_metadata(archive.read(metadata[0]), expected)
    assert platforms == Counter({p: 1 for p in PLATFORMS})
    assert sources[0].name == f"cloakrs-{expected}.tar.gz"
    with tarfile.open(sources[0]) as archive:
        prefix = f"cloakrs-{expected}/"
        names = {n.removeprefix(prefix) for n in archive.getnames()}
        required = {
            "pyproject.toml", "Cargo.toml", "LICENSE.md", "README.md",
            "bindings/python/Cargo.toml", "bindings/python/Cargo.lock",
            "bindings/python/src/lib.rs", "python/cloakrs/__init__.py",
            "python/cloakrs/_native.pyi", "python/cloakrs/py.typed",
        }
        for crate in ("core", "patterns", "locales"):
            required.update({f"crates/cloakrs-{crate}/Cargo.toml",
                             f"crates/cloakrs-{crate}/src/lib.rs"})
        assert required <= names, f"Missing source files: {required - names}"
        check_metadata(archive.extractfile(prefix + "PKG-INFO").read(), expected)
    print(f"Validated cloakrs {expected}: five abi3 wheels and a complete source archive")


def install_test(directory, source=False):
    """Build source outside the checkout, or select a native wheel without compilation."""
    expected = version()
    with tempfile.TemporaryDirectory(prefix="cloakrs-install-") as temporary:
        temporary = Path(temporary)
        wheel_dir = directory.resolve()
        if source:
            archives = list(wheel_dir.glob("*.tar.gz"))
            assert len(archives) == 1
            wheel_dir = temporary / "wheels"
            subprocess.run([
                sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-cache-dir",
                str(archives[0]), "--wheel-dir", str(wheel_dir),
            ], cwd=temporary, check=True)
        compatible = set(sys_tags())
        wheels = [p for p in wheel_dir.glob("*.whl")
                  if parse_wheel_filename(p.name)[3] & compatible]
        assert len(wheels) == 1, "Expected exactly one compatible wheel"
        assert str(parse_wheel_filename(wheels[0].name)[1]) == expected
        environment = temporary / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        subprocess.run([
            str(python), "-m", "pip", "--disable-pip-version-check", "install",
            "--no-index", "--no-deps", "--only-binary=:all:", str(wheels[0]),
        ], cwd=temporary, check=True)
        subprocess.run([
            str(python), str(BINDING / "tests/installed_smoke.py"), "--version", expected,
        ], cwd=temporary, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["version", "check", "install", "source"])
    parser.add_argument("directory", nargs="?", type=Path)
    args = parser.parse_args()
    if args.command == "version":
        expected = version()
        if os.environ.get("GITHUB_REF_TYPE") == "tag":
            assert os.environ["GITHUB_REF_NAME"] == f"python-v{expected}", (
                "Python release tag must match the package version"
            )
        print(expected)
        if output := os.environ.get("GITHUB_OUTPUT"):
            with open(output, "a", encoding="utf-8") as stream:
                stream.write(f"version={expected}\n")
    else:
        if args.directory is None:
            parser.error("directory is required")
        if args.command == "check":
            check_dist(args.directory)
        else:
            install_test(args.directory, source=args.command == "source")


if __name__ == "__main__":
    main()
