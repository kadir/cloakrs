"""Run with only the installed package and Python's standard library."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from importlib import metadata, resources
import json
from pathlib import Path

import cloakrs
from cloakrs import Mapping, Sanitizer, Scanner


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    assert cloakrs.__version__ == metadata.version("cloakrs") == args.version
    assert cloakrs.__engine_version__ == "0.4.1"
    assert not metadata.requires("cloakrs")
    assert "site-packages" in Path(cloakrs.__file__).parts
    for name in ("py.typed", "_native.pyi"):
        assert resources.files("cloakrs").joinpath(name).is_file()
    text = "👩🏽‍💻 Résumé: jane@example.com\r\n"
    scanner = Scanner(locale="us")
    finding = scanner.scan(text).findings[0]
    assert text[finding.start:finding.end] == finding.text == "jane@example.com"
    assert scanner.mask(text) == "👩🏽‍💻 Résumé: [EMAIL]\r\n"
    sanitizer = Sanitizer(locale="us")
    for email in ("jane@example.com", "o'hara@example.com"):
        quoted = f"日本語 🙂 VALUES ('{email}');"
        assert scanner.mask(quoted) == "日本語 🙂 VALUES ('[EMAIL]');"
        clean, mapping = sanitizer.sanitize(quoted)
        assert clean == "日本語 🙂 VALUES ('[EMAIL_1]');"
        assert Mapping.from_json(mapping.to_json()).restore(clean, strict=True) == quoted
    for style in ("brackets", "braces"):
        clean, mapping = sanitizer.sanitize(text, placeholder_style=style)
        assert "jane@example.com" not in clean
        assert repr(mapping) == "Mapping(entries=1)"
        imported = Mapping.from_json(mapping.to_json())
        assert imported.restore(clean, strict=True) == text
        assert imported.restore(clean.lower()) == text.lower()
        entry = json.loads(mapping.to_json())["entries"][0]
        assert text.encode()[entry["span_start"]:entry["span_end"]].decode() == finding.text
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(scanner.mask, [text] * 16)) == [scanner.mask(text)] * 16
    print(f"Installed cloakrs {args.version}: detection, masking, restoration, types, and threads OK")


if __name__ == "__main__":
    main()
