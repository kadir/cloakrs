"""Exercise the installed Python wheel against the real Rust engine."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from importlib import metadata, resources
import json
from pathlib import Path
import re

import pytest

import cloakrs
from cloakrs import ENTITY_TYPES, Finding, Scanner, ScanResult

ROOT = Path(__file__).resolve().parents[3]
CORPUS = json.loads((ROOT / "tests/evaluation/corpus.json").read_text(encoding="utf-8"))
BASELINE = {
    case["id"]: case["findings"]
    for case in json.loads(
        (ROOT / "tests/evaluation/baseline.json").read_text(encoding="utf-8")
    )["predictions"]
}


def canonical_entity(name):
    return re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", name).lower()


@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda case: case["id"])
def test_matches_rust_detection_snapshot(case):
    scanner = Scanner(locale=case["locale"].lower(), min_confidence=CORPUS["min_confidence"])
    text = case["text"]
    result = scanner.scan(text)
    actual = []
    for finding in result.findings:
        assert text[finding.start:finding.end] == finding.text
        actual.append((finding.entity_type, len(text[:finding.start].encode("utf-8")),
                       len(text[:finding.end].encode("utf-8"))))
    expected = [(canonical_entity(f["entity_type"]), f["start"], f["end"])
                for f in BASELINE[case["id"]]]
    assert sorted(actual) == sorted(expected)
    assert scanner.mask(text) == result.masked_text


@pytest.mark.parametrize("prefix", ["", "Résumé: ", "👩🏽‍💻 e\u0301 日本語: ", "\x00🙂\n"])
def test_python_offsets_and_nested_encoded_values(prefix):
    text = prefix + "https://example.com?email=jane%40example.com&ssn=123-45-6789"
    scanner = Scanner(locale="us")
    result = scanner.scan(text)
    assert {f.entity_type for f in result.findings} == {"url", "email", "ssn"}
    for finding in result.findings:
        assert text[finding.start:finding.end] == finding.text
        assert finding.start >= len(prefix)
    assert result.masked_text == prefix + "[URL]"
    excluded = Scanner(locale="us", exclude_entities=["url", "url"]).scan(text)
    assert excluded.masked_text == prefix + "https://example.com?email=[EMAIL]&ssn=[SSN]"
    email = next(f for f in excluded.findings if f.entity_type == "email")
    assert email.start == text.index("jane")
    assert email.text == "jane%40example.com"


def test_results_are_typed_immutable_and_do_not_leak_in_repr():
    sensitive = "jane@example.com"
    visible = "unrecognized-secret-value"
    scanner = Scanner(deny_list=[sensitive], allow_list=["kept@example.com"])
    result = scanner.scan(f"{visible} {sensitive} kept@example.com")
    assert isinstance(result, ScanResult)
    assert isinstance(result.findings, tuple)
    assert isinstance(result.findings[0], Finding)
    assert result.findings[0].text == sensitive
    for item in (scanner, result, result.findings, *result.findings):
        assert sensitive not in repr(item)
        assert visible not in repr(item)
        assert "kept@example.com" not in repr(item)
    with pytest.raises(FrozenInstanceError):
        result.masked_text = "changed"
    with pytest.raises(FrozenInstanceError):
        result.findings[0].text = "changed"


def test_exclusions_locale_and_literal_list_precedence():
    scanner = Scanner(locale="nl", exclude_entities=["email", "url"],
                      deny_list=["jane@example.com", "kept@example.com"],
                      allow_list=["kept@example.com"])
    text = "https://example.com BSN 123456782 jane@example.com kept@example.com"
    result = scanner.scan(text)
    assert result.masked_text == "https://example.com BSN [BSN] [DENYLIST] kept@example.com"
    assert {f.entity_type for f in result.findings} == {"bsn", "deny-list"}


def test_explicit_options_do_not_read_working_directory_config(tmp_path, monkeypatch):
    (tmp_path / ".cloakrs.toml").write_text("exclude_entities = ['email']")
    monkeypatch.chdir(tmp_path)
    assert Scanner().mask("jane@example.com") == "[EMAIL]"


def test_options_are_copied_and_all_canonical_names_are_accepted():
    exclusions = ["url"]
    scanner = Scanner(exclude_entities=exclusions)
    exclusions.append("email")
    assert scanner.mask("jane@example.com") == "[EMAIL]"
    assert len(ENTITY_TYPES) == 28
    assert Scanner(exclude_entities=ENTITY_TYPES).mask("jane@example.com") == "jane@example.com"


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -0.1, 1.1])
def test_invalid_confidence_is_rejected(value):
    with pytest.raises(ValueError, match="min_confidence"):
        Scanner(min_confidence=value)


@pytest.mark.parametrize("options", [
    {"locale": "private-secret"}, {"exclude_entities": ["private-secret"]},
])
def test_invalid_names_do_not_echo_values(options):
    with pytest.raises(ValueError) as error:
        Scanner(**options)
    assert "private-secret" not in repr(error.value)


@pytest.mark.parametrize("option", ["exclude_entities", "allow_list", "deny_list"])
@pytest.mark.parametrize("value", ["email", b"email", [123], None])
def test_option_sequences_are_validated(option, value):
    with pytest.raises(TypeError):
        Scanner(**{option: value})


@pytest.mark.parametrize("value", [None, 123, b"jane@example.com", ["jane@example.com"]])
def test_text_must_be_a_string(value):
    scanner = Scanner()
    for call in (scanner.scan, scanner.mask):
        with pytest.raises(TypeError, match="text must be a string"):
            call(value)


def test_lone_surrogates_fail_without_echoing_input():
    text = "private-secret\ud800"
    scanner = Scanner()
    for call in (scanner.scan, scanner.mask):
        with pytest.raises(ValueError, match="Unicode") as error:
            call(text)
        assert "private-secret" not in repr(error.value)
    with pytest.raises(ValueError, match="Unicode") as error:
        Scanner(deny_list=[text])
    assert "private-secret" not in repr(error.value)


def test_empty_input_and_newlines_are_preserved():
    scanner = Scanner()
    assert scanner.scan("") == ScanResult("", ())
    assert scanner.mask("\nplain text\r\n") == "\nplain text\r\n"


def test_url_credentials_are_masked_by_default_and_exclusion_is_explicit():
    text = "https://alice:supersecret@example.com/private"
    assert Scanner().mask(text) == "[URL]"
    assert Scanner(exclude_entities=["url"]).mask(text) == text


def test_shared_scanner_calls_do_not_mix_results():
    scanner = Scanner()
    texts = [f"Task {index}: jane@example.com" for index in range(32)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(scanner.scan, texts))
    for index, result in enumerate(results):
        assert result.masked_text == f"Task {index}: [EMAIL]"
        assert result.findings[0].text == "jane@example.com"


def test_installed_wheel_has_version_type_hints_and_native_extension():
    assert cloakrs.__version__ == metadata.version("cloakrs") == "0.1.0a1"
    assert cloakrs.__engine_version__ == "0.4.0"
    assert resources.files("cloakrs").joinpath("py.typed").is_file()
    assert resources.files("cloakrs").joinpath("_native.pyi").is_file()
    assert "site-packages" in Path(cloakrs.__file__).parts
