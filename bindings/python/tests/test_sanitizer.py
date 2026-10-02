"""Sanitizer behavior, sensitive mapping handling, and real CLI interoperability."""

from concurrent.futures import ThreadPoolExecutor
import copy
import json
import logging
import os
from pathlib import Path
import pickle
import subprocess

import pytest

from cloakrs import Mapping, Sanitizer

ROOT = Path(__file__).resolve().parents[3]
CORPUS = json.loads((ROOT / "tests/evaluation/corpus.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("style", ["brackets", "braces"])
@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda case: case["id"])
def test_corpus_round_trip_and_mapping_json(case, style):
    sanitizer = Sanitizer(locale=case["locale"].lower(),
                          min_confidence=CORPUS["min_confidence"])
    text = case["text"]
    clean, mapping = sanitizer.sanitize(text, placeholder_style=style)
    imported = Mapping.from_json(mapping.to_json())
    assert len(mapping) == len(imported)
    for key in (mapping, imported):
        assert key.restore(clean) == text
        assert key.restore(clean, strict=True) == text
    for entry in json.loads(mapping.to_json())["entries"]:
        assert text.encode("utf-8")[entry["span_start"]:entry["span_end"]].decode("utf-8") == (
            entry["original"]
        )


@pytest.mark.parametrize("style,open_,close", [("brackets", "[", "]"), ("braces", "{", "}")])
def test_repeated_values_collisions_and_tolerant_restoration(style, open_, close):
    existing = f"{open_} email_1 {close}"
    text = f"{existing} jane@example.com then jane@example.com"
    clean, mapping = Sanitizer().sanitize(text, placeholder_style=style)
    placeholder = f"{open_}EMAIL_2{close}"
    assert clean == f"{existing} {placeholder} then {placeholder}"
    assert len(mapping) == 1
    assert mapping.restore(clean) == text
    variant = f"{open_}\tEmail_2 \n{close}"
    unknown = f"{open_}EMAIL_20{close} {open_}EMAIL_02{close}"
    assert mapping.restore(f"Reply {variant} {unknown}") == f"Reply jane@example.com {unknown}"
    assert mapping.restore(variant, strict=True) == variant
    assert mapping.restore(placeholder, strict=True) == "jane@example.com"


def test_restore_does_not_recursively_expand_original_values():
    _, mapping = Sanitizer().sanitize("jane@example.com bob@example.com")
    data = json.loads(mapping.to_json())
    data["entries"][0].update(original="[EMAIL_2]", span_end=len("[EMAIL_2]"))
    mapping = Mapping.from_json(json.dumps(data))
    for strict in (False, True):
        assert mapping.restore("[EMAIL_1] [EMAIL_2]", strict=strict) == "[EMAIL_2] bob@example.com"


@pytest.mark.parametrize("style,placeholder", [
    ("brackets", "[EMAIL_1]"), ("braces", "{EMAIL_1}"),
])
@pytest.mark.parametrize("email", ["jane@example.com", "o'hara@example.com"])
def test_quoted_email_sanitization_and_mapping_round_trip(style, placeholder, email):
    text = f"日本語 🙂 email: '{email}'"
    clean, mapping = Sanitizer().sanitize(text, placeholder_style=style)
    assert clean == f"日本語 🙂 email: '{placeholder}'"
    entry, = json.loads(mapping.to_json())["entries"]
    assert entry["original"] == email
    assert text.encode()[entry["span_start"]:entry["span_end"]].decode() == email
    assert Mapping.from_json(mapping.to_json()).restore(clean, strict=True) == text


def test_encoded_quoted_email_sanitization_round_trip():
    text = "🙂 https://example.com?email=%27jane%40example.com%27"
    clean, mapping = Sanitizer(exclude_entities=["url"]).sanitize(text)
    assert clean == "🙂 https://example.com?email=%27[EMAIL_1]%27"
    assert Mapping.from_json(mapping.to_json()).restore(clean, strict=True) == text


@pytest.mark.parametrize("excluded", [(), ("url",)])
def test_unicode_and_nested_encoded_values_keep_rust_byte_offsets(excluded):
    text = "👩🏽‍💻 e\u0301 日本語: https://example.com?email=jane%40example.com&ssn=123-45-6789"
    clean, mapping = Sanitizer(locale="us", exclude_entities=excluded).sanitize(text)
    if excluded:
        assert clean.endswith("https://example.com?email=[EMAIL_1]&ssn=[SSN_1]")
        assert len(mapping) == 2
    else:
        assert clean == "👩🏽‍💻 e\u0301 日本語: [URL_1]"
        assert len(mapping) == 1
    assert mapping.restore(clean) == text
    entries = json.loads(mapping.to_json())["entries"]
    for entry in entries:
        assert text.encode()[entry["span_start"]:entry["span_end"]].decode() == entry["original"]
        assert entry["span_start"] > text.index(entry["original"])
    assert Mapping.from_json(mapping.to_json()).restore(clean) == text


def test_locale_exclusions_lists_and_configuration_isolation(tmp_path, monkeypatch):
    (tmp_path / ".cloakrs.toml").write_text("exclude_entities = ['bsn']")
    monkeypatch.chdir(tmp_path)
    deny = ["jane@example.com", "kept@example.com"]
    sanitizer = Sanitizer(locale="nl", exclude_entities=["email", "url"],
                          deny_list=deny, allow_list=["kept@example.com"])
    deny.clear()
    text = "https://example.com BSN 123456782 jane@example.com kept@example.com"
    clean, mapping = sanitizer.sanitize(text)
    assert clean == "https://example.com BSN [BSN_1] [DENYLIST_1] kept@example.com"
    assert mapping.restore(clean) == text


def test_url_credentials_are_replaced_by_default():
    text = "https://alice:supersecret@example.com/private"
    clean, mapping = Sanitizer().sanitize(text)
    assert clean == "[URL_1]"
    assert mapping.restore(clean) == text
    clean, mapping = Sanitizer(exclude_entities=["url"]).sanitize(text)
    assert clean == text
    assert len(mapping) == 0


@pytest.mark.parametrize("text", ["", "\x00🙂\nplain text\r\n", "\r\njane@example.com\n"])
def test_empty_text_and_exact_newlines(text):
    clean, mapping = Sanitizer().sanitize(text)
    assert mapping.restore(clean) == text
    assert Mapping.from_json(mapping.to_json()).restore(clean, strict=True) == text


def test_representations_and_logging_hide_all_mapping_fields(caplog):
    secret = "private-sensitive-value"
    entry = {
        "placeholder": secret, "entity_type": {"Custom": secret}, "original": secret,
        "span_start": 0, "span_end": len(secret), "confidence": 1.0, "recognizer_id": secret,
    }
    mapping = Mapping.from_json(json.dumps({"entries": [entry]}))
    assert repr(mapping) == str(mapping) == "Mapping(entries=1)"
    assert secret not in repr(Sanitizer(deny_list=[secret]))
    with caplog.at_level(logging.INFO):
        logging.getLogger(__name__).info("mapping=%s debug=%r", mapping, mapping)
    assert secret not in caplog.text
    assert secret in mapping.to_json()  # Export is an explicit sensitive operation.
    assert mapping.restore(secret) == secret


@pytest.mark.parametrize("protocol", range(pickle.HIGHEST_PROTOCOL + 1))
def test_mapping_cannot_be_implicitly_pickled(protocol):
    _, mapping = Sanitizer().sanitize("jane@example.com")
    with pytest.raises(TypeError, match="explicit sensitive export"):
        pickle.dumps(mapping, protocol=protocol)


def test_mapping_requires_explicit_construction_and_export():
    _, mapping = Sanitizer().sanitize("jane@example.com")
    with pytest.raises(TypeError, match="create a Mapping"):
        Mapping()
    for call in (copy.copy, copy.deepcopy, json.dumps):
        with pytest.raises(TypeError):
            call(mapping)
    with pytest.raises(TypeError, match="explicit sensitive export"):
        mapping.__getstate__()
    assert not hasattr(mapping, "__dict__")


@pytest.mark.parametrize("data", [
    "private-sensitive-value", '{"private-sensitive-value":', "{}", "null", "[]",
    '{"entries": [{"original": "private-sensitive-value"}]}',
    '{"entries": [], "private-sensitive-value": null} trailing',
])
def test_bad_json_does_not_echo_values(data):
    with pytest.raises(ValueError, match="invalid mapping JSON") as error:
        Mapping.from_json(data)
    assert "private-sensitive-value" not in repr(error.value)


@pytest.mark.parametrize("change", [
    {"placeholder": ""}, {"span_start": -1}, {"span_start": 100}, {"span_end": 1},
    {"span_end": 100}, {"confidence": -0.1}, {"confidence": 1.1},
    {"confidence": float("nan")}, {"confidence": float("inf")},
    {"entity_type": "private-sensitive-value"},
])
def test_inconsistent_entries_are_rejected_without_echoing_fields(change):
    _, mapping = Sanitizer().sanitize("jane@example.com")
    data = json.loads(mapping.to_json())
    data["entries"][0].update(change)
    with pytest.raises(ValueError, match="invalid mapping JSON") as error:
        Mapping.from_json(json.dumps(data))
    assert "jane@example.com" not in repr(error.value)
    assert "private-sensitive-value" not in repr(error.value)


@pytest.mark.parametrize("placeholder", ["[EMAIL_1]", "[ email_1 ]", "[Email_1]"])
def test_ambiguous_imported_placeholders_are_rejected(placeholder):
    _, mapping = Sanitizer().sanitize("jane@example.com")
    data = json.loads(mapping.to_json())
    data["entries"].append(dict(data["entries"][0], placeholder=placeholder))
    with pytest.raises(ValueError, match="invalid mapping JSON"):
        Mapping.from_json(json.dumps(data))


@pytest.mark.parametrize("value", [None, 123, b"private-sensitive-value", ["text"]])
def test_argument_types(value):
    sanitizer = Sanitizer()
    _, mapping = sanitizer.sanitize("jane@example.com")
    for call in (sanitizer.sanitize, mapping.restore, Mapping.from_json):
        with pytest.raises(TypeError):
            call(value)
    with pytest.raises(TypeError):
        sanitizer.sanitize("text", placeholder_style=value)
    with pytest.raises(TypeError):
        mapping.restore("text", strict=value)


def test_strict_rejects_truthy_strings():
    _, mapping = Sanitizer().sanitize("jane@example.com")
    with pytest.raises(TypeError, match="strict must be a boolean"):
        mapping.restore("[email_1]", strict="false")


def test_surrogates_and_bad_styles_do_not_echo_inputs():
    sanitizer = Sanitizer()
    _, mapping = sanitizer.sanitize("jane@example.com")
    secret = "private-sensitive-value\ud800"
    for call in (sanitizer.sanitize, mapping.restore, Mapping.from_json):
        with pytest.raises(ValueError, match="Unicode") as error:
            call(secret)
        assert "private-sensitive-value" not in repr(error.value)
    with pytest.raises(ValueError, match="Unicode"):
        Sanitizer(deny_list=[secret])
    for style in ("private-sensitive-value", secret):
        with pytest.raises(ValueError) as error:
            sanitizer.sanitize("jane@example.com", placeholder_style=style)
        assert "private-sensitive-value" not in repr(error.value)
    data = json.loads(mapping.to_json())
    data["entries"][0]["original"] = secret
    with pytest.raises(ValueError, match="invalid mapping JSON") as error:
        Mapping.from_json(json.dumps(data))
    assert "private-sensitive-value" not in repr(error.value)


@pytest.mark.parametrize("options,error_type", [
    ({"locale": "private-sensitive-value"}, ValueError),
    ({"exclude_entities": ["private-sensitive-value"]}, ValueError),
    ({"min_confidence": float("nan")}, ValueError),
    ({"min_confidence": 1.1}, ValueError),
    ({"exclude_entities": "email"}, TypeError),
    ({"allow_list": [123]}, TypeError),
    ({"deny_list": None}, TypeError),
])
def test_sanitizer_configuration_validation(options, error_type):
    with pytest.raises(error_type) as error:
        Sanitizer(**options)
    assert "private-sensitive-value" not in repr(error.value)


def test_shared_sanitizer_and_mapping_are_independent_across_threads():
    sanitizer = Sanitizer()
    texts = [f"Task {i}: person{i}@example.com" for i in range(32)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(sanitizer.sanitize, texts))
        restored = list(pool.map(lambda pair: pair[1].restore(pair[0]), results))
        shared = results[0][1]
        same_mapping = list(pool.map(shared.restore, ["[email_1]"] * 32))
    assert restored == texts
    assert same_mapping == ["person0@example.com"] * 32
    for i, (clean, mapping) in enumerate(results):
        assert clean == f"Task {i}: [EMAIL_1]"
        assert len(mapping) == 1


@pytest.fixture
def cli(tmp_path):
    executable = ROOT / "target/debug" / ("cloakrs.exe" if os.name == "nt" else "cloakrs")
    assert executable.is_file(), "Build the CLI first: cargo build --locked -p cloakrs-cli"
    config = tmp_path / "empty.toml"
    config.write_text("", encoding="utf-8")

    def run(text, *args):
        result = subprocess.run(
            [str(executable), "--quiet", "--config", str(config),
             "--locale", "us", "--min-confidence", "0", *args],
            input=text.encode("utf-8"), capture_output=True, check=True, cwd=tmp_path,
        )
        assert result.stderr == b""
        return result.stdout.decode("utf-8")

    return run


@pytest.mark.parametrize("style", ["brackets", "braces"])
@pytest.mark.parametrize("excluded", [False, True])
def test_python_and_cli_mapping_interoperability(cli, tmp_path, style, excluded):
    text = (
        "👩🏽‍💻 Résumé:\r\njane@example.com then jane@example.com\n"
        "https://example.com?email=jane%40example.com&ssn=123-45-6789\n"
    )
    exclusions = ["url"] if excluded else []
    clean, mapping = Sanitizer(locale="us", exclude_entities=exclusions).sanitize(
        text, placeholder_style=style,
    )
    python_path = tmp_path / "python.json"
    python_path.write_text(mapping.to_json(), encoding="utf-8")
    assert cli(clean, "restore", "--mapping", str(python_path)) == text
    assert cli(clean, "restore", "--mapping", str(python_path), "--strict") == text
    cli_path = tmp_path / "cli.json"
    cli_args = ["--exclude-entities", "url"] if excluded else []
    cli_clean = cli(text, *cli_args, "sanitize", "--mapping", str(cli_path),
                    "--placeholder-style", style)
    cli_json = cli_path.read_text(encoding="utf-8")
    assert cli_clean == clean
    assert json.loads(cli_json) == json.loads(mapping.to_json())
    imported = Mapping.from_json(cli_json)
    assert imported.restore(cli_clean) == text
    assert imported.restore(cli_clean, strict=True) == text
    placeholder = "[EMAIL_1]" if style == "brackets" else "{EMAIL_1}"
    variant = placeholder[0] + " email_1 " + placeholder[-1]
    assert cli(variant, "restore", "--mapping", str(python_path)) == imported.restore(variant)
    assert cli(variant, "restore", "--mapping", str(python_path), "--strict") == (
        imported.restore(variant, strict=True)
    ) == variant
