"""Checked with mypy against the installed typed package."""
from typing import assert_type

from cloakrs import ENTITY_TYPES, Finding, Mapping, Sanitizer, Scanner, ScanResult

scanner = Scanner(locale="us", exclude_entities=["url"])
result = scanner.scan("Email jane@example.com")
assert_type(result, ScanResult)
assert_type(result.masked_text, str)
assert_type(result.findings, tuple[Finding, ...])
assert_type(result.findings[0].start, int)
assert_type(result.findings[0].confidence, float)
assert_type(scanner.mask("text"), str)
assert_type(ENTITY_TYPES, tuple[str, ...])

sanitizer = Sanitizer(locale="us", deny_list=["private-value"])
assert_type(sanitizer.sanitize("jane@example.com"), tuple[str, Mapping])
clean, mapping = sanitizer.sanitize("jane@example.com", placeholder_style="braces")
assert_type(clean, str)
assert_type(mapping, Mapping)
assert_type(mapping.restore(clean), str)
assert_type(mapping.restore(clean, strict=True), str)
assert_type(mapping.to_json(), str)
assert_type(Mapping.from_json(mapping.to_json()), Mapping)
assert_type(len(mapping), int)
