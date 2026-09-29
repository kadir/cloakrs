"""Checked with mypy against the installed typed package."""
from typing import assert_type

from cloakrs import ENTITY_TYPES, Finding, Scanner, ScanResult

scanner = Scanner(locale="us", exclude_entities=["url"])
result = scanner.scan("Email jane@example.com")
assert_type(result, ScanResult)
assert_type(result.masked_text, str)
assert_type(result.findings, tuple[Finding, ...])
assert_type(result.findings[0].start, int)
assert_type(result.findings[0].confidence, float)
assert_type(scanner.mask("text"), str)
assert_type(ENTITY_TYPES, tuple[str, ...])
