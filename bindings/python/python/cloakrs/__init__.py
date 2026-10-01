"""Local PII detection, redaction, and sanitization using the cloakrs Rust engine."""

from collections.abc import Sequence
from dataclasses import dataclass, field
from importlib.metadata import version
from typing import Never, SupportsIndex

from ._native import ENGINE_VERSION, ENTITY_TYPES, _Mapping, _Sanitizer, _Scanner

__version__ = version("cloakrs")
__engine_version__ = ENGINE_VERSION
__all__ = [
    "Scanner", "ScanResult", "Finding", "Sanitizer", "Mapping",
    "ENTITY_TYPES", "__version__", "__engine_version__",
]


@dataclass(frozen=True, slots=True)
class Finding:
    """A finding with half-open Python string indices and explicit sensitive text.

    ``source[finding.start:finding.end]`` selects the matched source value.
    Indices count Unicode code points, not UTF-8 bytes or display graphemes.
    """

    entity_type: str
    start: int
    end: int
    confidence: float
    recognizer_id: str
    text: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Redacted text and immutable findings. Text is omitted from repr()."""

    masked_text: str = field(repr=False)
    findings: tuple[Finding, ...]


def _strings(values: Sequence[str], option: str) -> list[str]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise TypeError(f"{option} must be a sequence of strings")
    result = list(values)
    if any(not isinstance(value, str) for value in result):
        raise TypeError(f"{option} must contain only strings")
    return result


class Scanner:
    """Reusable Rust scanner. All configuration is explicit and keyword-only.

    The default locale is ``universal`` and minimum confidence is 0.0, matching
    the Rust library. Exclusions are empty by default. Excluding ``url`` may
    leave embedded credentials visible. Literal allow-list precedence is
    preserved, including over deny-list findings.
    """

    __slots__ = ("_scanner",)

    def __init__(
        self,
        *,
        locale: str = "universal",
        min_confidence: float = 0.0,
        exclude_entities: Sequence[str] = (),
        allow_list: Sequence[str] = (),
        deny_list: Sequence[str] = (),
    ) -> None:
        try:
            self._scanner = _Scanner(
                locale=locale,
                min_confidence=min_confidence,
                exclude_entities=_strings(exclude_entities, "exclude_entities"),
                allow_list=_strings(allow_list, "allow_list"),
                deny_list=_strings(deny_list, "deny_list"),
            )
        except UnicodeEncodeError:
            raise ValueError("configuration must contain valid Unicode scalar values") from None

    def scan(self, text: str) -> ScanResult:
        """Scan text, returning redacted text and typed findings.

        Rust scanning runs with the Python interpreter lock released. Results
        contain sensitive original values through explicit ``Finding.text``
        access; ordinary representations omit them.
        """
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        try:
            masked, findings = self._scanner.scan(text)
        except UnicodeEncodeError:
            raise ValueError("text must contain valid Unicode scalar values") from None
        return ScanResult(masked, tuple(Finding(*finding) for finding in findings))

    def mask(self, text: str) -> str:
        """Return redacted text without materializing Python finding objects."""
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        try:
            return self._scanner.mask(text)
        except UnicodeEncodeError:
            raise ValueError("text must contain valid Unicode scalar values") from None

    def __repr__(self) -> str:
        return "Scanner()"


class Sanitizer:
    """Reusable Rust prompt sanitizer with the same configuration as Scanner.

    Each call returns an independent mapping. Repeated values within one call
    share a placeholder; existing placeholders in the input are preserved.
    """

    __slots__ = ("_sanitizer",)

    def __init__(
        self,
        *,
        locale: str = "universal",
        min_confidence: float = 0.0,
        exclude_entities: Sequence[str] = (),
        allow_list: Sequence[str] = (),
        deny_list: Sequence[str] = (),
    ) -> None:
        try:
            self._sanitizer = _Sanitizer(
                locale=locale,
                min_confidence=min_confidence,
                exclude_entities=_strings(exclude_entities, "exclude_entities"),
                allow_list=_strings(allow_list, "allow_list"),
                deny_list=_strings(deny_list, "deny_list"),
            )
        except UnicodeEncodeError:
            raise ValueError("configuration must contain valid Unicode scalar values") from None

    def sanitize(
        self, text: str, *, placeholder_style: str = "brackets",
    ) -> tuple[str, "Mapping"]:
        """Replace detected values with numbered bracket or brace placeholders.

        Keep the returned mapping private: it holds the original values needed
        to restore a response. Rust processing releases the interpreter lock.
        """
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        if not isinstance(placeholder_style, str):
            raise TypeError("placeholder_style must be a string")
        try:
            clean, mapping = self._sanitizer.sanitize(text, placeholder_style=placeholder_style)
        except UnicodeEncodeError:
            raise ValueError("arguments must contain valid Unicode scalar values") from None
        return clean, Mapping._from_native(mapping)

    def __repr__(self) -> str:
        return "Sanitizer()"


class Mapping:
    """Opaque restore key. JSON export explicitly exposes sensitive originals.

    Create through Sanitizer.sanitize() or Mapping.from_json(). Representations
    show only the entry count; automatic pickling is disabled.
    """

    __slots__ = ("_mapping",)
    _mapping: _Mapping

    def __init__(self) -> None:
        raise TypeError("create a Mapping with Sanitizer.sanitize() or Mapping.from_json()")

    @classmethod
    def _from_native(cls, mapping: _Mapping) -> "Mapping":
        result = object.__new__(cls)
        result._mapping = mapping
        return result

    @classmethod
    def from_json(cls, data: str) -> "Mapping":
        """Import Rust CLI-compatible mapping JSON without echoing parse errors.

        Reject inconsistent spans, invalid confidence, empty placeholders, and
        duplicate placeholders under the Rust engine's tolerant normalization.
        """
        if not isinstance(data, str):
            raise TypeError("data must be a JSON string")
        try:
            return cls._from_native(_Mapping.from_json(data))
        except UnicodeEncodeError:
            raise ValueError("data must contain valid Unicode scalar values") from None

    def to_json(self) -> str:
        """Export sensitive original values in the Rust CLI's mapping schema.

        Stored spans are UTF-8 byte offsets of the first occurrence, unlike
        Finding's Python string indices. No file is written automatically.
        """
        return self._mapping.to_json()

    def restore(self, text: str, *, strict: bool = False) -> str:
        """Restore known placeholders, leaving unknown ones untouched.

        By default, ASCII case and whitespace inside numbered placeholders are
        tolerated. strict=True requires exact matches. Replacements are not
        recursively restored. This operation releases the interpreter lock.
        """
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        if not isinstance(strict, bool):
            raise TypeError("strict must be a boolean")
        try:
            return self._mapping.restore(text, strict=strict)
        except UnicodeEncodeError:
            raise ValueError("text must contain valid Unicode scalar values") from None

    def __len__(self) -> int:
        return len(self._mapping)

    def __repr__(self) -> str:
        return f"Mapping(entries={len(self)})"

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise TypeError("Mapping cannot be pickled; use to_json() for explicit sensitive export")

    def __reduce__(self) -> Never:
        raise TypeError("Mapping cannot be pickled; use to_json() for explicit sensitive export")

    def __getstate__(self) -> Never:
        raise TypeError("Mapping cannot be pickled; use to_json() for explicit sensitive export")
