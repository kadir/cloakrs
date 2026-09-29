"""Local PII detection and redaction using the cloakrs Rust engine."""

from collections.abc import Sequence
from dataclasses import dataclass, field
from importlib.metadata import version

from ._native import ENGINE_VERSION, ENTITY_TYPES, _Scanner

__version__ = version("cloakrs")
__engine_version__ = ENGINE_VERSION
__all__ = ["Scanner", "ScanResult", "Finding", "ENTITY_TYPES", "__version__", "__engine_version__"]


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
