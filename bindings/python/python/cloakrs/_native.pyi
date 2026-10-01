from typing import Final

ENGINE_VERSION: Final[str]
ENTITY_TYPES: Final[tuple[str, ...]]

class _Scanner:
    def __init__(
        self,
        *,
        locale: str,
        min_confidence: float,
        exclude_entities: list[str],
        allow_list: list[str],
        deny_list: list[str],
    ) -> None: ...
    def scan(self, text: str) -> tuple[str, list[tuple[str, int, int, float, str, str]]]: ...
    def mask(self, text: str) -> str: ...

class _Sanitizer:
    def __init__(
        self,
        *,
        locale: str,
        min_confidence: float,
        exclude_entities: list[str],
        allow_list: list[str],
        deny_list: list[str],
    ) -> None: ...
    def sanitize(
        self, text: str, *, placeholder_style: str = "brackets",
    ) -> tuple[str, _Mapping]: ...

class _Mapping:
    @staticmethod
    def from_json(data: str) -> _Mapping: ...
    def to_json(self) -> str: ...
    def restore(self, text: str, *, strict: bool = False) -> str: ...
    def __len__(self) -> int: ...
