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
