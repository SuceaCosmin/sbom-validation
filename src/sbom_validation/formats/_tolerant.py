"""Type-tolerant accessors shared by the format loaders."""

from typing import Any


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _dicts(value: Any) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _strs(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]
