"""Offline JSON-schema validation against the bundled official schemas.

The schemas live in the ``schemas`` data directory and are loaded with
``importlib.resources``. ``$ref`` targets resolve through a local
``referencing.Registry`` built from those files; nothing is ever fetched.
"""

import json
from functools import lru_cache
from importlib import resources

from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

from sbom_validation.errors import InputProblem, UnsupportedFormat
from sbom_validation.formats.detect import CYCLONEDX, SPDX, FormatInfo

# @need-ids: REQ_OFFLINE_001, REQ_BSI11_FORMATS

MAX_ERRORS = 50

_SCHEMA_FILES = {
    (CYCLONEDX, "1.4"): "bom-1.4.schema.json",
    (CYCLONEDX, "1.5"): "bom-1.5.schema.json",
    (CYCLONEDX, "1.6"): "bom-1.6.schema.json",
    (CYCLONEDX, "1.7"): "bom-1.7.schema.json",
    (SPDX, "2.3"): "spdx-schema-2.3.json",
}
_SUPPORT_FILES = (
    "spdx.schema.json",
    "jsf-0.82.schema.json",
    "cryptography-defs.schema.json",
)


def _load(name: str) -> dict:
    text = (resources.files(__package__) / "schemas" / name).read_text(
        encoding="utf-8"
    )
    return json.loads(text)


@lru_cache(maxsize=1)
def _registry() -> Registry:
    registry = Registry()
    names = set(_SCHEMA_FILES.values()) | set(_SUPPORT_FILES)
    for name in sorted(names):
        schema = _load(name)
        resource = Resource.from_contents(schema, default_specification=DRAFT7)
        # Register under the schema's own $id (http URI); relative refs such
        # as "spdx.schema.json" resolve against it.
        registry = registry.with_resource(schema["$id"], resource)
    return registry


@lru_cache(maxsize=None)
def _validator(key: tuple[str, str]) -> Draft7Validator:
    schema = _load(_SCHEMA_FILES[key])
    return Draft7Validator(schema, registry=_registry())


def _path(error) -> str:
    parts = "/".join(str(p) for p in error.absolute_path)
    return "/" + parts if parts else "/"


def validate_schema(data: dict, info: FormatInfo) -> None:
    """Validate ``data`` against the bundled schema for ``info``.

    Raises UnsupportedFormat when no schema is bundled for that version, and
    InputProblem listing every schema error (capped) with its JSON path.
    """
    key = (info.format, info.version)
    if key not in _SCHEMA_FILES:
        raise UnsupportedFormat(
            f"No bundled schema for {info.format} {info.version}; "
            "schema validation is not available for this version."
        )
    errors = sorted(
        _validator(key).iter_errors(data),
        key=lambda e: (_path(e), e.message),
    )
    if not errors:
        return
    lines = [
        f"{info.format} {info.version} schema validation failed "
        f"({len(errors)} error{'s' if len(errors) != 1 else ''}):"
    ]
    lines += [f"  {_path(e)}: {e.message}" for e in errors[:MAX_ERRORS]]
    if len(errors) > MAX_ERRORS:
        lines.append(f"  ... and {len(errors) - MAX_ERRORS} more")
    raise InputProblem("\n".join(lines))
