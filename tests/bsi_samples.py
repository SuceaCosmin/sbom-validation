"""Compliant samples with one gap applied, as neutral SBOMs (no conftest).

``cdx(mutate)`` / ``spdx(mutate)`` parse a fresh copy of the compliant sample,
apply ``mutate`` to the raw JSON dict and convert it with the format loader.
``at(path, value)`` builds a mutator that sets (or, without ``value``, deletes)
the element at a JSON path of keys and list indices.
"""

import json
from dataclasses import replace
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

from sbom_validation.formats import cyclonedx, spdx2
from sbom_validation.model import Sbom

SAMPLES = Path(__file__).parent / "samples"
CDX_SAMPLE = SAMPLES / "cyclonedx" / "compliant_1_5.json"
SPDX_SAMPLE = SAMPLES / "spdx2" / "compliant_2_3.json"

CDX = "cdx"
SPDX = "spdx"
FORMATS = (CDX, SPDX)

# Component refs in the compliant samples, per format.
APP = {CDX: "pkg:generic/acme-app@1.0.0", SPDX: "SPDXRef-Package-acme-app"}
REQUESTS = {CDX: "pkg:pypi/requests@2.31.0", SPDX: "SPDXRef-Package-requests"}
URLLIB3 = {CDX: "pkg:pypi/urllib3@2.0.7", SPDX: "SPDXRef-Package-urllib3"}
IDNA = {CDX: "pkg:pypi/idna@3.4", SPDX: "SPDXRef-Package-idna"}

Mutator = Callable[[dict], None]
_DELETE = object()


@lru_cache(maxsize=None)
def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def raw(fmt: str) -> dict:
    """A fresh, independent copy of the compliant sample's JSON."""
    return json.loads(_text(CDX_SAMPLE if fmt == CDX else SPDX_SAMPLE))


def at(path: tuple, value: Any = _DELETE) -> Mutator:
    """Mutator setting ``path`` to ``value``, or deleting it if no value."""

    def mutate(data: dict) -> None:
        node = data
        for step in path[:-1]:
            node = node[step]
        if value is _DELETE:
            del node[path[-1]]
        else:
            node[path[-1]] = value

    return mutate


def both(*mutators: Mutator) -> Mutator:
    """Apply several mutators in order (one gap that touches two fields)."""

    def mutate(data: dict) -> None:
        for m in mutators:
            m(data)

    return mutate


def cdx(mutate: Mutator | None = None) -> Sbom:
    data = raw(CDX)
    if mutate:
        mutate(data)
    return cyclonedx.to_model(data)


def spdx(mutate: Mutator | None = None) -> Sbom:
    data = raw(SPDX)
    if mutate:
        mutate(data)
    return spdx2.to_model(data)


def load(fmt: str, mutate: Mutator | None = None) -> Sbom:
    return cdx(mutate) if fmt == CDX else spdx(mutate)


def replace_component(sbom: Sbom, ref: str, **changes: Any) -> Sbom:
    """The SBOM with one component's fields changed at model level."""
    assert any(c.ref == ref for c in sbom.components), ref
    return replace(
        sbom,
        components=tuple(
            replace(c, **changes) if c.ref == ref else c for c in sbom.components
        ),
    )
