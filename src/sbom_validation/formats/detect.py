"""Recognise the SBOM format and version of a parsed JSON document."""

import re
from dataclasses import dataclass

from sbom_validation.errors import InputProblem, UnsupportedFormat

# @need-ids: REQ_BSI11_FORMATS

CYCLONEDX = "CycloneDX"
SPDX = "SPDX"

# Newest version for which a schema is bundled (see formats/schemas/README.md).
NEWEST_CYCLONEDX = (1, 7)
NEWEST_SPDX2 = (2, 3)

_VERSION = re.compile(r"^(\d+)\.(\d+)$")
_SPDX_VERSION = re.compile(r"^SPDX-(\d+)\.(\d+)$")


@dataclass(frozen=True)
class FormatInfo:
    """Format name ("CycloneDX" or "SPDX") and bare version ("1.5", "2.3")."""

    format: str
    version: str


def _tuple(match: re.Match) -> tuple[int, int]:
    return int(match.group(1)), int(match.group(2))


def _is_spdx3(data: dict) -> bool:
    context = data.get("@context")
    if isinstance(context, str) and "spdx.org" in context:
        return True
    if isinstance(context, list) and any(
        isinstance(c, str) and "spdx.org" in c for c in context
    ):
        return True
    version = data.get("spdxVersion")
    return isinstance(version, str) and version.startswith("SPDX-3")


def detect_format(data: dict) -> FormatInfo:
    """Return the format of ``data``.

    Raises UnsupportedFormat for SPDX 3.x or a version newer than the newest
    bundled schema, and InputProblem when the document is neither format.
    """
    if _is_spdx3(data):
        raise UnsupportedFormat(
            "SPDX 3.x (JSON-LD) is not supported; only SPDX 2.x JSON is."
        )
    if data.get("bomFormat") == CYCLONEDX:
        spec = data.get("specVersion")
        match = _VERSION.match(spec) if isinstance(spec, str) else None
        if not match:
            raise InputProblem(
                "CycloneDX document has a missing or malformed 'specVersion'."
            )
        if _tuple(match) > NEWEST_CYCLONEDX:
            raise UnsupportedFormat(
                f"CycloneDX {spec} is newer than the newest supported "
                f"version ({NEWEST_CYCLONEDX[0]}.{NEWEST_CYCLONEDX[1]})."
            )
        return FormatInfo(CYCLONEDX, spec)
    spdx = data.get("spdxVersion")
    if isinstance(spdx, str):
        match = _SPDX_VERSION.match(spdx)
        if match and _tuple(match)[0] == 2:
            if _tuple(match) > NEWEST_SPDX2:
                raise UnsupportedFormat(
                    f"{spdx} is newer than the newest supported SPDX 2.x "
                    f"version ({NEWEST_SPDX2[0]}.{NEWEST_SPDX2[1]})."
                )
            return FormatInfo(SPDX, spdx.removeprefix("SPDX-"))
    raise InputProblem(
        "The document is neither a CycloneDX JSON BOM (bomFormat/specVersion) "
        "nor an SPDX 2.x JSON document (spdxVersion)."
    )
