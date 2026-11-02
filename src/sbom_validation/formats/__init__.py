"""SBOM format loaders: read, detect, schema-validate and convert."""

import json
from pathlib import Path

from sbom_validation.errors import InputProblem
from sbom_validation.formats import cyclonedx, spdx2
from sbom_validation.formats.detect import CYCLONEDX, FormatInfo, detect_format
from sbom_validation.formats.schemas import validate_schema
from sbom_validation.model import Sbom

# @need-ids: REQ_BSI11_FORMATS

__all__ = [
    "FormatInfo",
    "detect_format",
    "load_sbom",
    "read_json",
    "to_sbom",
    "validate_schema",
]


def read_json(path: Path) -> dict:
    """Read a JSON object from ``path`` (UTF-8, with or without BOM)."""
    path = Path(path)
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        raise InputProblem(f"File not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise InputProblem(f"Invalid JSON in {path}: {exc}") from None
    except UnicodeDecodeError as exc:
        raise InputProblem(f"{path} is not valid UTF-8 text: {exc}") from None
    except OSError as exc:
        raise InputProblem(f"Cannot read {path}: {exc.strerror or exc}") from None
    if not isinstance(data, dict):
        raise InputProblem(f"{path}: the top-level JSON value must be an object.")
    return data


def to_sbom(data: dict, info: FormatInfo) -> Sbom:
    """Convert a parsed document of the detected format to the neutral model."""
    if info.format == CYCLONEDX:
        return cyclonedx.to_model(data)
    return spdx2.to_model(data)


def load_sbom(path: Path) -> tuple[Sbom, FormatInfo]:
    """Read, detect, schema-validate and convert the SBOM at ``path``."""
    data = read_json(path)
    info = detect_format(data)
    validate_schema(data, info)
    return to_sbom(data, info), info
