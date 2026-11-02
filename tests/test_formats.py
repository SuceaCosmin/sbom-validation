"""Tests for format detection, reading and offline schema validation."""

import copy
import json
import socket
import urllib.request
from pathlib import Path

import pytest

from sbom_validation.errors import InputProblem, UnsupportedFormat
from sbom_validation.formats import (
    detect_format,
    load_sbom,
    read_json,
    to_sbom,
    validate_schema,
)
from sbom_validation.formats import schemas
from sbom_validation.formats.detect import FormatInfo

SAMPLES = Path(__file__).parent / "samples"
CDX = SAMPLES / "cyclonedx" / "compliant_1_5.json"
SPDX = SAMPLES / "spdx2" / "compliant_2_3.json"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_detects_cyclonedx_and_spdx2():
    assert detect_format(load(CDX)) == FormatInfo("CycloneDX", "1.5")
    assert detect_format(load(SPDX)) == FormatInfo("SPDX", "2.3")
    assert detect_format({"bomFormat": "CycloneDX", "specVersion": "1.3"}) == FormatInfo(
        "CycloneDX", "1.3"
    )
    assert detect_format({"spdxVersion": "SPDX-2.2"}) == FormatInfo("SPDX", "2.2")


def test_spdx3_is_unsupported_format():
    with pytest.raises(UnsupportedFormat):
        detect_format({"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"})
    with pytest.raises(UnsupportedFormat):
        detect_format({"spdxVersion": "SPDX-3.0"})


def test_newer_than_bundled_is_unsupported_format():
    with pytest.raises(UnsupportedFormat):
        detect_format({"bomFormat": "CycloneDX", "specVersion": "1.99"})
    with pytest.raises(UnsupportedFormat):
        detect_format({"spdxVersion": "SPDX-2.9"})


def test_unknown_document_is_input_problem():
    for doc in ({}, {"hello": "world"}, {"bomFormat": "Other", "specVersion": "1.5"},
                {"bomFormat": "CycloneDX"}, {"spdxVersion": "nonsense"}):
        with pytest.raises(InputProblem):
            detect_format(doc)


def test_utf8_bom_file_loads(tmp_path):
    path = tmp_path / "bom.json"
    path.write_bytes(b"\xef\xbb\xbf" + CDX.read_bytes())
    sbom, info = load_sbom(path)
    assert info == FormatInfo("CycloneDX", "1.5")
    assert sbom.format == "CycloneDX"
    assert sbom.spec_version == "1.5"


def test_load_sbom_both_samples():
    sbom, info = load_sbom(SPDX)
    assert (info.format, info.version) == ("SPDX", "2.3")
    assert sbom.format == "SPDX" and sbom.spec_version == "2.3"
    assert to_sbom(load(CDX), FormatInfo("CycloneDX", "1.5")).format == "CycloneDX"


def test_missing_file_is_input_problem(tmp_path):
    with pytest.raises(InputProblem):
        read_json(tmp_path / "nope.json")


def test_unreadable_path_is_input_problem(tmp_path):
    with pytest.raises(InputProblem):
        read_json(tmp_path)  # a directory


def test_invalid_json_is_input_problem(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(InputProblem):
        read_json(path)


def test_non_object_top_level_is_input_problem(tmp_path):
    path = tmp_path / "list.json"
    path.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(InputProblem):
        read_json(path)


def test_schema_failure_lists_paths():
    data = load(CDX)
    data["components"][0]["type"] = "not-a-type"
    data["metadata"]["timestamp"] = 12
    with pytest.raises(InputProblem) as exc:
        validate_schema(data, FormatInfo("CycloneDX", "1.5"))
    msg = exc.value.message
    assert "components/0/type" in msg
    assert "metadata/timestamp" in msg

    spdx = load(SPDX)
    del spdx["name"]
    with pytest.raises(InputProblem) as exc:
        validate_schema(spdx, FormatInfo("SPDX", "2.3"))
    assert "name" in exc.value.message


def test_schema_failure_message_is_capped():
    data = load(CDX)
    data["components"] = [{"type": "bad"} for _ in range(120)]
    with pytest.raises(InputProblem) as exc:
        validate_schema(data, FormatInfo("CycloneDX", "1.5"))
    assert "more" in exc.value.message


def test_validate_schema_without_bundled_schema_is_unsupported():
    with pytest.raises(UnsupportedFormat):
        validate_schema({}, FormatInfo("CycloneDX", "1.3"))
    with pytest.raises(UnsupportedFormat):
        validate_schema({}, FormatInfo("SPDX", "2.2"))


@pytest.mark.parametrize("version", ["1.4", "1.5", "1.6", "1.7"])
def test_all_bundled_cyclonedx_schemas_resolve(version):
    data = {"bomFormat": "CycloneDX", "specVersion": version, "version": 1}
    validate_schema(data, FormatInfo("CycloneDX", version))
    bad = copy.deepcopy(data)
    bad["version"] = "x"
    with pytest.raises(InputProblem):
        validate_schema(bad, FormatInfo("CycloneDX", version))


def test_all_samples_are_schema_valid():
    paths = sorted(SAMPLES.rglob("*.json"))
    assert len(paths) >= 2
    for path in paths:
        data = read_json(path)
        info = detect_format(data)
        validate_schema(data, info)


def test_validation_makes_no_network_call(monkeypatch):
    # Cold start: drop cached registry and validators so $ref resolution
    # itself is proven to be offline.
    schemas._registry.cache_clear()
    schemas._validator.cache_clear()

    def no_urlopen(*args, **kwargs):
        raise AssertionError("urlopen attempted")

    monkeypatch.setattr(urllib.request, "urlopen", no_urlopen)
    def boom(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", boom)
    for path in (CDX, SPDX):
        data = read_json(path)
        validate_schema(data, detect_format(data))
