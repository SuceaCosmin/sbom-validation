"""Regression tests from the final review: bounded messages, linear parsing,
deep nesting."""

import json
import time

import pytest

from sbom_validation.cli import main
from sbom_validation.engine import run
from sbom_validation.errors import InputProblem
from sbom_validation.formats import FormatInfo, read_json, validate_schema
from sbom_validation.formats import cyclonedx, spdx2
from sbom_validation.results import ExitCode

STD, VER = "bsi-tr-03183-2", "1.1"


def _bare_cdx() -> dict:
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}


# --- bounded schema error messages ------------------------------------------


def test_unique_items_message_names_indices_and_stays_small():
    data = _bare_cdx()
    comps = [{"type": "library", "name": f"c{i}", "version": "1"} for i in range(10000)]
    comps.append(dict(comps[7]))
    data["components"] = comps
    with pytest.raises(InputProblem) as exc:
        validate_schema(data, FormatInfo("CycloneDX", "1.6"))
    text = str(exc.value)
    assert "items 7 and 10000 are identical" in text
    assert len(text) < 5000


def test_enum_message_is_truncated():
    data = _bare_cdx()
    data["components"] = [{"type": "x" * 5000, "name": "a", "version": "1"}]
    with pytest.raises(InputProblem) as exc:
        validate_schema(data, FormatInfo("CycloneDX", "1.6"))
    text = str(exc.value)
    assert "..." in text
    assert len(text) < 2000


def test_oneof_message_is_truncated():
    data = _bare_cdx()
    data["components"] = [
        {
            "type": "library",
            "name": "a",
            "version": "1",
            "licenses": [
                {
                    "license": {"id": "y" * 5000, "name": "z" * 5000},
                    "expression": "e" * 5000,
                }
            ],
        }
    ]
    with pytest.raises(InputProblem) as exc:
        validate_schema(data, FormatInfo("CycloneDX", "1.6"))
    text = str(exc.value)
    assert "..." in text
    assert len(text) < 3000


# --- linear e-mail extraction -----------------------------------------------


def test_long_author_without_at_is_linear():
    text = "a" * 1_000_000
    start = time.perf_counter()
    parties = cyclonedx._free_text_party(text)
    assert time.perf_counter() - start < 2
    assert parties[0].email is None


def test_long_dotted_author_without_at_is_linear():
    text = "a." * 500_000
    start = time.perf_counter()
    cyclonedx._free_text_party(text)
    assert time.perf_counter() - start < 2


def test_email_trailing_dot_is_stripped():
    parties = cyclonedx._free_text_party("Acme Dev <dev@example.com>.")
    assert parties[0].email == "dev@example.com"
    parties = cyclonedx._free_text_party("mail dev@example.com.")
    assert parties[0].email == "dev@example.com"


def test_long_spdx_actor_is_linear():
    for text in ("Person: a" + " " * 200_000 + "b", "Person: " + "a (" * 100_000):
        start = time.perf_counter()
        spdx2._actor(text)
        assert time.perf_counter() - start < 2


# --- deep nesting -----------------------------------------------------------


def test_read_json_deep_nesting_is_input_problem(tmp_path):
    path = tmp_path / "deep.json"
    path.write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    with pytest.raises(InputProblem, match="nested too deeply"):
        read_json(path)


def test_engine_and_cli_deep_nesting_exit_2(tmp_path, capsys):
    path = tmp_path / "deep.json"
    path.write_text('{"a":' + "[" * 100_000 + "]" * 100_000 + "}", encoding="utf-8")
    report = run(path, STD, VER)
    assert "nested too deeply" in report.problem
    code = main([str(path), "--standard", STD, "--standard-version", VER])
    assert code == ExitCode.INPUT_PROBLEM


def test_schema_deep_nesting_is_input_problem(tmp_path):
    comp = {"type": "library", "name": "leaf"}
    for _ in range(250):
        comp = {"type": "library", "name": "n", "components": [comp]}
    data = _bare_cdx()
    data["components"] = [comp]
    with pytest.raises(InputProblem, match="nested too deeply"):
        validate_schema(data, FormatInfo("CycloneDX", "1.6"))
    path = tmp_path / "nested.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    code = main([str(path), "--standard", STD, "--standard-version", VER])
    assert code == ExitCode.INPUT_PROBLEM
