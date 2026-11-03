"""End-to-end checks of the built executable (``python scripts/build_exe.py``).

Skipped when no executable exists. Point ``SBOM_VALIDATION_EXE`` at another
build to test it instead of ``dist/sbom-validation[.exe]``.
"""

import copy
import json
import os
import subprocess
from pathlib import Path

import pytest

from sbom_validation.cli import main as cli_main

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "tests" / "samples"
EXE = Path(
    os.environ.get("SBOM_VALIDATION_EXE")
    or ROOT / "dist" / ("sbom-validation.exe" if os.name == "nt" else "sbom-validation")
)
STANDARD = ["--standard", "bsi-tr-03183-2", "--standard-version", "1.1"]

pytestmark = pytest.mark.skipif(not EXE.exists(), reason=f"executable not built: {EXE}")


def _load(rel: str) -> dict:
    return json.loads((SAMPLES / rel).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def sboms(tmp_path_factory) -> dict[str, Path]:
    folder = tmp_path_factory.mktemp("sboms")
    cdx, spdx = _load("cyclonedx/compliant_1_5.json"), _load("spdx2/compliant_2_3.json")

    bad_cdx = copy.deepcopy(cdx)
    bad_cdx["metadata"].pop("timestamp")
    for comp in bad_cdx["components"]:
        for key in ("licenses", "hashes", "supplier"):
            comp.pop(key, None)
    bad_spdx = copy.deepcopy(spdx)
    for pkg in bad_spdx["packages"]:
        for key in ("licenseConcluded", "licenseDeclared", "checksums", "supplier", "originator"):
            pkg.pop(key, None)
    invalid = copy.deepcopy(cdx)
    invalid["components"][0]["type"] = "bogus-type"
    old = copy.deepcopy(cdx)
    old["specVersion"] = "1.3"

    files = {
        "cdx_ok": cdx, "spdx_ok": spdx, "cdx_bad": bad_cdx, "spdx_bad": bad_spdx,
        "schema_invalid": invalid, "old_cdx": old, "unknown_format": {"hello": "world"},
    }
    paths = {}
    for name, doc in files.items():
        paths[name] = folder / f"{name}.json"
        paths[name].write_text(json.dumps(doc), encoding="utf-8")
    paths["not_json"] = folder / "not_json.json"
    paths["not_json"].write_text("{ not json", encoding="utf-8")
    paths["missing"] = folder / "missing.json"
    return paths


def _exe(*args) -> subprocess.CompletedProcess:
    return subprocess.run([str(EXE), *map(str, args)], capture_output=True, text=True, timeout=120)


@pytest.mark.parametrize(
    ("name", "code"),
    [
        ("cdx_ok", 0), ("spdx_ok", 0),
        ("cdx_bad", 1), ("spdx_bad", 1), ("old_cdx", 1),
        ("schema_invalid", 2), ("not_json", 2), ("missing", 2), ("unknown_format", 2),
    ],
)
def test_exit_code(sboms, name, code):
    assert _exe(sboms[name], *STANDARD).returncode == code


def test_help_and_usage_errors(sboms):
    assert _exe("--help").returncode == 0
    assert _exe().returncode == 3
    assert _exe(sboms["cdx_ok"], "--standard", "nope", "--standard-version", "1").returncode == 3
    assert _exe(sboms["cdx_ok"], *STANDARD, "--json", sboms["cdx_ok"].parent / "no" / "x.json").returncode == 3


@pytest.mark.parametrize("name", ["cdx_ok", "cdx_bad", "spdx_ok", "spdx_bad"])
def test_reports_match_in_process_run(sboms, tmp_path, capsys, name):
    exe_json, exe_html = tmp_path / "exe.json", tmp_path / "exe.html"
    result = _exe(sboms[name], *STANDARD, "--json", exe_json, "--html", exe_html)
    assert exe_html.read_text(encoding="utf-8").lstrip().lower().startswith("<!doctype html")

    py_json = tmp_path / "py.json"
    assert cli_main([str(sboms[name]), *STANDARD, "--json", str(py_json)]) == result.returncode
    capsys.readouterr()
    from_exe, from_py = (json.loads(p.read_text(encoding="utf-8")) for p in (exe_json, py_json))
    assert from_exe["results"] == from_py["results"]
    assert from_exe["counts"] == from_py["counts"]


def test_reported_tool_version_is_known(sboms, tmp_path):
    out = tmp_path / "r.json"
    _exe(sboms["cdx_ok"], *STANDARD, "--json", out)
    assert json.loads(out.read_text(encoding="utf-8"))["tool"]["version"] != "unknown"
