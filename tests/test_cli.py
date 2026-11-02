"""Command-line interface: exit codes, outputs and offline behaviour."""

import json
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from bsi_samples import CDX, CDX_SAMPLE, SPDX_SAMPLE, at, raw
from sbom_validation.cli import main
from sbom_validation.results import ExitCode

STD = ["--standard", "bsi-tr-03183-2", "--standard-version", "1.1"]


def _write(tmp_path: Path, data: dict, name: str = "sbom.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _gap(tmp_path: Path) -> Path:
    data = raw(CDX)
    # "name" is schema-required (that would be exit 2); a missing hashes entry
    # is schema-valid but a BSI gap.
    at(("components", 1, "hashes"))(data)
    return _write(tmp_path, data, "gap.json")


def test_compliant_returns_0(capsys):
    assert main([str(CDX_SAMPLE), *STD]) == ExitCode.OK
    assert capsys.readouterr().out.strip()


def test_single_gap_returns_1(tmp_path, capsys):
    assert main([str(_gap(tmp_path)), *STD]) == ExitCode.NON_COMPLIANT
    assert "FAILED" in capsys.readouterr().out


def test_schema_invalid_returns_2(tmp_path):
    path = _write(tmp_path, {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": 3})
    assert main([str(path), *STD]) == ExitCode.INPUT_PROBLEM


def test_missing_file_returns_2(tmp_path):
    assert main([str(tmp_path / "nope.json"), *STD]) == ExitCode.INPUT_PROBLEM


def test_unknown_version_returns_3_and_lists_supported(capsys):
    argv = [str(CDX_SAMPLE), "--standard", "bsi-tr-03183-2", "--standard-version", "9.9"]
    assert main(argv) == ExitCode.USAGE
    err = capsys.readouterr().err
    assert "bsi-tr-03183-2 1.1" in err
    assert len(err.strip().splitlines()) == 1


def test_spdx3_returns_3(tmp_path, capsys):
    path = _write(
        tmp_path,
        {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": []},
    )
    assert main([str(path), *STD]) == ExitCode.USAGE
    err = capsys.readouterr().err
    assert "SPDX" in err and len(err.strip().splitlines()) == 1


@pytest.mark.parametrize("option", ["--json", "--html"])
def test_unwritable_output_dir_returns_3(tmp_path, capsys, option):
    out = tmp_path / "missing" / "report.out"
    assert main([str(CDX_SAMPLE), *STD, option, str(out)]) == ExitCode.USAGE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert len(captured.err.strip().splitlines()) == 1
    assert not out.parent.exists()


def test_path_with_spaces_and_unicode(tmp_path, capsys):
    folder = tmp_path / "my sboms ünï cødé 日本"
    folder.mkdir()
    sbom = folder / "sbom ü.json"
    shutil.copy(CDX_SAMPLE, sbom)
    json_out, html_out = folder / "r ü.json", folder / "r ü.html"
    argv = [str(sbom), *STD, "--json", str(json_out), "--html", str(html_out)]
    assert main(argv) == ExitCode.OK
    assert json.loads(json_out.read_text(encoding="utf-8"))
    assert "<html" in html_out.read_text(encoding="utf-8")
    capsys.readouterr()


@pytest.mark.parametrize("sample", [CDX_SAMPLE, SPDX_SAMPLE])
def test_all_three_outputs_in_one_run(tmp_path, capsys, sample):
    json_out, html_out = tmp_path / "r.json", tmp_path / "r.html"
    argv = [str(sample), *STD, "--json", str(json_out), "--html", str(html_out)]
    assert main(argv) == ExitCode.OK
    assert capsys.readouterr().out.strip()
    assert json.loads(json_out.read_text(encoding="utf-8"))
    assert html_out.read_text(encoding="utf-8").lstrip().lower().startswith("<!doctype html")
    assert b"\r\n" not in json_out.read_bytes()


def test_reports_written_for_non_compliant_and_input_problem(tmp_path, capsys):
    out = tmp_path / "r.json"
    assert main([str(_gap(tmp_path)), *STD, "--json", str(out)]) == 1
    assert out.exists()
    out2 = tmp_path / "r2.json"
    assert main([str(tmp_path / "nope.json"), *STD, "--json", str(out2)]) == 2
    assert json.loads(out2.read_text(encoding="utf-8"))
    capsys.readouterr()


def test_write_failure_keeps_console_summary(tmp_path, capsys):
    target = tmp_path / "isdir"
    target.mkdir()
    assert main([str(CDX_SAMPLE), *STD, "--json", str(target)]) == ExitCode.USAGE
    captured = capsys.readouterr()
    assert captured.out.strip()
    assert len(captured.err.strip().splitlines()) == 1


def test_internal_error_returns_4(monkeypatch, capsys):
    def boom(*_args):
        raise RuntimeError("kaboom")

    monkeypatch.setattr("sbom_validation.cli.run", boom)
    assert main([str(CDX_SAMPLE), *STD]) == ExitCode.INTERNAL
    err = capsys.readouterr().err
    assert err.strip() == "internal error: RuntimeError: kaboom"


def test_no_network(monkeypatch, tmp_path, capsys):
    def no_socket(*_args, **_kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", no_socket)
    for sample in (CDX_SAMPLE, SPDX_SAMPLE):
        out = tmp_path / f"{sample.stem}.html"
        assert main([str(sample), *STD, "--html", str(out)]) == ExitCode.OK
    capsys.readouterr()


def test_bad_arguments_return_3_not_2(capsys):
    assert main([]) == ExitCode.USAGE
    assert main([str(CDX_SAMPLE)]) == ExitCode.USAGE
    assert main([str(CDX_SAMPLE), "--standard", "x"]) == ExitCode.USAGE
    assert main([str(CDX_SAMPLE), *STD, "--bogus"]) == ExitCode.USAGE
    err = capsys.readouterr().err
    assert "bsi-tr-03183-2 1.1" in err


def test_help_returns_0(capsys):
    assert main(["--help"]) == 0
    out = capsys.readouterr().out
    assert "--standard-version" in out and "bsi-tr-03183-2" in out


def _module(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "sbom_validation", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def test_python_dash_m_entry_point(tmp_path):
    ok = _module(str(CDX_SAMPLE), *STD)
    assert ok.returncode == 0 and ok.stdout.strip()
    bad = _module(str(_gap(tmp_path)), *STD)
    assert bad.returncode == 1
    usage = _module(str(CDX_SAMPLE))
    assert usage.returncode == 3
