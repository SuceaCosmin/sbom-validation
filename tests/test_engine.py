"""Engine pipeline: rule-set resolution, loading, format gate, evaluation."""

import json
import time
from pathlib import Path

import pytest

from sbom_validation.engine import run
from sbom_validation.errors import UnsupportedFormat, UsageProblem
from sbom_validation.results import ExitCode, Status, exit_code_for
from sbom_validation.standards import get_rule_set
from bsi_samples import CDX, CDX_SAMPLE, SPDX_SAMPLE, at, raw

STD, VER = "bsi-tr-03183-2", "1.1"


def _write(tmp_path: Path, data: dict, name: str = "sbom.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _cdx_1_3(tmp_path: Path) -> Path:
    data = raw(CDX)
    data["specVersion"] = "1.3"
    return _write(tmp_path, data)


# @need-ids: REQ_FMT_001
@pytest.mark.parametrize("sample", [CDX_SAMPLE, SPDX_SAMPLE])
def test_compliant_sample_has_no_failed_rows(sample):
    report = run(sample, STD, VER)
    assert report.problem is None
    assert report.results
    assert report.counts()[Status.FAILED] == 0
    assert report.sbom_path == str(sample)


def test_schema_invalid_gives_problem_and_no_results(tmp_path):
    data = raw(CDX)
    data["components"] = "not-a-list"
    report = run(_write(tmp_path, data), STD, VER)
    assert report.problem
    assert report.results == ()
    assert (report.sbom_format, report.sbom_format_version) == ("CycloneDX", "1.5")


def test_unreadable_file_gives_problem(tmp_path):
    report = run(tmp_path / "missing.json", STD, VER)
    assert report.problem
    assert report.results == ()
    assert report.sbom_format is None and report.sbom_format_version is None


def test_cyclonedx_1_3_fails_formats_and_skips_others(tmp_path):
    report = run(_cdx_1_3(tmp_path), STD, VER)
    assert report.problem is None
    assert (report.sbom_format, report.sbom_format_version) == ("CycloneDX", "1.3")
    first, *rest = report.results
    assert first.id == "REQ_BSI11_FORMATS"
    assert first.status is Status.FAILED
    assert rest
    for row in rest:
        assert row.status is Status.NOT_EVALUATED
        assert row.findings == ()


def test_spdx3_raises_unsupported_format(tmp_path):
    path = _write(
        tmp_path, {"@context": "https://spdx.org/rdf/3.0.0/spdx-context.jsonld"}
    )
    with pytest.raises(UnsupportedFormat):
        run(path, STD, VER)


def test_unknown_version_raises_usage_problem():
    with pytest.raises(UsageProblem):
        run(CDX_SAMPLE, STD, "9.9")


@pytest.mark.parametrize("sample", [CDX_SAMPLE, SPDX_SAMPLE])
def test_results_follow_rule_set_order(sample, tmp_path):
    expected = [rule.id for rule in get_rule_set(STD, VER).rules]
    assert [r.id for r in run(sample, STD, VER).results] == expected
    skipped = run(_cdx_1_3(tmp_path), STD, VER)
    assert [r.id for r in skipped.results] == expected


def test_large_sbom_runs_quickly(tmp_path):
    data = raw(CDX)
    data["components"] = [
        {
            "type": "library",
            "bom-ref": f"pkg:generic/c{i}@1.0",
            "name": f"c{i}",
            "version": "1.0",
        }
        for i in range(20_000)
    ]
    path = _write(tmp_path, data)
    start = time.perf_counter()
    report = run(path, STD, VER)
    assert time.perf_counter() - start < 10
    assert report.problem is None
    assert report.results


def test_exit_codes_via_exit_code_for(tmp_path):
    assert exit_code_for(run(CDX_SAMPLE, STD, VER)) is ExitCode.OK
    gap = raw(CDX)
    at(("metadata", "timestamp"))(gap)
    report = run(_write(tmp_path, gap, "gap.json"), STD, VER)
    assert exit_code_for(report) is ExitCode.NON_COMPLIANT
    bad = raw(CDX)
    bad["components"] = 5
    report = run(_write(tmp_path, bad, "bad.json"), STD, VER)
    assert exit_code_for(report) is ExitCode.INPUT_PROBLEM
    assert exit_code_for(run(_cdx_1_3(tmp_path), STD, VER)) is ExitCode.NON_COMPLIANT
