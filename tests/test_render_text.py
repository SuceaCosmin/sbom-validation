"""Console and JSON renderers."""

import json
import re
from pathlib import Path

from bsi_samples import CDX, CDX_SAMPLE, at, raw
from sbom_validation.engine import run
from sbom_validation.render.console import render_console
from sbom_validation.render.json_report import render_json
from sbom_validation.results import Finding, Report, RequirementResult, Status

STD, VER = "bsi-tr-03183-2", "1.1"


def _row(status, n=1, findings=()):
    return RequirementResult(
        f"REQ_X_{n}", f"Title {n}", f"5.{n}", status, "things", tuple(findings)
    )


def _report(*rows, problem=None):
    return Report(STD, VER, "x/sbom.json", "CycloneDX", "1.6", tuple(rows), problem)


def _gap_report(tmp_path: Path) -> Report:
    gap = raw(CDX)
    at(("metadata", "timestamp"))(gap)
    path = tmp_path / "gap.json"
    path.write_text(json.dumps(gap), encoding="utf-8")
    return run(path, STD, VER)


def _all_reports(tmp_path):
    clean = tmp_path / "clean.json"  # sample file name itself contains the word
    clean.write_bytes(CDX_SAMPLE.read_bytes())
    return [
        run(clean, STD, VER),
        _gap_report(tmp_path),
        _report(problem="bad schema\n  at /components: not an array"),
        _report(_row(Status.NOT_EVALUATED), _row(Status.NOT_VERIFIABLE, 2)),
    ]


def test_console_lists_failed_rows_and_counts(tmp_path):
    report = _gap_report(tmp_path)
    out = render_console(report)
    counts = report.counts()
    failed = [r for r in report.results if r.status is Status.FAILED]
    assert failed
    assert STD in out and VER in out and "CycloneDX" in out and report.sbom_path in out
    assert (
        f"{counts[Status.PASSED]} passed, {counts[Status.FAILED]} failed, "
        f"{counts[Status.NOT_VERIFIABLE]} not verifiable, "
        f"{counts[Status.NOT_EVALUATED]} not evaluated"
    ) in out
    for r in failed:
        assert r.id in out and r.title in out and r.section in out
        for f in r.findings:
            assert f.message in out
    passed = next(r for r in report.results if r.status is Status.PASSED)
    assert passed.id not in out
    assert out.endswith("\n") and not out.endswith("\n\n")
    out.encode("ascii")


def test_console_never_says_compliant(tmp_path):
    for report in _all_reports(tmp_path):
        out = render_console(report).lower()
        assert "compliant" not in out
        assert "complies" not in out


def test_console_notes_manual_review_for_not_verifiable():
    out = render_console(
        _report(_row(Status.NOT_VERIFIABLE), _row(Status.NOT_VERIFIABLE, 2))
    )
    assert (
        "2 requirement(s) cannot be verified automatically and need manual review."
        in out
    )
    assert "REQ_X_1" not in out
    assert "manual review" not in render_console(_report(_row(Status.PASSED)))


def test_console_caps_findings_per_requirement():
    findings = [Finding(f"c{i}", f"msg{i}") for i in range(25)]
    out = render_console(_report(_row(Status.FAILED, findings=findings)))
    assert "msg9" in out and "msg10" not in out
    assert "... and 15 more (see JSON/HTML report)" in out


def test_json_round_trips_all_results(tmp_path):
    report = _gap_report(tmp_path)
    data = json.loads(render_json(report))
    assert list(data) == [
        "schema_version",
        "tool",
        "standard",
        "version",
        "sbom",
        "counts",
        "results",
        "problem",
    ]
    assert data["schema_version"] == "1"
    assert data["tool"]["name"] == "sbom-validation" and data["tool"]["version"]
    assert data["sbom"] == {
        "path": report.sbom_path,
        "format": report.sbom_format,
        "format_version": report.sbom_format_version,
    }
    assert data["problem"] is None
    assert len(data["results"]) == len(report.results)
    for item, r in zip(data["results"], report.results):
        assert item["id"] == r.id and item["title"] == r.title
        assert item["section"] == r.section and item["examined"] == r.examined
        assert item["status"] == r.status.value.lower()
        assert item["findings"] == [
            {"component_ref": f.component_ref, "message": f.message}
            for f in r.findings
        ]


def test_json_has_no_findings_cap():
    findings = [Finding(None, f"m{i}") for i in range(25)]
    data = json.loads(render_json(_report(_row(Status.FAILED, findings=findings))))
    assert len(data["results"][0]["findings"]) == 25


def test_json_is_utf8_safe():
    out = render_json(
        _report(_row(Status.FAILED, findings=[Finding("c", "café")]))
    )
    assert "café" in out
    out.encode("utf-8")


def test_json_and_console_agree_on_counts(tmp_path):
    for report in _all_reports(tmp_path):
        if report.problem:
            continue
        j = json.loads(render_json(report))["counts"]
        m = re.search(
            r"(\d+) passed, (\d+) failed, (\d+) not verifiable, (\d+) not evaluated",
            render_console(report),
        )
        assert m
        assert [j["passed"], j["failed"], j["not_verifiable"], j["not_evaluated"]] == [
            int(g) for g in m.groups()
        ]


def test_problem_report_shows_schema_error_details():
    report = _report(problem="schema error\n  at /components: not an array")
    out = render_console(report)
    assert "Input problem" in out
    assert "schema error" in out and "at /components: not an array" in out
    assert "passed" not in out
    assert json.loads(render_json(report))["problem"] == report.problem
