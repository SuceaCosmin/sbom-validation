"""The engine works for any registered rule set (goal G8)."""

import inspect

import pytest

from bsi_samples import CDX_SAMPLE, SPDX_SAMPLE
from sbom_validation import engine, standards
from sbom_validation.formats.detect import SPDX, FormatInfo
from sbom_validation.results import Finding, RequirementResult, Status
from sbom_validation.standards.base import Rule, RuleSet


def _row(status, findings=()):
    return lambda sbom: RequirementResult(
        "STUB_PLAIN", "Plain", "2", status, "stuff", tuple(findings)
    )


def _rejected(info: FormatInfo) -> RequirementResult:
    return RequirementResult(
        "STUB_FMT",
        "Stub format",
        "1",
        Status.FAILED,
        "format",
        (Finding(None, f"{info.format} {info.version} not wanted by stub"),),
    )


STUB = RuleSet(
    standard="stub-std",
    version="9",
    accepts=lambda info: info.format == SPDX,
    rejected_format_row=_rejected,
    rules=(
        Rule(
            "STUB_FMT",
            "Stub format",
            "1",
            lambda s: RequirementResult("STUB_FMT", "Stub format", "1", Status.PASSED, "format"),
        ),
        Rule("STUB_PLAIN", "Plain", "2", _row(Status.PASSED)),
        Rule("STUB_MANUAL", "Manual", "3", None, "manual things"),
    ),
)


@pytest.fixture(autouse=True)
def _register_stub(monkeypatch):
    monkeypatch.setitem(standards._REGISTRY, "stub-std", {"9": STUB})


def test_rejected_format_uses_stub_row_and_not_evaluated_for_others():
    report = engine.run(CDX_SAMPLE, "stub-std", "9")
    assert report.problem is None
    by_id = {r.id: r for r in report.results}
    assert list(by_id) == ["STUB_FMT", "STUB_PLAIN", "STUB_MANUAL"]
    assert by_id["STUB_FMT"].status is Status.FAILED
    assert "not wanted by stub" in by_id["STUB_FMT"].findings[0].message
    assert by_id["STUB_PLAIN"].status is Status.NOT_EVALUATED
    assert by_id["STUB_MANUAL"].status is Status.NOT_EVALUATED
    assert by_id["STUB_MANUAL"].examined == "manual things"


def test_accepted_format_runs_stub_rules():
    report = engine.run(SPDX_SAMPLE, "stub-std", "9")
    statuses = {r.id: r.status for r in report.results}
    assert statuses == {
        "STUB_FMT": Status.PASSED,
        "STUB_PLAIN": Status.PASSED,
        "STUB_MANUAL": Status.NOT_VERIFIABLE,
    }


def test_engine_does_not_import_a_standard_module():
    imports = [
        line for line in inspect.getsource(engine).splitlines()
        if line.startswith(("import ", "from "))
    ]
    assert not [line for line in imports if "bsi" in line.lower()]
    assert not hasattr(engine, "formats_failed_row")
