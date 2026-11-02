from sbom_validation.results import (
    ExitCode,
    Finding,
    Report,
    RequirementResult,
    Status,
    exit_code_for,
)


def _result(status: Status, rid: str = "R1") -> RequirementResult:
    return RequirementResult(
        id=rid, title="t", section="1", status=status, examined="x"
    )


def _report(*statuses: Status, problem: str | None = None) -> Report:
    return Report(
        standard="BSI TR-03183-2",
        version="1.1",
        sbom_path="sbom.json",
        sbom_format="CycloneDX",
        sbom_format_version="1.6",
        results=tuple(_result(s, f"R{i}") for i, s in enumerate(statuses)),
        problem=problem,
    )


def test_not_verifiable_never_changes_exit_code() -> None:
    report = _report(Status.PASSED, Status.NOT_VERIFIABLE, Status.NOT_EVALUATED)
    assert exit_code_for(report) == ExitCode.OK


def test_any_failed_is_non_compliant() -> None:
    report = _report(Status.PASSED, Status.FAILED, Status.NOT_VERIFIABLE)
    assert exit_code_for(report) == ExitCode.NON_COMPLIANT


def test_problem_report_is_input_problem() -> None:
    report = _report(Status.FAILED, problem="cannot parse")
    assert exit_code_for(report) == ExitCode.INPUT_PROBLEM


def test_counts_cover_all_statuses() -> None:
    counts = _report(Status.PASSED, Status.PASSED, Status.FAILED).counts()
    assert counts == {
        Status.PASSED: 2,
        Status.FAILED: 1,
        Status.NOT_VERIFIABLE: 0,
        Status.NOT_EVALUATED: 0,
    }


def test_exit_code_values_and_finding_default() -> None:
    assert [int(c) for c in ExitCode] == [0, 1, 2, 3, 4]
    assert Finding(None, "m").component_ref is None
