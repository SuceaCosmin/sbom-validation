"""Result model and exit codes."""

from dataclasses import dataclass
from enum import Enum, IntEnum


class Status(str, Enum):
    """Outcome of evaluating one requirement."""

    PASSED = "PASSED"
    FAILED = "FAILED"
    NOT_VERIFIABLE = "NOT_VERIFIABLE"
    NOT_EVALUATED = "NOT_EVALUATED"


@dataclass(frozen=True)
class Finding:
    """A single observation about a component or the SBOM."""

    component_ref: str | None
    message: str


@dataclass(frozen=True)
class RequirementResult:
    """Result of one requirement check."""

    id: str
    title: str
    section: str
    status: Status
    examined: str
    findings: tuple[Finding, ...] = ()


@dataclass(frozen=True)
class Report:
    """Complete validation report for one SBOM."""

    standard: str
    version: str
    sbom_path: str
    sbom_format: str | None
    sbom_format_version: str | None
    results: tuple[RequirementResult, ...]
    problem: str | None = None

    def counts(self) -> dict[Status, int]:
        """Return the number of results per status, zero when absent."""
        counts = {status: 0 for status in Status}
        for result in self.results:
            counts[result.status] += 1
        return counts


# @need-ids: REQ_CLI_001
class ExitCode(IntEnum):
    """Process exit codes."""

    OK = 0
    NON_COMPLIANT = 1
    INPUT_PROBLEM = 2
    USAGE = 3
    INTERNAL = 4


# @need-ids: REQ_CLI_001
def exit_code_for(report: Report) -> ExitCode:
    """Map a report to its exit code."""
    if report.problem is not None:
        return ExitCode.INPUT_PROBLEM
    # @need-ids: REQ_SEVERITY_001
    # Only FAILED affects the exit code; NOT_VERIFIABLE and NOT_EVALUATED never do.
    if any(r.status is Status.FAILED for r in report.results):
        return ExitCode.NON_COMPLIANT
    return ExitCode.OK
