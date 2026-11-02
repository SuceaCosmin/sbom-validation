"""Plain-ASCII console report for CI logs."""

from sbom_validation.results import Report, Status

# @need-ids: REQ_REPORT_001, REQ_SEVERITY_001

MAX_FINDINGS = 10


def render_console(report: Report) -> str:
    """Render a short summary: header, counts, failed rows with findings."""
    lines = [
        f"SBOM validation: {report.standard} {report.version}",
        f"SBOM: {report.sbom_path}",
        f"Format: {report.sbom_format or 'unknown'} "
        f"{report.sbom_format_version or ''}".rstrip(),
        "",
    ]
    if report.problem is not None:
        lines.append("Input problem")
        lines.append("-------------")
        lines.extend(report.problem.splitlines())
        return "\n".join(lines) + "\n"

    counts = report.counts()
    lines.append(
        f"{counts[Status.PASSED]} passed, {counts[Status.FAILED]} failed, "
        f"{counts[Status.NOT_VERIFIABLE]} not verifiable, "
        f"{counts[Status.NOT_EVALUATED]} not evaluated"
    )
    for result in report.results:
        if result.status is not Status.FAILED:
            continue
        lines.append("")
        lines.append(f"FAILED {result.id}: {result.title} (section {result.section})")
        for finding in result.findings[:MAX_FINDINGS]:
            where = f"[{finding.component_ref}] " if finding.component_ref else ""
            lines.append(f"  - {where}{finding.message}")
        extra = len(result.findings) - MAX_FINDINGS
        if extra > 0:
            lines.append(f"  ... and {extra} more (see JSON/HTML report)")
    manual = counts[Status.NOT_VERIFIABLE]
    if manual:
        lines.append("")
        lines.append(
            f"{manual} requirement(s) cannot be verified automatically "
            "and need manual review."
        )
    return "\n".join(lines) + "\n"
