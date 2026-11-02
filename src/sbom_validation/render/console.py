"""Plain-ASCII console report for CI logs."""

import re

from sbom_validation.results import Report, Status

# @need-ids: REQ_REPORT_001, REQ_SEVERITY_001

MAX_FINDINGS = 10


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_READABLE = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _ascii(text: str) -> str:
    """Show non-ASCII characters as escapes so legacy consoles never fail."""
    return text.encode("ascii", "backslashreplace").decode("ascii")


def _safe(text: str) -> str:
    """One printable ASCII line: control characters (CR, LF, ESC, DEL, C1 ...)
    and non-ASCII characters from the SBOM are shown as escapes, so SBOM
    content can never inject log lines or terminal sequences."""
    escaped = _CONTROL.sub(
        lambda m: _READABLE.get(m.group(0), "\\x%02x" % ord(m.group(0))), text
    )
    return _ascii(escaped)


def render_console(report: Report) -> str:
    """Render a short summary: header, counts, failed rows with findings."""
    lines = [
        f"SBOM validation: {_safe(report.standard)} {_safe(report.version)}",
        f"SBOM: {_safe(report.sbom_path)}",
        f"Format: {_safe(report.sbom_format or 'unknown')} "
        f"{_safe(report.sbom_format_version or '')}".rstrip(),
        "",
    ]
    if report.problem is not None:
        lines.append("Input problem")
        lines.append("-------------")
        lines.extend(_safe(line) for line in report.problem.splitlines())
        return _ascii("\n".join(lines) + "\n")

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
        lines.append(f"FAILED {_safe(result.id)}: {_safe(result.title)} "
            f"(section {_safe(result.section)})")
        for finding in result.findings[:MAX_FINDINGS]:
            where = f"[{_safe(finding.component_ref)}] " if finding.component_ref else ""
            lines.append(f"  - {where}{_safe(finding.message)}")
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
    return _ascii("\n".join(lines) + "\n")
