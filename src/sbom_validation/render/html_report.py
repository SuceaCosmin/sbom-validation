"""Standalone HTML report: inline CSS/JS, no external references."""

from html import escape
from importlib import metadata

from sbom_validation.render._html_assets import CSS, JS
from sbom_validation.results import Report, RequirementResult, Status

# @need-ids: REQ_REPORT_001, REQ_SEVERITY_001

MAX_FINDINGS = 200

_LABELS = {
    Status.FAILED: "Failed",
    Status.NOT_VERIFIABLE: "Not verifiable",
    Status.NOT_EVALUATED: "Not evaluated",
    Status.PASSED: "Passed",
}
# Sort order of the Status column: failed first.
_RANK = {status: i for i, status in enumerate(_LABELS)}
_COLUMNS = ("Status", "Requirement ID", "Title", "Spec section", "Element(s) examined")


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _key(status: Status) -> str:
    return status.value.lower()


def _tool_version() -> str:
    try:
        return metadata.version("sbom-validation")
    except metadata.PackageNotFoundError:
        return "unknown"


def _details(result: RequirementResult) -> str:
    if not result.findings:
        return ""
    items = []
    for finding in result.findings[:MAX_FINDINGS]:
        where = (
            f"<code>{_e(finding.component_ref)}</code> "
            if finding.component_ref
            else ""
        )
        items.append(f"<li>{where}{_e(finding.message)}</li>")
    extra = len(result.findings) - MAX_FINDINGS
    more = f"<p>... and {extra} more (see JSON report)</p>" if extra > 0 else ""
    return (
        f"<details><summary>{len(result.findings)} finding(s)</summary>"
        f"<ul>{''.join(items)}</ul>{more}</details>"
    )


def _row(result: RequirementResult) -> str:
    return (
        f'<tr data-status="{_key(result.status)}">'
        f'<td class="status" data-rank="{_RANK[result.status]}">'
        f"{_LABELS[result.status]}</td>"
        f"<td>{_e(result.id)}</td><td>{_e(result.title)}</td>"
        f"<td>{_e(result.section)}</td><td>{_e(result.examined)}</td>"
        f"<td>{_details(result)}</td></tr>"
    )


def _table(report: Report) -> str:
    heads = "".join(
        f'<th scope="col" aria-sort="none"><button type="button">{c}</button></th>'
        for c in _COLUMNS
    )
    options = '<option value="all">All</option>' + "".join(
        f'<option value="{_key(s)}">{label}</option>' for s, label in _LABELS.items()
    )
    body = "".join(_row(r) for r in report.results)
    return (
        '<div class="controls">'
        f'<label>Status <select id="status-filter">{options}</select></label>'
        '<label>Search <input type="search" id="search" '
        'placeholder="id, title, finding"></label></div>'
        '<div class="tablewrap"><table>'
        f'<thead><tr>{heads}<th scope="col">Details</th></tr></thead>'
        f"<tbody>{body}</tbody></table></div>"
    )


def _summary(report: Report) -> str:
    counts = report.counts()
    order = (Status.PASSED, Status.FAILED, Status.NOT_VERIFIABLE, Status.NOT_EVALUATED)
    out = [
        '<ul class="counts">'
        + "".join(
            f'<li>{_LABELS[s]}: <strong data-count="{_key(s)}">{counts[s]}</strong></li>'
            for s in order
        )
        + "</ul>"
    ]
    manual = counts[Status.NOT_VERIFIABLE]
    if manual:
        out.append(
            f'<p class="note">{manual} requirement(s) cannot be verified '
            "automatically and need manual review.</p>"
        )
    return "".join(out)


def render_html(report: Report) -> str:
    """Render one self-contained HTML5 document (rows are static HTML)."""
    title = f"SBOM validation: {report.standard} {report.version}"
    fmt = (
        f"{report.sbom_format or 'unknown'} {report.sbom_format_version or ''}".strip()
    )
    parts = [
        f"<h1>{_e(title)}</h1>",
        '<dl class="meta">'
        f"<dt>SBOM</dt><dd>{_e(report.sbom_path)}</dd>"
        f"<dt>Format</dt><dd>{_e(fmt)}</dd>"
        f"<dt>Tool</dt><dd>sbom-validation {_e(_tool_version())}</dd></dl>",
    ]
    script = ""
    if report.problem is not None:
        parts.append(f"<h2>Input problem</h2><pre>{_e(report.problem)}</pre>")
    else:
        parts.append(_summary(report))
        parts.append(_table(report))
        script = f"<script>{JS}</script>"
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{_e(title)}</title><style>{CSS}</style></head>"
        f"<body><main>{''.join(parts)}</main>{script}</body></html>\n"
    )
