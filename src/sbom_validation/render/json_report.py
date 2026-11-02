"""JSON report."""

import json
from importlib import metadata

from sbom_validation.results import Report, Status

# @need-ids: REQ_REPORT_001, REQ_SEVERITY_001


def _tool_version() -> str:
    try:
        return metadata.version("sbom-validation")
    except metadata.PackageNotFoundError:
        return "unknown"


def _key(status: Status) -> str:
    return status.value.lower()


def render_json(report: Report) -> str:
    """Render the full report (all findings, no cap) as indented JSON."""
    counts = report.counts()
    document = {
        "schema_version": "1",
        "tool": {"name": "sbom-validation", "version": _tool_version()},
        "standard": report.standard,
        "version": report.version,
        "sbom": {
            "path": report.sbom_path,
            "format": report.sbom_format,
            "format_version": report.sbom_format_version,
        },
        "counts": {_key(status): counts[status] for status in Status},
        "results": [
            {
                "id": r.id,
                "title": r.title,
                "section": r.section,
                "status": _key(r.status),
                "examined": r.examined,
                "findings": [
                    {"component_ref": f.component_ref, "message": f.message}
                    for f in r.findings
                ],
            }
            for r in report.results
        ],
        "problem": report.problem,
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"
