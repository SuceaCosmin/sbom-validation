"""Validation engine: one SBOM file against one standard version."""

from pathlib import Path

from sbom_validation.errors import InputProblem
from sbom_validation.formats import detect_format, read_json, to_sbom, validate_schema
from sbom_validation.formats.detect import FormatInfo
from sbom_validation.results import Report, RequirementResult, Status
from sbom_validation.standards import get_rule_set
from sbom_validation.standards.bsi_tr_03183_2.v1_1 import formats_failed_row

# @need-ids: REQ_OFFLINE_001, REQ_BSI11_FORMATS

_FORMATS_ID = "REQ_BSI11_FORMATS"


def run(path: Path, standard: str, version: str) -> Report:
    """Validate the SBOM at ``path`` against ``standard`` ``version``.

    UsageProblem (unknown standard or version) and UnsupportedFormat
    propagate; unreadable or schema-invalid input becomes ``Report.problem``.
    """
    rule_set = get_rule_set(standard, version)

    def report(info: FormatInfo | None, results=(), problem=None) -> Report:
        return Report(
            standard=standard,
            version=version,
            sbom_path=str(path),
            sbom_format=info.format if info else None,
            sbom_format_version=info.version if info else None,
            results=tuple(results),
            problem=problem,
        )

    try:
        data = read_json(path)
        info = detect_format(data)
    except InputProblem as exc:
        return report(None, problem=str(exc))

    if not rule_set.accepts(info):
        return report(
            info,
            (
                formats_failed_row(info)
                if rule.id == _FORMATS_ID
                else RequirementResult(
                    rule.id,
                    rule.title,
                    rule.section,
                    Status.NOT_EVALUATED,
                    rule.examined,
                )
                for rule in rule_set.rules
            ),
        )

    try:
        validate_schema(data, info)
    except InputProblem as exc:
        return report(info, problem=str(exc))
    sbom = to_sbom(data, info)
    return report(info, (rule.evaluate(sbom) for rule in rule_set.rules))
