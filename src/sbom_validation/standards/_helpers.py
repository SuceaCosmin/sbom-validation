"""Builders that turn small predicates into rules.

Each builder returns a ``Rule`` whose check is a pure function of the SBOM
and builds its findings in a single pass over the components.
"""

import re
from typing import Callable, Iterable

from sbom_validation.model import Component, Sbom
from sbom_validation.results import Finding, RequirementResult, Status
from sbom_validation.standards.base import Rule

NO_COMPONENTS = "SBOM contains no components"

_VERSION = re.compile(r"(\d+)\.(\d+)")

Message = str | Callable[[Component], str]
Values = Callable[[Sbom], Iterable[tuple[str | None, str]]]


def version_tuple(text: str) -> tuple[int, int] | None:
    """``"1.10"`` -> ``(1, 10)``; None when not a bare ``major.minor``."""
    match = _VERSION.fullmatch(text) if isinstance(text, str) else None
    return (int(match.group(1)), int(match.group(2))) if match else None


def result(
    rule_id: str, title: str, section: str, examined: str, findings: Iterable[Finding]
) -> RequirementResult:
    """FAILED when there is any finding, otherwise PASSED."""
    findings = tuple(findings)
    return RequirementResult(
        id=rule_id,
        title=title,
        section=section,
        status=Status.FAILED if findings else Status.PASSED,
        examined=examined,
        findings=findings,
    )


def sbom_rule(
    rule_id: str,
    title: str,
    section: str,
    examined: str,
    problem: Callable[[Sbom], str | None],
) -> Rule:
    """Rule on the SBOM itself; ``problem`` returns what is wrong, or None."""

    def check(sbom: Sbom) -> RequirementResult:
        message = problem(sbom)
        findings = () if message is None else (Finding(None, message),)
        return result(rule_id, title, section, examined, findings)

    return Rule(rule_id, title, section, check, examined)


def component_rule(
    rule_id: str,
    title: str,
    section: str,
    examined: str,
    predicate: Callable[[Component], bool],
    message: Message,
) -> Rule:
    """Required per-component rule: fails for each component not satisfying
    ``predicate``, and fails outright when the SBOM has no components."""
    describe = message if callable(message) else (lambda _c: message)

    def check(sbom: Sbom) -> RequirementResult:
        if not sbom.components:
            findings: Iterable[Finding] = (Finding(None, NO_COMPONENTS),)
        else:
            findings = (
                Finding(c.ref, describe(c)) for c in sbom.components if not predicate(c)
            )
        return result(rule_id, title, section, examined, findings)

    return Rule(rule_id, title, section, check, examined)


def conditional_rule(
    rule_id: str,
    title: str,
    section: str,
    examined: str,
    values: Values,
    valid: Callable[[str], bool],
    message: Callable[[str], str],
) -> Rule:
    """Conditional rule: only present values are checked for form.

    ``values`` yields ``(component_ref or None, value)`` for each present
    value. Absence is not an error; ``examined`` then notes "none present".
    """

    def check(sbom: Sbom) -> RequirementResult:
        present = 0
        findings: list[Finding] = []
        for ref, value in values(sbom):
            present += 1
            if not valid(value):
                findings.append(Finding(ref, message(value)))
        note = f"{examined}; none present" if present == 0 else (
            f"{examined}; {present} present"
        )
        return result(rule_id, title, section, note, findings)

    return Rule(rule_id, title, section, check, examined)


def per_component(
    get: Callable[[Component], Iterable[str | None]],
) -> Values:
    """Values function yielding each component's present (non-None) values."""

    def values(sbom: Sbom) -> Iterable[tuple[str | None, str]]:
        for component in sbom.components:
            for value in get(component):
                if value is not None:
                    yield component.ref, value

    return values


def not_verifiable(rule_id: str, title: str, section: str, examined: str) -> Rule:
    """Rule that is always NOT_VERIFIABLE (``check=None``)."""
    return Rule(rule_id, title, section, None, examined)
