"""Rule and rule-set types shared by every standard version."""

from dataclasses import dataclass
from typing import Callable

from sbom_validation.formats.detect import FormatInfo
from sbom_validation.model import Sbom
from sbom_validation.results import RequirementResult, Status

# @need-ids: REQ_TRACE_001

NOT_DECIDABLE = "cannot be decided from the SBOM alone; needs manual review"


@dataclass(frozen=True)
class Rule:
    """One requirement of a standard version.

    ``check=None`` means the rule is always NOT_VERIFIABLE; ``examined`` is
    then the description of the elements shown to the reviewer.
    """

    id: str
    title: str
    section: str
    check: Callable[[Sbom], RequirementResult] | None
    examined: str = ""

    def evaluate(self, sbom: Sbom) -> RequirementResult:
        """Run the check, or give the NOT_VERIFIABLE row when there is none."""
        if self.check is None:
            return RequirementResult(
                id=self.id,
                title=self.title,
                section=self.section,
                status=Status.NOT_VERIFIABLE,
                examined=self.examined or NOT_DECIDABLE,
            )
        return self.check(sbom)


@dataclass(frozen=True)
class RuleSet:
    """A self-contained standard version: accepted formats and its rules."""

    standard: str
    version: str
    accepts: Callable[[FormatInfo], bool]
    rules: tuple[Rule, ...]
