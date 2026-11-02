"""Registry of the supported standards and their versions."""

from sbom_validation.errors import UsageProblem
from sbom_validation.standards import bsi_tr_03183_2
from sbom_validation.standards.base import Rule, RuleSet

__all__ = ["Rule", "RuleSet", "get_rule_set", "supported"]

_REGISTRY: dict[str, dict[str, RuleSet]] = {
    bsi_tr_03183_2.STANDARD: bsi_tr_03183_2.VERSIONS,
}


def supported() -> dict[str, tuple[str, ...]]:
    """Standard name -> its supported versions."""
    return {standard: tuple(versions) for standard, versions in _REGISTRY.items()}


def get_rule_set(standard: str, version: str) -> RuleSet:
    """The rule set for ``standard`` and ``version``; UsageProblem if unknown."""
    rule_set = _REGISTRY.get(standard, {}).get(version)
    if rule_set is None:
        combos = ", ".join(
            f"{name} {v}" for name, versions in supported().items() for v in versions
        )
        raise UsageProblem(
            f"Unsupported standard and version: {standard} {version}. "
            f"Supported: {combos}. To request support for another standard or "
            "version, open an issue in the sbom-validation project."
        )
    return rule_set
