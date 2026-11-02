"""BSI TR-03183-2 version 1.1 (English, 2023-11-28) as data.

One rule per ``REQ_BSI11_*`` need in docs/requirements.rst, in that order.
The element mapping is docs/mappings/bsi-tr-03183-2-v1.1.md; the format
loaders apply it, so the rules here see only the neutral ``Sbom`` model.
"""

from sbom_validation.checks import (
    is_cpe,
    is_email,
    is_purl,
    is_rfc3339,
    is_sha256,
    is_spdx_licence_expression,
    is_uri,
    is_url,
)
from sbom_validation.formats.detect import CYCLONEDX, SPDX, FormatInfo
from sbom_validation.model import Component, Party, Sbom
from sbom_validation.results import Finding, RequirementResult
from sbom_validation.standards._helpers import (
    component_rule,
    conditional_rule,
    not_verifiable,
    per_component,
    result,
    sbom_rule,
    version_tuple,
)
from sbom_validation.standards.base import Rule, RuleSet

STANDARD = "bsi-tr-03183-2"
VERSION = "1.1"

_MIN_CYCLONEDX = (1, 4)
_MIN_SPDX = (2, 3)


def accepts(info: FormatInfo) -> bool:
    """CycloneDX 1.4 or higher, or SPDX 2.x from 2.3 (numeric comparison)."""
    version = version_tuple(info.version)
    if version is None:
        return False
    if info.format == CYCLONEDX:
        return version >= _MIN_CYCLONEDX
    if info.format == SPDX:
        return version[0] == _MIN_SPDX[0] and version >= _MIN_SPDX
    return False


def _has_contact(parties: tuple[Party, ...]) -> bool:
    """Any party with a valid email, or else any party with a valid URL."""
    return any(p.email is not None and is_email(p.email) for p in parties) or any(
        p.url is not None and is_url(p.url) for p in parties
    )


def _present(value: str | None) -> bool:
    return value is not None and value.strip() != ""


def _timestamp_problem(sbom: Sbom) -> str | None:
    if not _present(sbom.timestamp):
        return "no SBOM timestamp"
    if not is_rfc3339(sbom.timestamp):
        return f"timestamp '{sbom.timestamp}' is not an RFC 3339 date-time"
    return None


def _licence_ok(c: Component) -> bool:
    return any(is_spdx_licence_expression(lic) for lic in c.licenses)


def _licence_message(c: Component) -> str:
    if not c.licenses:
        return "no licence"
    found = ", ".join(f"'{lic}'" for lic in c.licenses)
    return (
        "no SPDX licence identifier or expression, LicenseRef-scancode- or "
        f"LicenseRef-<entity>- identifier (found {found})"
    )


def _hash_ok(c: Component) -> bool:
    return c.sha256 is not None and is_sha256(c.sha256)


def _hash_message(c: Component) -> str:
    if c.sha256 is None:
        return "no SHA-256 hash"
    return f"SHA-256 hash '{c.sha256}' is not 64 hexadecimal characters"


def _identifier_ok(value: str) -> bool:
    return is_purl(value) or is_cpe(value)


def _malformed(what: str, form: str):
    return lambda value: f"{what} '{value}' is not a valid {form}"


# --- REQ_BSI11_FORMATS (section 4) -----------------------------------------

_FORMATS_TITLE = "SBOM format and version"
_FORMATS_EXAMINED = (
    "SBOM format and version: bomFormat/specVersion (CycloneDX) or "
    "spdxVersion (SPDX); accepted are CycloneDX 1.4 or higher and SPDX 2.3 "
    "or higher"
)


def _formats_row(info: FormatInfo) -> RequirementResult:
    findings = ()
    if not accepts(info):
        findings = (
            Finding(
                None,
                f"{info.format} {info.version} is not accepted; BSI TR-03183-2 "
                "v1.1 requires CycloneDX 1.4 or higher, or SPDX 2.3 or higher",
            ),
        )
    examined = f"{_FORMATS_EXAMINED} (found {info.format} {info.version})"
    return result("REQ_BSI11_FORMATS", _FORMATS_TITLE, "4", examined, findings)


def formats_failed_row(info: FormatInfo) -> RequirementResult:
    """The FAILED section 4 row for a format ``accepts`` rejected (for the
    engine, which then reports the other rules as not evaluated)."""
    row = _formats_row(info)
    if not row.findings:
        raise ValueError(f"{info.format} {info.version} is accepted")
    return row


def _formats_check(sbom: Sbom) -> RequirementResult:
    return _formats_row(FormatInfo(sbom.format, sbom.spec_version))


# --- The rule set -----------------------------------------------------------

RULES: tuple[Rule, ...] = (
    # @need-ids: REQ_BSI11_FORMATS
    Rule("REQ_BSI11_FORMATS", _FORMATS_TITLE, "4", _formats_check, _FORMATS_EXAMINED),
    # @need-ids: REQ_BSI11_DEPTH
    not_verifiable(
        "REQ_BSI11_DEPTH",
        "Recursive dependency resolution",
        "5.1",
        "dependency graph: dependencies[*] (CycloneDX) or DEPENDS_ON/"
        "DEPENDENCY_OF/CONTAINS relationships (SPDX); whether resolution "
        "reached the first component outside the scope of delivery needs "
        "manual review",
    ),
    # @need-ids: REQ_BSI11_BUILD
    not_verifiable(
        "REQ_BSI11_BUILD",
        "SBOM created in the build process",
        "5.1",
        "metadata.lifecycles and metadata.tools (CycloneDX) or "
        "creationInfo Tool: creators and comment (SPDX), as hints only; "
        "whether the SBOM was created in the build needs manual review",
    ),
    # @need-ids: REQ_BSI11_SBOM_CREATOR
    sbom_rule(
        "REQ_BSI11_SBOM_CREATOR",
        "SBOM creator",
        "5.2.1",
        "SBOM creator email, or URL where no email: metadata authors/"
        "manufacture/manufacturer/supplier (CycloneDX) or creationInfo "
        "Person:/Organization: creators (SPDX)",
        lambda sbom: None
        if _has_contact(sbom.creators)
        else "no SBOM creator with a valid email address or URL",
    ),
    # @need-ids: REQ_BSI11_TIMESTAMP
    sbom_rule(
        "REQ_BSI11_TIMESTAMP",
        "SBOM timestamp",
        "5.2.1",
        "SBOM timestamp as RFC 3339 date-time: metadata.timestamp (CycloneDX) "
        "or creationInfo.created (SPDX)",
        _timestamp_problem,
    ),
    # @need-ids: REQ_BSI11_CMP_CREATOR
    component_rule(
        "REQ_BSI11_CMP_CREATOR",
        "Component creator",
        "5.2.2",
        "component creator email, or URL where no email: authors/author/"
        "manufacturer/supplier/publisher/website reference (CycloneDX) or "
        "originator/supplier/homepage (SPDX), every component",
        lambda c: _has_contact(c.creators),
        "no creator with a valid email address or URL",
    ),
    # @need-ids: REQ_BSI11_CMP_NAME
    component_rule(
        "REQ_BSI11_CMP_NAME",
        "Component name",
        "5.2.2",
        "component name (CycloneDX) or package name (SPDX), every component",
        lambda c: _present(c.name),
        "no name",
    ),
    # @need-ids: REQ_BSI11_CMP_VERSION
    component_rule(
        "REQ_BSI11_CMP_VERSION",
        "Component version",
        "5.2.2",
        "component version (CycloneDX) or package versionInfo (SPDX), every "
        "component; the versioning scheme is not reported",
        lambda c: _present(c.version),
        "no version",
    ),
    # @need-ids: REQ_BSI11_CMP_DEPS
    component_rule(
        "REQ_BSI11_CMP_DEPS",
        "Component dependencies",
        "5.2.2",
        "recorded direct dependencies: dependencies[*] entry for the "
        "component's bom-ref (CycloneDX) or DEPENDS_ON/DEPENDENCY_OF "
        "relationships (SPDX: judged document-wide), every component; "
        "completeness is not "
        "verifiable and needs manual review",
        lambda c: c.dependencies is not None,
        "no dependency data recorded for this component",
    ),
    # @need-ids: REQ_BSI11_CMP_LICENCE
    component_rule(
        "REQ_BSI11_CMP_LICENCE",
        "Component licence",
        "5.2.2",
        "licence form: licenses[*].license.id/name/expression (CycloneDX) or "
        "licenseDeclared/licenseConcluded (SPDX), every component; whether "
        "the licence is correct is not verifiable and needs manual review",
        _licence_ok,
        _licence_message,
    ),
    # @need-ids: REQ_BSI11_CMP_HASH
    component_rule(
        "REQ_BSI11_CMP_HASH",
        "Hash of the executable component",
        "5.2.2",
        "SHA-256 hash: hashes[*] with alg SHA-256 (CycloneDX) or "
        "checksums[*] with algorithm SHA256 (SPDX), every component",
        _hash_ok,
        _hash_message,
    ),
    # @need-ids: REQ_BSI11_SBOM_URI
    conditional_rule(
        "REQ_BSI11_SBOM_URI",
        "SBOM URI",
        "5.3.1",
        "SBOM URI form when present: serialNumber or bom external reference "
        "(CycloneDX) or documentNamespace (SPDX)",
        lambda sbom: () if sbom.uri is None else ((None, sbom.uri),),
        is_uri,
        _malformed("SBOM URI", "URI"),
    ),
    # @need-ids: REQ_BSI11_SRC_URI
    conditional_rule(
        "REQ_BSI11_SRC_URI",
        "Source code URI",
        "5.3.2",
        "source code URI form when present: vcs external reference "
        "(CycloneDX) or VCS downloadLocation (SPDX), every component",
        per_component(lambda c: (c.source_uri,)),
        is_uri,
        _malformed("source code URI", "URI"),
    ),
    # @need-ids: REQ_BSI11_EXE_URI
    conditional_rule(
        "REQ_BSI11_EXE_URI",
        "URI of the executable form",
        "5.3.2",
        "executable URI form when present: distribution/distribution-intake "
        "external reference (CycloneDX) or non-VCS downloadLocation (SPDX), "
        "every component",
        per_component(lambda c: (c.executable_uri,)),
        is_uri,
        _malformed("executable URI", "URI"),
    ),
    # @need-ids: REQ_BSI11_SRC_HASH
    conditional_rule(
        "REQ_BSI11_SRC_HASH",
        "SHA-256 of the source code",
        "5.3.2",
        "source code SHA-256 form when present: SHA-256 hash on a vcs or "
        "source-distribution external reference (CycloneDX); not "
        "distinguishable in SPDX 2.x, every component",
        per_component(lambda c: (c.source_sha256,)),
        is_sha256,
        _malformed("source code SHA-256", "64-character hexadecimal hash"),
    ),
    # @need-ids: REQ_BSI11_OTHER_IDS
    conditional_rule(
        "REQ_BSI11_OTHER_IDS",
        "Other unique identifiers",
        "5.3.2",
        "CPE and purl form when present: cpe/purl (CycloneDX) or SECURITY "
        "cpe22Type/cpe23Type and PACKAGE-MANAGER purl externalRefs (SPDX), "
        "every component",
        per_component(lambda c: c.identifiers),
        _identifier_ok,
        _malformed("identifier", "CPE or purl"),
    ),
    # @need-ids: REQ_BSI11_ONE_PER_VERSION
    not_verifiable(
        "REQ_BSI11_ONE_PER_VERSION",
        "One SBOM per software version",
        "3.1",
        "document version and metadata.component.version (CycloneDX) or "
        "documentNamespace and primary package versionInfo (SPDX); whether "
        "each software version has its own SBOM needs manual review",
    ),
    # @need-ids: REQ_BSI11_COMPONENT_EXEC
    not_verifiable(
        "REQ_BSI11_COMPONENT_EXEC",
        "Component is a single executable file",
        "3.2",
        "components[*].type (CycloneDX) or packages[*].primaryPackagePurpose "
        "(SPDX); whether each component is a single executable file needs "
        "manual review",
    ),
)

RULE_SET = RuleSet(
    standard=STANDARD,
    version=VERSION,
    accepts=accepts,
    rejected_format_row=formats_failed_row,
    rules=RULES,
)
