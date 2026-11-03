"""Tests for the rule framework and the BSI TR-03183-2 v1.1 rule set."""

import re
import time
from dataclasses import replace
from pathlib import Path

import pytest

from bsi_samples import (
    APP,
    CDX,
    FORMATS,
    IDNA,
    REQUESTS,
    SPDX,
    URLLIB3,
    at,
    both,
    cdx,
    load,
    replace_component,
    spdx,
)
from sbom_validation.errors import UsageProblem
from sbom_validation.formats.detect import FormatInfo
from sbom_validation.model import Component, Party, Sbom
from sbom_validation.results import Finding, Status
from sbom_validation.standards import get_rule_set, supported
from sbom_validation.standards.base import Rule, RuleSet
from sbom_validation.standards.bsi_tr_03183_2 import v1_1
from sbom_validation.standards.bsi_tr_03183_2.v1_1 import RULE_SET, formats_failed_row

REQUIREMENTS = Path(__file__).parents[1] / "docs" / "requirements" / "bsi_tr_03183_2_v1_1.rst"

NOT_VERIFIABLE = {
    "REQ_BSI11_DEPTH",
    "REQ_BSI11_BUILD",
    "REQ_BSI11_ONE_PER_VERSION",
    "REQ_BSI11_COMPONENT_EXEC",
}
CONDITIONAL = {
    "REQ_BSI11_SBOM_URI",
    "REQ_BSI11_SRC_URI",
    "REQ_BSI11_EXE_URI",
    "REQ_BSI11_SRC_HASH",
    "REQ_BSI11_OTHER_IDS",
}
REQUIRED_COMPONENT = {
    "REQ_BSI11_CMP_CREATOR",
    "REQ_BSI11_CMP_NAME",
    "REQ_BSI11_CMP_VERSION",
    "REQ_BSI11_CMP_DEPS",
    "REQ_BSI11_CMP_LICENCE",
    "REQ_BSI11_CMP_HASH",
}

ALL_FOUR = lambda fmt: {r[fmt] for r in (APP, REQUESTS, URLLIB3, IDNA)}  # noqa: E731

# One gap per rule and format: (builder of the gapped SBOM, failing refs).
# CycloneDX sample: components[0] = requests (externalReferences[0] vcs,
# [1] distribution), components[0].components[0] = urllib3,
# components[1] = idna, dependencies[3] = idna's entry.
# SPDX sample: packages[0..3] = acme-app, requests, urllib3, idna.
GAPS = {
    "REQ_BSI11_FORMATS": {
        CDX: (lambda: cdx(at(("specVersion",), "1.3")), {None}),
        SPDX: (lambda: spdx(at(("spdxVersion",), "SPDX-2.2")), {None}),
    },
    "REQ_BSI11_SBOM_CREATOR": {
        CDX: (lambda: cdx(at(("metadata", "authors"))), {None}),
        SPDX: (
            lambda: spdx(
                at(("creationInfo", "creators"), ["Tool: example-sbom-generator-1.0"])
            ),
            {None},
        ),
    },
    "REQ_BSI11_TIMESTAMP": {
        CDX: (lambda: cdx(at(("metadata", "timestamp"))), {None}),
        SPDX: (lambda: spdx(at(("creationInfo", "created"))), {None}),
    },
    "REQ_BSI11_CMP_CREATOR": {
        CDX: (lambda: cdx(at(("components", 1, "author"))), {IDNA[CDX]}),
        SPDX: (lambda: spdx(at(("packages", 3, "originator"))), {IDNA[SPDX]}),
    },
    "REQ_BSI11_CMP_NAME": {
        CDX: (lambda: cdx(at(("components", 1, "name"))), {IDNA[CDX]}),
        SPDX: (lambda: spdx(at(("packages", 3, "name"))), {IDNA[SPDX]}),
    },
    "REQ_BSI11_CMP_VERSION": {
        CDX: (lambda: cdx(at(("components", 1, "version"))), {IDNA[CDX]}),
        SPDX: (lambda: spdx(at(("packages", 3, "versionInfo"))), {IDNA[SPDX]}),
    },
    "REQ_BSI11_CMP_DEPS": {
        CDX: (lambda: cdx(at(("dependencies", 3))), {IDNA[CDX]}),
        # SPDX states dependencies document-wide: the gap is "no dependency
        # relationships at all", which leaves every package without data.
        SPDX: (lambda: spdx(at(("relationships",), [])), ALL_FOUR(SPDX)),
    },
    "REQ_BSI11_CMP_LICENCE": {
        CDX: (lambda: cdx(at(("components", 1, "licenses"))), {IDNA[CDX]}),
        SPDX: (
            lambda: spdx(
                both(
                    at(("packages", 3, "licenseDeclared")),
                    at(("packages", 3, "licenseConcluded")),
                )
            ),
            {IDNA[SPDX]},
        ),
    },
    "REQ_BSI11_CMP_HASH": {
        CDX: (lambda: cdx(at(("components", 1, "hashes"))), {IDNA[CDX]}),
        SPDX: (lambda: spdx(at(("packages", 3, "checksums"))), {IDNA[SPDX]}),
    },
    "REQ_BSI11_SBOM_URI": {
        CDX: (lambda: cdx(at(("serialNumber",), "urn uuid 3e671687")), {None}),
        SPDX: (lambda: spdx(at(("documentNamespace",), "not a uri")), {None}),
    },
    "REQ_BSI11_SRC_URI": {
        CDX: (
            lambda: cdx(
                at(
                    ("components", 0, "externalReferences", 0, "url"),
                    "https://github.com/psf/ requests",
                )
            ),
            {REQUESTS[CDX]},
        ),
        SPDX: (
            lambda: spdx(
                at(
                    ("packages", 1, "downloadLocation"),
                    "git+https://github.com/psf/ requests",
                )
            ),
            {REQUESTS[SPDX]},
        ),
    },
    "REQ_BSI11_EXE_URI": {
        CDX: (
            lambda: cdx(
                at(
                    ("components", 0, "externalReferences", 1, "url"),
                    "files.pythonhosted.org/requests-2.31.0.tar.gz",
                )
            ),
            {REQUESTS[CDX]},
        ),
        SPDX: (
            lambda: spdx(
                at(
                    ("packages", 2, "downloadLocation"),
                    "files.pythonhosted.org/urllib3-2.0.7.tar.gz",
                )
            ),
            {URLLIB3[SPDX]},
        ),
    },
    "REQ_BSI11_SRC_HASH": {
        CDX: (
            lambda: cdx(
                at(
                    ("components", 0, "externalReferences", 0, "hashes", 0, "content"),
                    "1234",
                )
            ),
            {REQUESTS[CDX]},
        ),
        # The SPDX loader never fills source_sha256 (mapping open point 3),
        # so the gap is applied at model level.
        SPDX: (
            lambda: replace_component(spdx(), REQUESTS[SPDX], source_sha256="1234"),
            {REQUESTS[SPDX]},
        ),
    },
    "REQ_BSI11_OTHER_IDS": {
        CDX: (
            lambda: cdx(
                at(("components", 0, "components", 0, "cpe"), "cpe:2.3:a:broken")
            ),
            {URLLIB3[CDX]},
        ),
        SPDX: (
            lambda: spdx(
                at(
                    ("packages", 2, "externalRefs", 0, "referenceLocator"),
                    "cpe:2.3:a:broken",
                )
            ),
            {URLLIB3[SPDX]},
        ),
    },
}

parametrize_formats = pytest.mark.parametrize("fmt", FORMATS)


def evaluate(sbom: Sbom) -> dict:
    return {rule.id: rule.evaluate(sbom) for rule in RULE_SET.rules}


def _assert_passes_on_compliant(rule_id: str, fmt: str) -> None:
    result = evaluate(load(fmt))[rule_id]
    assert result.status is Status.PASSED, result
    assert result.findings == ()


def _assert_fails_on_single_gap(rule_id: str, fmt: str) -> None:
    build, failing_refs = GAPS[rule_id][fmt]
    results = evaluate(build())
    result = results[rule_id]
    assert result.status is Status.FAILED, result
    assert {f.component_ref for f in result.findings} == failing_refs
    assert len(result.findings) == len(failing_refs)
    assert all(f.message for f in result.findings)
    # Exactly one gap: no other rule fails on this sample.
    failed = {rid for rid, r in results.items() if r.status is Status.FAILED}
    assert failed == {rule_id}


# --- Compliant samples ----------------------------------------------------


@parametrize_formats
def test_compliant_samples_have_no_failed_rows(fmt):
    results = evaluate(load(fmt))
    for rule_id, result in results.items():
        expected = (
            Status.NOT_VERIFIABLE if rule_id in NOT_VERIFIABLE else Status.PASSED
        )
        assert result.status is expected, result


# --- One pair per machine-checkable rule ----------------------------------


# @need-ids: REQ_BSI11_FORMATS
@parametrize_formats
def test_formats_passes_on_compliant(fmt):
    _assert_passes_on_compliant("REQ_BSI11_FORMATS", fmt)


# @need-ids: REQ_BSI11_FORMATS
@parametrize_formats
def test_formats_fails_on_single_gap(fmt):
    _assert_fails_on_single_gap("REQ_BSI11_FORMATS", fmt)


# @need-ids: REQ_BSI11_SBOM_CREATOR
@parametrize_formats
def test_sbom_creator_passes_on_compliant(fmt):
    _assert_passes_on_compliant("REQ_BSI11_SBOM_CREATOR", fmt)


# @need-ids: REQ_BSI11_SBOM_CREATOR
@parametrize_formats
def test_sbom_creator_fails_on_single_gap(fmt):
    _assert_fails_on_single_gap("REQ_BSI11_SBOM_CREATOR", fmt)


# @need-ids: REQ_BSI11_TIMESTAMP
@parametrize_formats
def test_timestamp_passes_on_compliant(fmt):
    _assert_passes_on_compliant("REQ_BSI11_TIMESTAMP", fmt)


# @need-ids: REQ_BSI11_TIMESTAMP
@parametrize_formats
def test_timestamp_fails_on_single_gap(fmt):
    _assert_fails_on_single_gap("REQ_BSI11_TIMESTAMP", fmt)


# @need-ids: REQ_BSI11_CMP_CREATOR
@parametrize_formats
def test_cmp_creator_passes_on_compliant(fmt):
    _assert_passes_on_compliant("REQ_BSI11_CMP_CREATOR", fmt)


# @need-ids: REQ_BSI11_CMP_CREATOR
@parametrize_formats
def test_cmp_creator_fails_on_single_gap(fmt):
    _assert_fails_on_single_gap("REQ_BSI11_CMP_CREATOR", fmt)


# @need-ids: REQ_BSI11_CMP_NAME
@parametrize_formats
def test_cmp_name_passes_on_compliant(fmt):
    _assert_passes_on_compliant("REQ_BSI11_CMP_NAME", fmt)


# @need-ids: REQ_BSI11_CMP_NAME
@parametrize_formats
def test_cmp_name_fails_on_single_gap(fmt):
    _assert_fails_on_single_gap("REQ_BSI11_CMP_NAME", fmt)


# @need-ids: REQ_BSI11_CMP_VERSION
@parametrize_formats
def test_cmp_version_passes_on_compliant(fmt):
    _assert_passes_on_compliant("REQ_BSI11_CMP_VERSION", fmt)


# @need-ids: REQ_BSI11_CMP_VERSION
@parametrize_formats
def test_cmp_version_fails_on_single_gap(fmt):
    _assert_fails_on_single_gap("REQ_BSI11_CMP_VERSION", fmt)


# @need-ids: REQ_BSI11_CMP_DEPS
@parametrize_formats
def test_cmp_deps_passes_on_compliant(fmt):
    _assert_passes_on_compliant("REQ_BSI11_CMP_DEPS", fmt)


# @need-ids: REQ_BSI11_CMP_DEPS
@parametrize_formats
def test_cmp_deps_fails_on_single_gap(fmt):
    _assert_fails_on_single_gap("REQ_BSI11_CMP_DEPS", fmt)


# @need-ids: REQ_BSI11_CMP_LICENCE
@parametrize_formats
def test_cmp_licence_passes_on_compliant(fmt):
    _assert_passes_on_compliant("REQ_BSI11_CMP_LICENCE", fmt)


# @need-ids: REQ_BSI11_CMP_LICENCE
@parametrize_formats
def test_cmp_licence_fails_on_single_gap(fmt):
    _assert_fails_on_single_gap("REQ_BSI11_CMP_LICENCE", fmt)


# @need-ids: REQ_BSI11_CMP_HASH
@parametrize_formats
def test_cmp_hash_passes_on_compliant(fmt):
    _assert_passes_on_compliant("REQ_BSI11_CMP_HASH", fmt)


# @need-ids: REQ_BSI11_CMP_HASH
@parametrize_formats
def test_cmp_hash_fails_on_single_gap(fmt):
    _assert_fails_on_single_gap("REQ_BSI11_CMP_HASH", fmt)


# @need-ids: REQ_BSI11_SBOM_URI
@parametrize_formats
def test_sbom_uri_passes_on_compliant(fmt):
    _assert_passes_on_compliant("REQ_BSI11_SBOM_URI", fmt)


# @need-ids: REQ_BSI11_SBOM_URI
@parametrize_formats
def test_sbom_uri_fails_on_single_gap(fmt):
    _assert_fails_on_single_gap("REQ_BSI11_SBOM_URI", fmt)


# @need-ids: REQ_BSI11_SRC_URI
@parametrize_formats
def test_src_uri_passes_on_compliant(fmt):
    _assert_passes_on_compliant("REQ_BSI11_SRC_URI", fmt)


# @need-ids: REQ_BSI11_SRC_URI
@parametrize_formats
def test_src_uri_fails_on_single_gap(fmt):
    _assert_fails_on_single_gap("REQ_BSI11_SRC_URI", fmt)


# @need-ids: REQ_BSI11_EXE_URI
@parametrize_formats
def test_exe_uri_passes_on_compliant(fmt):
    _assert_passes_on_compliant("REQ_BSI11_EXE_URI", fmt)


# @need-ids: REQ_BSI11_EXE_URI
@parametrize_formats
def test_exe_uri_fails_on_single_gap(fmt):
    _assert_fails_on_single_gap("REQ_BSI11_EXE_URI", fmt)


# @need-ids: REQ_BSI11_SRC_HASH
@parametrize_formats
def test_src_hash_passes_on_compliant(fmt):
    _assert_passes_on_compliant("REQ_BSI11_SRC_HASH", fmt)


# @need-ids: REQ_BSI11_SRC_HASH
@parametrize_formats
def test_src_hash_fails_on_single_gap(fmt):
    _assert_fails_on_single_gap("REQ_BSI11_SRC_HASH", fmt)


# @need-ids: REQ_BSI11_OTHER_IDS
@parametrize_formats
def test_other_ids_passes_on_compliant(fmt):
    _assert_passes_on_compliant("REQ_BSI11_OTHER_IDS", fmt)


# @need-ids: REQ_BSI11_OTHER_IDS
@parametrize_formats
def test_other_ids_fails_on_single_gap(fmt):
    _assert_fails_on_single_gap("REQ_BSI11_OTHER_IDS", fmt)


def test_every_machine_checkable_rule_has_a_gap_for_both_formats():
    checkable = {r.id for r in RULE_SET.rules if r.check is not None}
    assert checkable == set(GAPS)
    assert all(set(GAPS[rid]) == set(FORMATS) for rid in GAPS)


# --- Named extras ----------------------------------------------------------


def _component(ref: str, **changes) -> Component:
    base = Component(
        ref=ref,
        name="lib",
        version="1.0",
        creators=(Party("Dev", "dev@example.com", None),),
        licenses=("MIT",),
        sha256="a" * 64,
        hashes=(("SHA-256", "a" * 64),),
        dependencies=(),
        source_uri=None,
        executable_uri=None,
        source_sha256=None,
        identifiers=(),
        is_primary=False,
    )
    return replace(base, **changes)


def _sbom(components: tuple[Component, ...], **changes) -> Sbom:
    base = Sbom(
        format="CycloneDX",
        spec_version="1.5",
        creators=(Party("Team", "sbom@example.com", None),),
        timestamp="2026-11-02T09:30:00Z",
        uri="urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
        components=components,
    )
    return replace(base, **changes)


def test_failing_components_are_listed():
    unnamed = {"c-7", "c-42", "c-99"}
    components = tuple(
        _component(f"c-{i}", name=None if f"c-{i}" in unnamed else f"lib{i}")
        for i in range(100)
    )
    results = [rule.evaluate(_sbom(components)) for rule in RULE_SET.rules]
    rows = [r for r in results if r.id == "REQ_BSI11_CMP_NAME"]
    assert len(rows) == 1
    assert rows[0].status is Status.FAILED
    assert len(rows[0].findings) == 3
    assert {f.component_ref for f in rows[0].findings} == unnamed
    assert [r.id for r in results if r.status is Status.FAILED] == [
        "REQ_BSI11_CMP_NAME"
    ]


EMPTY = {
    CDX: lambda: cdx(both(at(("metadata", "component")), at(("components",), []))),
    SPDX: lambda: spdx(at(("packages",), [])),
}


@parametrize_formats
def test_empty_components_is_not_a_vacuous_pass(fmt):
    sbom = EMPTY[fmt]()
    assert sbom.components == ()
    results = evaluate(sbom)
    for rule_id in REQUIRED_COMPONENT:
        result = results[rule_id]
        assert result.status is Status.FAILED, result
        assert result.findings == (Finding(None, "SBOM contains no components"),)
    for rule_id in CONDITIONAL - {"REQ_BSI11_SBOM_URI"}:
        assert results[rule_id].status is Status.PASSED
        assert "none present" in results[rule_id].examined


@parametrize_formats
def test_conditional_rules_pass_when_absent(fmt):
    def strip(c: Component) -> Component:
        return replace(
            c, source_uri=None, executable_uri=None, source_sha256=None, identifiers=()
        )

    sbom = load(fmt)
    sbom = replace(sbom, uri=None, components=tuple(strip(c) for c in sbom.components))
    results = evaluate(sbom)
    for rule_id in CONDITIONAL:
        assert results[rule_id].status is Status.PASSED, results[rule_id]
        assert "none present" in results[rule_id].examined
        assert results[rule_id].findings == ()


# @need-ids: REQ_BSI11_SBOM_URI
@parametrize_formats
def test_sbom_uri_absent_in_document_passes(fmt):
    sbom = cdx(at(("serialNumber",))) if fmt == CDX else spdx(at(("documentNamespace",)))
    assert sbom.uri is None
    result = evaluate(sbom)["REQ_BSI11_SBOM_URI"]
    assert result.status is Status.PASSED
    assert "none present" in result.examined


@parametrize_formats
def test_noassertion_licence_fails(fmt):
    if fmt == CDX:
        sbom = cdx(at(("components", 1, "licenses"), [{"license": {"name": "NOASSERTION"}}]))
    else:
        sbom = spdx(
            both(
                at(("packages", 3, "licenseDeclared"), "NOASSERTION"),
                at(("packages", 3, "licenseConcluded"), "NOASSERTION"),
            )
        )
    result = evaluate(sbom)["REQ_BSI11_CMP_LICENCE"]
    assert result.status is Status.FAILED
    assert [f.component_ref for f in result.findings] == [IDNA[fmt]]
    assert "NOASSERTION" in result.findings[0].message


def _point_dependencies_at_no_value(data: dict) -> None:
    """Keep the sample's relationships; point each dependency one at
    NONE / NOASSERTION, which the mapping does not accept as a statement."""
    deps = [
        r
        for r in data["relationships"]
        if r["relationshipType"] in ("DEPENDS_ON", "DEPENDENCY_OF")
    ]
    for i, rel in enumerate(deps):
        end = (
            "spdxElementId"
            if rel["relationshipType"] == "DEPENDENCY_OF"
            else "relatedSpdxElement"
        )
        rel[end] = ("NONE", "NOASSERTION")[i % 2]


# @need-ids: REQ_BSI11_CMP_DEPS
def test_cmp_deps_fails_when_only_no_value_endpoints():
    result = evaluate(spdx(_point_dependencies_at_no_value))["REQ_BSI11_CMP_DEPS"]
    assert result.status is Status.FAILED
    assert {f.component_ref for f in result.findings} == ALL_FOUR(SPDX)


def test_licence_alternatives_pass_if_any_one_holds():
    sbom = replace_component(spdx(), IDNA[SPDX], licenses=("NOASSERTION", "MIT"))
    assert evaluate(sbom)["REQ_BSI11_CMP_LICENCE"].status is Status.PASSED


def test_creator_alternatives_pass_if_any_one_holds():
    creators = (
        Party("No contact", None, None),
        Party("Bad email", "not-an-email", None),
        Party(None, None, "https://example.org/"),
    )
    sbom = replace_component(cdx(), IDNA[CDX], creators=creators)
    assert evaluate(sbom)["REQ_BSI11_CMP_CREATOR"].status is Status.PASSED
    sbom = replace_component(cdx(), IDNA[CDX], creators=creators[:2])
    assert evaluate(sbom)["REQ_BSI11_CMP_CREATOR"].status is Status.FAILED


@parametrize_formats
def test_uppercase_hash_passes(fmt):
    # Through the loader: the primary's sample hash is upper-case.
    assert evaluate(load(fmt))["REQ_BSI11_CMP_HASH"].status is Status.PASSED
    # At model level, independent of any loader normalisation.
    sbom = replace_component(load(fmt), IDNA[fmt], sha256="ABCDEF" + "0" * 58)
    assert evaluate(sbom)["REQ_BSI11_CMP_HASH"].status is Status.PASSED


def test_malformed_hash_fails():
    sbom = replace_component(cdx(), IDNA[CDX], sha256="a" * 63)
    result = evaluate(sbom)["REQ_BSI11_CMP_HASH"]
    assert result.status is Status.FAILED
    assert [f.component_ref for f in result.findings] == [IDNA[CDX]]


# @need-ids: REQ_BSI11_TIMESTAMP
@parametrize_formats
def test_timestamp_fails_when_malformed(fmt):
    sbom = replace(load(fmt), timestamp="2026-11-02")
    result = evaluate(sbom)["REQ_BSI11_TIMESTAMP"]
    assert result.status is Status.FAILED
    assert result.findings[0].component_ref is None


def test_empty_name_fails():
    sbom = replace_component(cdx(), IDNA[CDX], name="  ")
    assert evaluate(sbom)["REQ_BSI11_CMP_NAME"].status is Status.FAILED


# @need-ids: REQ_BSI11_FORMATS
def test_unsupported_version_is_a_failed_formats_row():
    info = FormatInfo("CycloneDX", "1.3")
    assert RULE_SET.accepts(info) is False
    row = formats_failed_row(info)
    assert row.id == "REQ_BSI11_FORMATS"
    assert row.section == "4"
    assert row.status is Status.FAILED
    assert row.findings and row.findings[0].component_ref is None
    assert "1.3" in row.findings[0].message
    # The rule itself gives the same verdict on a model in that version.
    by_rule = evaluate(cdx(at(("specVersion",), "1.3")))["REQ_BSI11_FORMATS"]
    assert by_rule == row


@pytest.mark.parametrize(
    "fmt, version, expected",
    [
        ("CycloneDX", "1.3", False),
        ("CycloneDX", "1.4", True),
        ("CycloneDX", "1.5", True),
        ("CycloneDX", "1.7", True),
        ("CycloneDX", "1.10", True),  # numeric, not string, comparison
        ("CycloneDX", "0.9", False),
        ("SPDX", "2.2", False),
        ("SPDX", "2.3", True),
        ("SPDX", "2.10", True),
        ("SPDX", "3.0", False),
        ("SPDX", "1.2", False),
        ("CycloneDX", "1.x", False),
        ("CycloneDX", "", False),
        ("SPDX", "SPDX-2.3", False),
        ("Other", "1.5", False),
    ],
)
def test_accepts(fmt, version, expected):
    assert RULE_SET.accepts(FormatInfo(fmt, version)) is expected


def test_unknown_version_raises_usage_problem():
    with pytest.raises(UsageProblem) as exc:
        get_rule_set("bsi-tr-03183-2", "2.0")
    message = exc.value.message
    assert "bsi-tr-03183-2" in message and "1.1" in message and "2.0" in message
    assert "request" in message.lower()
    with pytest.raises(UsageProblem) as exc:
        get_rule_set("iso-5962", "1.1")
    assert "bsi-tr-03183-2 1.1" in exc.value.message


def test_known_rule_set_is_returned():
    assert get_rule_set("bsi-tr-03183-2", "1.1") is RULE_SET
    assert supported() == {"bsi-tr-03183-2": ("1.1",)}
    assert isinstance(RULE_SET, RuleSet)
    assert RULE_SET.standard == "bsi-tr-03183-2" and RULE_SET.version == "1.1"
    assert all(isinstance(r, Rule) for r in RULE_SET.rules)


def _not_verifiable_samples():
    yield load(CDX)
    yield load(SPDX)
    yield EMPTY[CDX]()
    yield EMPTY[SPDX]()
    for gaps in GAPS.values():
        for build, _ in gaps.values():
            yield build()


# @need-ids: REQ_BSI11_DEPTH, REQ_BSI11_BUILD, REQ_BSI11_ONE_PER_VERSION, REQ_BSI11_COMPONENT_EXEC
def test_not_verifiable_rules_never_fail():
    rules = [r for r in RULE_SET.rules if r.id in NOT_VERIFIABLE]
    assert {r.id for r in rules} == NOT_VERIFIABLE
    assert all(r.check is None for r in rules)
    for sbom in _not_verifiable_samples():
        for rule in rules:
            result = rule.evaluate(sbom)
            assert result.status is Status.NOT_VERIFIABLE
            assert result.findings == ()
            assert result.examined


# --- Traceability and framework ------------------------------------------

_REQ_BLOCK = re.compile(
    r"^\.\. req:: (.+)\n   :id: (REQ_BSI11_\w+)\n(?:   :.+\n)*?   :section: ([\d.]+)$",
    re.M,
)


# @need-ids: REQ_TRACE_001
def test_rules_trace_to_requirements():
    needs = {
        rid: (section, title)
        for title, rid, section in _REQ_BLOCK.findall(
            REQUIREMENTS.read_text(encoding="utf-8")
        )
    }
    assert len(needs) == 18
    # The docs group requirements by section, so compare membership, not order.
    assert {r.id for r in RULE_SET.rules} == set(needs)
    assert len(RULE_SET.rules) == len(needs)
    for rule in RULE_SET.rules:
        assert (rule.section, rule.title) == needs[rule.id]


@parametrize_formats
def test_results_carry_rule_identity(fmt):
    for rule in RULE_SET.rules:
        result = rule.evaluate(load(fmt))
        assert (result.id, result.title, result.section) == (
            rule.id,
            rule.title,
            rule.section,
        )
        assert result.examined


def test_rule_without_check_is_not_verifiable():
    rule = Rule("X", "t", "1", None)
    result = rule.evaluate(_sbom(()))
    assert result.status is Status.NOT_VERIFIABLE


def test_marker_per_rule_in_source():
    source = Path(v1_1.__file__).read_text(encoding="utf-8")
    markers = re.findall(r"# @need-ids: (REQ_BSI11_\w+)", source)
    assert set(markers) == {r.id for r in RULE_SET.rules}


def test_large_sbom_evaluates_quickly():
    components = tuple(
        _component(
            f"c-{i}",
            identifiers=(f"pkg:pypi/lib{i}@1.0",),
            source_uri=f"https://example.org/src/{i}",
            executable_uri=f"https://example.org/bin/{i}",
            source_sha256="b" * 64,
        )
        for i in range(20_000)
    )
    sbom = _sbom(components)
    start = time.perf_counter()
    results = [rule.evaluate(sbom) for rule in RULE_SET.rules]
    elapsed = time.perf_counter() - start
    assert not [r for r in results if r.status is Status.FAILED]
    assert elapsed < 3.0, elapsed
