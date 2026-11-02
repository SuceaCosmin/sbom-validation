"""Tests for the CycloneDX loader."""

import copy
import json
import time
from pathlib import Path

from sbom_validation.formats.cyclonedx import to_model
from sbom_validation.model import Party

SAMPLE = Path(__file__).parent / "samples" / "cyclonedx" / "compliant_1_5.json"


def load() -> dict:
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


def by_ref(sbom):
    return {c.ref: c for c in sbom.components}


def test_maps_primary_and_nested_components():
    sbom = to_model(load())
    assert sbom.format == "CycloneDX"
    assert sbom.spec_version == "1.5"
    assert sbom.timestamp == "2026-11-02T09:30:00Z"
    assert sbom.uri == "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
    assert sbom.creators == (Party("Example Build Team", "sbom@example.com", None),)
    assert len(sbom.components) == 4
    comps = by_ref(sbom)
    primary = comps["pkg:generic/acme-app@1.0.0"]
    assert primary.is_primary
    assert [c.is_primary for c in sbom.components].count(True) == 1
    assert primary.name == "acme-app" and primary.version == "1.0.0"
    assert primary.creators == (Party("Acme Dev <dev@example.com>", "dev@example.com", None),)
    assert primary.licenses == ("Apache-2.0",)
    assert primary.identifiers == ("pkg:generic/acme-app@1.0.0",)
    nested = comps["pkg:pypi/urllib3@2.0.7"]
    assert not nested.is_primary
    assert nested.licenses == ("MIT OR Apache-2.0",)
    assert nested.identifiers == ("cpe:2.3:a:urllib3:urllib3:2.0.7:*:*:*:*:*:*:*",)
    assert nested.dependencies == ()
    req = comps["pkg:pypi/requests@2.31.0"]
    assert req.dependencies == ("pkg:pypi/urllib3@2.0.7", "pkg:pypi/idna@3.4")
    assert req.source_uri == "https://github.com/psf/requests"
    assert req.executable_uri == "https://files.pythonhosted.org/requests-2.31.0.tar.gz"
    assert req.source_sha256 == "1" * 64
    assert req.creators == (
        Party("Maintainers", "maintainers@example.org", "https://pypi.org/project/requests/"),
    )
    assert comps["pkg:pypi/idna@3.4"].dependencies == ()
    data = load()
    data["dependencies"] = [
        d for d in data["dependencies"] if d["ref"] != "pkg:pypi/idna@3.4"
    ]
    assert by_ref(to_model(data))["pkg:pypi/idna@3.4"].dependencies is None


def test_hash_is_normalised_lowercase():
    sbom = to_model(load())
    primary = by_ref(sbom)["pkg:generic/acme-app@1.0.0"]
    assert primary.sha256 == "a" * 64
    assert primary.hashes == (("SHA-256", "a" * 64),)


def test_missing_dependency_graph_gives_none():
    data = load()
    del data["dependencies"]
    assert all(c.dependencies is None for c in to_model(data).components)


def test_zero_components():
    data = load()
    del data["components"]
    del data["metadata"]["component"]
    sbom = to_model(data)
    assert sbom.components == ()
    assert to_model({"bomFormat": "CycloneDX", "specVersion": "1.5"}).components == ()


def test_duplicate_bom_refs_do_not_crash():
    data = load()
    data["components"].append(copy.deepcopy(data["components"][1]))
    sbom = to_model(data)
    assert len(sbom.components) == 5


def test_license_noassertion_is_kept_verbatim():
    data = load()
    data["components"][1]["licenses"] = [
        {"license": {"name": "NOASSERTION"}},
        {"license": {"id": "MIT"}},
        "junk",
    ]
    comp = by_ref(to_model(data))["pkg:pypi/idna@3.4"]
    assert comp.licenses == ("NOASSERTION", "MIT")


def test_deep_nesting_and_scale_are_safe_and_fast():
    deep: dict = {"name": "leaf", "bom-ref": "leaf"}
    for i in range(5000):
        deep = {"name": f"n{i}", "bom-ref": f"n{i}", "components": [deep]}
    assert len(to_model({"components": [deep]}).components) == 5001
    data = {
        "components": [{"name": f"c{i}", "bom-ref": f"r{i}"} for i in range(20000)],
        "dependencies": [{"ref": f"r{i}", "dependsOn": [f"r{i - 1}"]} for i in range(20000)],
    }
    start = time.perf_counter()
    assert len(to_model(data).components) == 20000
    assert time.perf_counter() - start < 1.0


def test_tolerates_wrong_types():
    sbom = to_model(
        {
            "metadata": {"authors": "x", "component": 5},
            "components": [1, {"name": 3, "hashes": [None, {"alg": 1}]}],
            "dependencies": [None, {"ref": 1}],
        }
    )
    assert len(sbom.components) == 1
