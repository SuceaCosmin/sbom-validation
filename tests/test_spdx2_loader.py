"""Tests for the SPDX 2.x loader."""

import json
import time
from pathlib import Path

from sbom_validation.formats.spdx2 import to_model
from sbom_validation.model import Party

SAMPLE = Path(__file__).parent / "samples" / "spdx2" / "compliant_2_3.json"
APP = "SPDXRef-Package-acme-app"
REQ = "SPDXRef-Package-requests"
URL3 = "SPDXRef-Package-urllib3"
IDNA = "SPDXRef-Package-idna"


def load() -> dict:
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


def by_ref(sbom):
    return {c.ref: c for c in sbom.components}


def test_packages_become_components():
    sbom = to_model(load())
    assert sbom.format == "SPDX"
    assert sbom.spec_version == "2.3"
    assert sbom.timestamp == "2026-11-02T09:30:00Z"
    assert sbom.uri.startswith("https://example.com/spdx/acme-app-1.0.0-")
    assert sbom.creators == (Party("Example Build Team", "sbom@example.com", None),)
    assert len(sbom.components) == 4
    comps = by_ref(sbom)
    app = comps[APP]
    assert app.is_primary
    assert [c.is_primary for c in sbom.components].count(True) == 1
    assert app.name == "acme-app" and app.version == "1.0.0"
    assert app.creators == (Party("Acme Dev", "dev@example.com", None),)
    assert app.licenses == ("Apache-2.0", "Apache-2.0")
    assert app.identifiers == ("pkg:generic/acme-app@1.0.0",)
    assert app.source_uri is None and app.executable_uri is None
    assert app.source_sha256 is None
    req = comps[REQ]
    assert req.creators == (
        Party("Python Software Foundation", "maintainers@example.org", None),
        Party(None, None, "https://pypi.org/project/requests/"),
    )
    assert req.source_uri == "git+https://github.com/psf/requests"
    assert req.executable_uri is None
    urllib3 = comps[URL3]
    assert urllib3.executable_uri == "https://files.pythonhosted.org/urllib3-2.0.7.tar.gz"
    assert urllib3.source_uri is None
    assert urllib3.identifiers == ("cpe:2.3:a:urllib3:urllib3:2.0.7:*:*:*:*:*:*:*",)


def test_primary_from_describes_relationship():
    data = load()
    del data["documentDescribes"]
    assert by_ref(to_model(data))[APP].is_primary
    data["relationships"] = [
        r for r in data["relationships"] if r["relationshipType"] != "DESCRIBES"
    ]
    assert not any(c.is_primary for c in to_model(data).components)


def test_dependency_relationships_both_directions():
    comps = by_ref(to_model(load()))
    assert comps[APP].dependencies == (REQ, IDNA)
    # requests: DEPENDS_ON urllib3 plus "idna DEPENDENCY_OF requests".
    assert comps[REQ].dependencies == (URL3, IDNA)
    assert comps[URL3].dependencies == ()
    assert comps[IDNA].dependencies == ()


def test_dependency_of_means_target_depends_on_source():
    data = load()
    data["relationships"] = [
        {
            "spdxElementId": URL3,
            "relationshipType": "DEPENDENCY_OF",
            "relatedSpdxElement": REQ,
        }
    ]
    comps = by_ref(to_model(data))
    assert comps[REQ].dependencies == (URL3,)
    assert comps[URL3].dependencies == ()


def test_no_relationships_gives_none():
    data = load()
    del data["relationships"]
    assert all(c.dependencies is None for c in to_model(data).components)
    data["relationships"] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": APP,
        }
    ]
    assert all(c.dependencies is None for c in to_model(data).components)


def test_checksums_normalised_lowercase():
    data = load()
    data["packages"][0]["checksums"].append(
        {"algorithm": "SHA1", "checksumValue": "ABCDEF"}
    )
    app = by_ref(to_model(data))[APP]
    assert app.sha256 == "a" * 64
    assert app.hashes == (("SHA-256", "a" * 64), ("SHA-1", "abcdef"))


def test_noassertion_and_none_kept_verbatim():
    data = load()
    pkg = data["packages"][3]
    pkg["licenseDeclared"] = "NOASSERTION"
    pkg["licenseConcluded"] = "NONE"
    assert by_ref(to_model(data))[IDNA].licenses == ("NOASSERTION", "NONE")
    pkg["downloadLocation"] = "NONE"
    assert by_ref(to_model(data))[IDNA].executable_uri is None


def test_zero_packages():
    data = load()
    del data["packages"]
    assert to_model(data).components == ()
    assert to_model({"spdxVersion": "SPDX-2.3"}).components == ()


def test_tolerates_wrong_types():
    sbom = to_model(
        {
            "creationInfo": "x",
            "packages": [1, {"name": 3, "checksums": [None, {"algorithm": 1}]}],
            "relationships": [None, {"spdxElementId": 1}],
            "documentDescribes": "x",
        }
    )
    assert len(sbom.components) == 1
    assert sbom.components[0].dependencies is None


def test_scale_is_fast():
    n = 20000
    data = {
        "packages": [{"SPDXID": f"SPDXRef-{i}", "name": f"p{i}"} for i in range(n)],
        "relationships": [
            {
                "spdxElementId": f"SPDXRef-{i}",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": f"SPDXRef-{i - 1}",
            }
            for i in range(n)
        ]
        + [
            {
                "spdxElementId": f"SPDXRef-{i}",
                "relationshipType": "DEPENDENCY_OF",
                "relatedSpdxElement": f"SPDXRef-{i + 1}",
            }
            for i in range(30000)
        ],
    }
    start = time.perf_counter()
    assert len(to_model(data).components) == n
    assert time.perf_counter() - start < 1.0
