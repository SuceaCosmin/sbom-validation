"""Convert a parsed SPDX 2.x JSON document to the neutral model.

The loader reads an already-parsed dict and does not validate the schema; it
skips missing or wrong-typed values instead of raising.
"""

import re
from typing import Any

from sbom_validation.formats._tolerant import _dicts, _str
from sbom_validation.model import Component, Party, Sbom

_DOCUMENT = "SPDXRef-DOCUMENT"
_VCS_PREFIXES = ("git+", "hg+", "svn+", "bzr+")
_NO_VALUE = ("NONE", "NOASSERTION")
_ACTOR = re.compile(r"^(Person|Organization):\s*(.*?)\s*(?:\(([^()]*)\))?\s*$", re.DOTALL)
_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://\S+$")
_SHA_ALG = re.compile(r"^SHA(\d+)$")


def _actor(value: Any) -> Party | None:
    """Party from ``Person: name (email)`` / ``Organization: name (email)``."""
    text = _str(value)
    match = _ACTOR.match(text) if text else None
    if not match:
        return None
    name = match.group(2) or None
    contact = (match.group(3) or "").strip()
    email = contact if "@" in contact and not _URL.match(contact) else None
    url = contact if _URL.match(contact) else None
    if not (name or email or url):
        return None
    return Party(name, email, url)


def _sbom_creators(info: dict) -> tuple[Party, ...]:
    # @need-ids: REQ_BSI11_SBOM_CREATOR
    creators = info.get("creators")
    if not isinstance(creators, list):
        return ()
    parties = (_actor(c) for c in creators)
    return tuple(p for p in parties if p is not None)


def _component_creators(raw: dict) -> tuple[Party, ...]:
    # @need-ids: REQ_BSI11_CMP_CREATOR
    # A supplier stands in only where there is no originator (mapping file).
    parties = [p for p in (_actor(raw.get("originator")),) if p]
    if not parties:
        parties = [p for p in (_actor(raw.get("supplier")),) if p]
    homepage = _str(raw.get("homepage"))
    if homepage and homepage not in _NO_VALUE:
        parties.append(Party(None, None, homepage))
    return tuple(parties)


def _licenses(raw: dict) -> tuple[str, ...]:
    # @need-ids: REQ_BSI11_CMP_LICENCE
    values = (_str(raw.get("licenseDeclared")), _str(raw.get("licenseConcluded")))
    return tuple(v for v in values if v)


def _hash_pairs(checksums: Any) -> tuple[tuple[str, str], ...]:
    # @need-ids: REQ_BSI11_CMP_HASH
    out = []
    for c in _dicts(checksums):
        alg, value = _str(c.get("algorithm")), _str(c.get("checksumValue"))
        if alg and value:
            alg = alg.upper()
            sha = _SHA_ALG.match(alg)
            out.append((f"SHA-{sha.group(1)}" if sha else alg, value.lower()))
    return tuple(out)


def _first_sha256(pairs: tuple[tuple[str, str], ...]) -> str | None:
    for alg, value in pairs:
        if alg == "SHA-256":
            return value
    return None


def _uris(raw: dict) -> tuple[str | None, str | None, str | None]:
    # @need-ids: REQ_BSI11_SRC_URI, REQ_BSI11_EXE_URI, REQ_BSI11_SRC_HASH
    # Source and executable hashes are not distinguishable in SPDX 2.x
    # (mapping file), so no source hash is reported.
    location = _str(raw.get("downloadLocation"))
    if not location or location in _NO_VALUE:
        return None, None, None
    if location.lower().startswith(_VCS_PREFIXES):
        return location, None, None
    return None, location, None


def _identifiers(raw: dict) -> tuple[str, ...]:
    # @need-ids: REQ_BSI11_OTHER_IDS
    out = []
    for ref in _dicts(raw.get("externalRefs")):
        category = _str(ref.get("referenceCategory"))
        kind = _str(ref.get("referenceType"))
        locator = _str(ref.get("referenceLocator"))
        if not locator:
            continue
        if category == "SECURITY" and kind in ("cpe22Type", "cpe23Type"):
            out.append(locator)
        elif category in ("PACKAGE-MANAGER", "PACKAGE_MANAGER") and kind == "purl":
            out.append(locator)
    return tuple(out)


def _relationships(data: dict) -> tuple[set[str], dict[str, dict[str, None]] | None]:
    """Primary SPDXIDs and the dependency map (None when no dependency data).

    ``A DEPENDS_ON B`` and ``B DEPENDENCY_OF A`` both mean A depends on B.
    """
    # @need-ids: REQ_BSI11_CMP_DEPS
    describes: set[str] = set()
    described = data.get("documentDescribes")
    if isinstance(described, list):
        describes.update(i for i in described if isinstance(i, str))
    deps: dict[str, dict[str, None]] = {}
    has_dependency_data = False
    for rel in _dicts(data.get("relationships")):
        kind = _str(rel.get("relationshipType"))
        source, target = _str(rel.get("spdxElementId")), _str(rel.get("relatedSpdxElement"))
        if not source or not target:
            continue
        if kind == "DESCRIBES" and source == _DOCUMENT:
            describes.add(target)
        elif kind == "DESCRIBED_BY" and target == _DOCUMENT:
            describes.add(source)
        elif kind in ("DEPENDS_ON", "DEPENDENCY_OF"):
            has_dependency_data = True
            dependent, dependency = (source, target) if kind == "DEPENDS_ON" else (target, source)
            if dependency in _NO_VALUE or dependent in _NO_VALUE:
                continue
            deps.setdefault(dependent, {})[dependency] = None
    return describes, deps if has_dependency_data else None


def _convert(
    raw: dict,
    ref: str,
    deps: dict[str, dict[str, None]] | None,
    is_primary: bool,
) -> Component:
    # @need-ids: REQ_BSI11_CMP_NAME, REQ_BSI11_CMP_VERSION
    hashes = _hash_pairs(raw.get("checksums"))
    source, executable, source_hash = _uris(raw)
    return Component(
        ref=ref,
        name=_str(raw.get("name")),
        version=_str(raw.get("versionInfo")),
        creators=_component_creators(raw),
        licenses=_licenses(raw),
        sha256=_first_sha256(hashes),
        hashes=hashes,
        dependencies=None if deps is None else tuple(deps.get(ref, ())),
        source_uri=source,
        executable_uri=executable,
        source_sha256=source_hash,
        identifiers=_identifiers(raw),
        is_primary=is_primary,
    )


def _spec_version(data: dict) -> str:
    text = _str(data.get("spdxVersion")) or ""
    return text.removeprefix("SPDX-")


def to_model(data: dict) -> Sbom:
    """Build the neutral model from a parsed SPDX 2.x JSON document."""
    info = data.get("creationInfo")
    info = info if isinstance(info, dict) else {}
    primary_ids, deps = _relationships(data)

    components: list[Component] = []
    for index, raw in enumerate(_dicts(data.get("packages"))):
        ref = _str(raw.get("SPDXID")) or f"_anonymous-{index}"
        components.append(_convert(raw, ref, deps, ref in primary_ids))

    return Sbom(
        format="SPDX",
        spec_version=_spec_version(data),
        creators=_sbom_creators(info),
        # @need-ids: REQ_BSI11_TIMESTAMP
        timestamp=_str(info.get("created")),
        # @need-ids: REQ_BSI11_SBOM_URI
        uri=_str(data.get("documentNamespace")),
        components=tuple(components),
    )
