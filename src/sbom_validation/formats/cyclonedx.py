"""Convert a parsed CycloneDX JSON document to the neutral model.

The loader reads an already-parsed dict and does not validate the schema; it
skips missing or wrong-typed values instead of raising.
"""

import re
from typing import Any

from sbom_validation.formats._tolerant import _dicts, _str, _strs
from sbom_validation.model import Component, Party, Sbom

# Matches start only at a token boundary (after whitespace, a delimiter or the
# start), and the domain is dot-separated labels, so matching is linear in the
# text length and a trailing dot is never part of the address.
_EMAIL = re.compile(
    r"(?<![^\s<>()@,;])[^\s<>()@,;]+@[^\s<>()@,;.]+(?:\.[^\s<>()@,;.]+)+"
)


def _free_text_party(value: Any) -> list[Party]:
    """Party from a free-text author or publisher field."""
    text = _str(value)
    if not text or not text.strip():
        return []
    match = _EMAIL.search(text)
    return [Party(text, match.group(0) if match else None, None)]


def _entity_parties(entity: Any) -> list[Party]:
    """Parties from an organizationalEntity (contact emails plus first URL)."""
    if not isinstance(entity, dict):
        return []
    name = _str(entity.get("name"))
    urls = _strs(entity.get("url"))
    url = urls[0] if urls else None
    parties = [
        Party(_str(c.get("name")) or name, _str(c.get("email")), url)
        for c in _dicts(entity.get("contact"))
    ]
    if not parties and (name or url):
        parties.append(Party(name, None, url))
    return parties


def _contact_parties(contacts: Any) -> list[Party]:
    return [
        Party(_str(c.get("name")), _str(c.get("email")), None) for c in _dicts(contacts)
    ]


def _sbom_creators(metadata: dict) -> tuple[Party, ...]:
    # @need-ids: REQ_BSI11_SBOM_CREATOR
    parties = _contact_parties(metadata.get("authors"))
    for key in ("manufacture", "manufacturer", "supplier"):
        parties.extend(_entity_parties(metadata.get(key)))
    return tuple(parties)


def _sbom_uri(data: dict) -> str | None:
    # @need-ids: REQ_BSI11_SBOM_URI
    serial = _str(data.get("serialNumber"))
    if serial:
        return serial
    for ref in _dicts(data.get("externalReferences")):
        if ref.get("type") == "bom" and _str(ref.get("url")):
            return ref["url"]
    return None


def _component_creators(raw: dict, ext_refs: list[dict]) -> tuple[Party, ...]:
    # @need-ids: REQ_BSI11_CMP_CREATOR
    parties = _contact_parties(raw.get("authors"))
    parties.extend(_free_text_party(raw.get("author")))
    parties.extend(_entity_parties(raw.get("manufacturer")))
    parties.extend(_entity_parties(raw.get("supplier")))
    parties.extend(_free_text_party(raw.get("publisher")))
    for ref in ext_refs:
        if ref.get("type") == "website" and _str(ref.get("url")):
            parties.append(Party(None, None, ref["url"]))
    return tuple(parties)


def _licenses(raw: dict) -> tuple[str, ...]:
    # @need-ids: REQ_BSI11_CMP_LICENCE
    out: list[str] = []
    for entry in _dicts(raw.get("licenses")):
        lic = entry.get("license")
        value = None
        if isinstance(lic, dict):
            value = _str(lic.get("id")) or _str(lic.get("name"))
        if not value:
            value = _str(entry.get("expression"))
        if value:
            out.append(value)
    return tuple(out)


def _hash_pairs(hashes: Any) -> tuple[tuple[str, str], ...]:
    # @need-ids: REQ_BSI11_CMP_HASH
    out = []
    for h in _dicts(hashes):
        alg, content = _str(h.get("alg")), _str(h.get("content"))
        if alg and content:
            out.append((alg.upper(), content.lower()))
    return tuple(out)


def _first_sha256(pairs: tuple[tuple[str, str], ...]) -> str | None:
    for alg, value in pairs:
        if alg == "SHA-256":
            return value
    return None


def _uris(ext_refs: list[dict]) -> tuple[str | None, str | None, str | None]:
    # @need-ids: REQ_BSI11_SRC_URI, REQ_BSI11_EXE_URI, REQ_BSI11_SRC_HASH
    source = executable = intake = source_hash = None
    for ref in ext_refs:
        kind, url = ref.get("type"), _str(ref.get("url"))
        if kind == "vcs" and url and source is None:
            source = url
        elif kind == "distribution" and url and executable is None:
            executable = url
        elif kind == "distribution-intake" and url and intake is None:
            intake = url
        if kind in ("vcs", "source-distribution") and source_hash is None:
            source_hash = _first_sha256(_hash_pairs(ref.get("hashes")))
    return source, executable or intake, source_hash


def _identifiers(raw: dict) -> tuple[str, ...]:
    # @need-ids: REQ_BSI11_OTHER_IDS
    return tuple(v for v in (_str(raw.get("cpe")), _str(raw.get("purl"))) if v)


def _dependency_map(data: dict) -> dict[str, tuple[str, ...]]:
    # @need-ids: REQ_BSI11_CMP_DEPS
    # Several entries for one ref are merged; absent ref means "no data".
    merged: dict[str, list[str]] = {}
    for entry in _dicts(data.get("dependencies")):
        ref = _str(entry.get("ref"))
        if ref is None:
            continue
        merged.setdefault(ref, []).extend(_strs(entry.get("dependsOn")))
    return {ref: tuple(deps) for ref, deps in merged.items()}


def _convert(
    raw: dict, ref: str, deps: dict[str, tuple[str, ...]], is_primary: bool
) -> Component:
    # @need-ids: REQ_BSI11_CMP_NAME, REQ_BSI11_CMP_VERSION
    ext_refs = _dicts(raw.get("externalReferences"))
    hashes = _hash_pairs(raw.get("hashes"))
    source, executable, source_hash = _uris(ext_refs)
    return Component(
        ref=ref,
        name=_str(raw.get("name")),
        version=_str(raw.get("version")),
        creators=_component_creators(raw, ext_refs),
        licenses=_licenses(raw),
        sha256=_first_sha256(hashes),
        hashes=hashes,
        dependencies=deps.get(ref),
        source_uri=source,
        executable_uri=executable,
        source_sha256=source_hash,
        identifiers=_identifiers(raw),
        is_primary=is_primary,
    )


def to_model(data: dict) -> Sbom:
    """Build the neutral model from a parsed CycloneDX JSON document."""
    metadata = data.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    deps = _dependency_map(data)

    components: list[Component] = []
    anon = 0
    # Explicit stack: (raw component, is_primary). Children are pushed in
    # reverse so document order is preserved without recursion.
    stack: list[tuple[dict, bool]] = [
        (c, False) for c in reversed(_dicts(data.get("components")))
    ]
    primary = metadata.get("component")
    if isinstance(primary, dict):
        stack.append((primary, True))
    while stack:
        raw, is_primary = stack.pop()
        ref = _str(raw.get("bom-ref"))
        if not ref:
            ref = f"_anonymous-{anon}"
            anon += 1
        components.append(_convert(raw, ref, deps, is_primary))
        stack.extend((c, False) for c in reversed(_dicts(raw.get("components"))))

    return Sbom(
        format="CycloneDX",
        spec_version=_str(data.get("specVersion")) or "",
        creators=_sbom_creators(metadata),
        timestamp=_str(metadata.get("timestamp")),
        uri=_sbom_uri(data),
        components=tuple(components),
    )
