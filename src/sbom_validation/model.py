"""Format-neutral SBOM model consumed by the rules."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Party:
    """A person or organisation named in an SBOM."""

    name: str | None
    email: str | None
    url: str | None


@dataclass(frozen=True)
class Component:
    """One component. ``dependencies`` is None when the SBOM has no data."""

    ref: str
    name: str | None
    version: str | None
    creators: tuple[Party, ...]
    licenses: tuple[str, ...]
    sha256: str | None
    hashes: tuple[tuple[str, str], ...]
    dependencies: tuple[str, ...] | None
    source_uri: str | None
    executable_uri: str | None
    source_sha256: str | None
    identifiers: tuple[str, ...]
    is_primary: bool


@dataclass(frozen=True)
class Sbom:
    """A whole SBOM in neutral form."""

    format: str
    spec_version: str
    creators: tuple[Party, ...]
    timestamp: str | None
    uri: str | None
    components: tuple[Component, ...]
