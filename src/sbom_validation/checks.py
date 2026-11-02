"""Pure, offline form checks on strings.

Every function takes ``str`` and returns ``bool`` and never raises, whatever
the input. Nothing here touches the network or the filesystem at call time
(the SPDX licence list is bundled in the ``license-expression`` package).
"""

from __future__ import annotations

import re
from datetime import datetime
from functools import lru_cache
from urllib.parse import urlparse

from license_expression import get_spdx_licensing
from packageurl import PackageURL

__all__ = [
    "is_cpe",
    "is_email",
    "is_purl",
    "is_rfc3339",
    "is_sha256",
    "is_spdx_licence_expression",
    "is_uri",
    "is_url",
]

_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")

_RFC3339_RE = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?"
    r"([Zz]|[+-]\d{2}:\d{2})",
    re.ASCII,
)

_EMAIL_RE = re.compile(r"[^\s@]+@[^\s@.]+(?:\.[^\s@.]+)+")

_URI_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*:[^\s<>\"{}|\\^`]+", re.ASCII)

_CPE_COMPONENT = r"(?:[^:\\\s]|\\.)+"
_CPE23_RE = re.compile(rf"cpe:2\.3:{_CPE_COMPONENT}(?::{_CPE_COMPONENT}){{10}}")
_CPE22_RE = re.compile(r"cpe:/[aho]?(?::[^:\s]*){0,6}")

# Accepted licence references that are not in the SPDX list:
#   [DocumentRef-<idstring>:]LicenseRef-<idstring>
# where <idstring> is one or more of [A-Za-z0-9.-]. This covers the
# LicenseRef-scancode-* and LicenseRef-<entity>-* forms as special cases.
_LICENSE_REF_RE = re.compile(
    r"(?<![A-Za-z0-9.:\-])"
    r"(?:DocumentRef-[A-Za-z0-9.\-]+:)?LicenseRef-[A-Za-z0-9.\-]+"
    r"(?![A-Za-z0-9.:\-])"
)
_LOWERCASE_OPERATOR_RE = re.compile(r"(?<![^\s()])(?:and|or|with)(?![^\s()])")

_SPDX_PLACEHOLDER = "MIT"
_TOKEN_SPLIT_RE = re.compile(r"[\s()]+")
_OPERATORS = frozenset({"AND", "OR", "WITH"})


def is_sha256(s: str) -> bool:
    """Exactly 64 hex characters, either case, no surrounding whitespace."""
    try:
        return _SHA256_RE.fullmatch(s) is not None
    except Exception:
        return False


# @need-ids: REQ_BSI11_TIMESTAMP
def is_rfc3339(s: str) -> bool:
    """Full RFC 3339 date-time with ``T``/``t`` and ``Z`` or numeric offset."""
    try:
        m = _RFC3339_RE.fullmatch(s)
        if m is None:
            return False
        year, month, day, hour, minute, second, frac, tz = m.groups()
        # Normalise for datetime.fromisoformat (Python 3.11 accepts 3 or 6
        # fractional digits); the regex above has already pinned the shape.
        frac_part = f".{(frac + '000000')[:6]}" if frac else ""
        offset = "+00:00" if tz in ("Z", "z") else tz
        datetime.fromisoformat(
            f"{year}-{month}-{day}T{hour}:{minute}:{second}{frac_part}{offset}"
        )
        return True
    except Exception:
        return False


# @need-ids: REQ_BSI11_CMP_CREATOR, REQ_BSI11_SBOM_CREATOR
def is_email(s: str) -> bool:
    """Pragmatic ``local@domain.tld`` check."""
    try:
        return _EMAIL_RE.fullmatch(s) is not None
    except Exception:
        return False


# @need-ids: REQ_BSI11_CMP_CREATOR, REQ_BSI11_SBOM_CREATOR
def is_url(s: str) -> bool:
    """http/https/ftp URL with a non-empty host."""
    try:
        if not s or any(c.isspace() or ord(c) < 0x20 for c in s):
            return False
        parts = urlparse(s)
        return parts.scheme.lower() in ("http", "https", "ftp") and bool(
            parts.hostname
        )
    except Exception:
        return False


# @need-ids: REQ_BSI11_SBOM_URI, REQ_BSI11_SRC_URI, REQ_BSI11_EXE_URI
def is_uri(s: str) -> bool:
    """RFC 3986 absolute URI with a scheme (``urn:uuid:...``, ``https://...``)."""
    try:
        return _URI_RE.fullmatch(s) is not None
    except Exception:
        return False


# @need-ids: REQ_BSI11_OTHER_IDS
def is_purl(s: str) -> bool:
    """Valid Package URL per ``packageurl.PackageURL.from_string``."""
    try:
        PackageURL.from_string(s)
        return True
    except Exception:
        return False


# @need-ids: REQ_BSI11_OTHER_IDS
def is_cpe(s: str) -> bool:
    """CPE 2.3 formatted string (11 components) or CPE 2.2 URI."""
    try:
        return _CPE23_RE.fullmatch(s) is not None or (
            _CPE22_RE.fullmatch(s) is not None
        )
    except Exception:
        return False


@lru_cache(maxsize=1)
def _licensing():
    return get_spdx_licensing()


@lru_cache(maxsize=1)
def _canonical_keys() -> frozenset:
    # Canonical keys plus the list's aliases, which carry the deprecated-but-
    # listed SPDX ids (e.g. GPL-2.0, GPL-2.0+ handled via "+" stripping).
    symbols = _licensing().known_symbols.values()
    return frozenset(
        {sym.key for sym in symbols}
        | {alias for sym in symbols for alias in sym.aliases}
    )


@lru_cache(maxsize=8192)
def _check_licence(s: str) -> bool:
    if not s.strip() or _LOWERCASE_OPERATOR_RE.search(s):
        return False
    substituted = _LICENSE_REF_RE.sub(_SPDX_PLACEHOLDER, s)
    result = _licensing().validate(substituted, validate_license_keys=True)
    if result.errors:
        return False
    # The library matches ids case-insensitively; BSI requires the canonical
    # SPDX id (and canonical exception id after WITH).
    canonical = _canonical_keys()
    for token in _TOKEN_SPLIT_RE.split(substituted):
        if not token or token in _OPERATORS:
            continue
        if token not in canonical and token.rstrip("+") not in canonical:
            return False
    return True


# @need-ids: REQ_BSI11_CMP_LICENCE
def is_spdx_licence_expression(s: str) -> bool:
    """Valid SPDX licence expression (bundled list, incl. deprecated IDs).

    Supports ``AND``/``OR``/``WITH`` and parentheses, plus LicenseRef forms
    (see ``_LICENSE_REF_RE``). ``NOASSERTION`` and ``NONE`` are rejected.
    """
    try:
        return _check_licence(s)
    except Exception:
        return False
