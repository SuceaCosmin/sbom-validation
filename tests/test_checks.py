"""Tests for the pure form checks."""

import pytest

from sbom_validation import checks
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


@pytest.mark.parametrize(
    "value, expected",
    [
        ("a" * 64, True),
        ("A" * 64, True),
        ("0123456789abcdefABCDEF" + "0" * 42, True),
        ("a" * 63, False),
        ("a" * 65, False),
        ("g" * 64, False),
        (" " + "a" * 64, False),
        ("a" * 64 + "\n", False),
        ("", False),
    ],
)
def test_is_sha256(value, expected):
    assert is_sha256(value) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2023-11-28T10:00:00Z", True),
        ("2023-11-28T10:00:00z", True),
        ("2023-11-28t10:00:00Z", True),
        ("2023-11-28T10:00:00.123Z", True),
        ("2023-11-28T10:00:00+01:00", True),
        ("2023-11-28T10:00:00-05:30", True),
        ("2023-11-28", False),
        ("2023-11-28T10:00:00", False),
        ("2023-11-28T10:00Z", False),
        ("2023-13-28T10:00:00Z", False),
        ("2023-02-30T10:00:00Z", False),
        ("2023-11-28T25:00:00Z", False),
        ("2023-11-28 10:00:00Z", False),
        ("2023-11-28T10:00:00+0100", False),
        (" 2023-11-28T10:00:00Z", False),
        ("", False),
        ("yesterday", False),
    ],
)
def test_is_rfc3339(value, expected):
    assert is_rfc3339(value) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("MIT OR Apache-2.0", True),
        ("MIT", True),
        ("MIT WITH Classpath-exception-2.0", True),
        ("(MIT AND BSD-3-Clause) OR ISC", True),
        ("GPL-2.0-only", True),
        ("GPL-2.0", True),  # deprecated but listed
        ("LicenseRef-scancode-foo", True),
        ("LicenseRef-acme-1", True),
        ("MIT OR LicenseRef-acme-1.2", True),
        ("DocumentRef-x:LicenseRef-y", True),
        ("NOASSERTION", False),
        ("NONE", False),
        ("Proprietary", False),
        ("Foo-1.0", False),
        ("MIT OR", False),
        ("MIT or ISC", False),
        ("LicenseRef-", False),
        ("LicenseRef-a_b", False),
        ("(", False),
        ("", False),
        ("   ", False),
    ],
)
def test_is_spdx_licence_expression(value, expected):
    assert is_spdx_licence_expression(value) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("pkg:npm/foo@1.0.0", True),
        ("pkg:maven/org.apache/commons@1.2?type=jar", True),
        ("foo", False),
        ("pkg:", False),
        ("pkg:npm", False),
        ("", False),
    ],
)
def test_is_purl(value, expected):
    assert is_purl(value) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("a@b.co", True),
        ("first.last+tag@sub.example.org", True),
        ("a@", False),
        ("@b.co", False),
        ("a@b", False),
        ("a@b.", False),
        ("a b@c.de", False),
        ("a@@b.co", False),
        ("a@b.co ", False),
        ("", False),
    ],
)
def test_is_email(value, expected):
    assert is_email(value) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("https://x.org/a", True),
        ("http://x.org", True),
        ("ftp://x.org/f", True),
        ("x.org", False),
        ("https://", False),
        ("file:///etc/passwd", False),
        ("mailto:a@b.co", False),
        ("https://x .org", False),
        ("", False),
    ],
)
def test_is_url(value, expected):
    assert is_url(value) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", True),
        ("https://example.org/sbom/1", True),
        ("git+https://github.com/a/b.git", True),
        ("x.org", False),
        ("/relative/path", False),
        ("1http://x", False),
        ("http://a b", False),
        ("", False),
    ],
)
def test_is_uri(value, expected):
    assert is_uri(value) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", True),
        ("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*", False),
        ("cpe:/a:vendor:product:1.0", True),
        ("cpe:/a", True),
        ("cpe:2.3:a", False),
        ("foo", False),
        ("", False),
    ],
)
def test_is_cpe(value, expected):
    assert is_cpe(value) is expected


ODD_INPUTS = [
    "",
    " ",
    "\t\n",
    "x" * 100_000,
    "(" * 5_000,
    "MIT OR " * 3_000,
    "é€漢字\u0000퟿",
    "a@" + "b." * 5_000,
    "pkg:" + "a/" * 5_000,
    "cpe:2.3:" + ":" * 500,
    "‮​",
]

ALL_CHECKS = [
    is_email,
    is_url,
    is_uri,
    is_sha256,
    is_rfc3339,
    is_purl,
    is_cpe,
    is_spdx_licence_expression,
]


@pytest.mark.parametrize("check", ALL_CHECKS, ids=lambda f: f.__name__)
@pytest.mark.parametrize("value", ODD_INPUTS, ids=lambda v: repr(v[:12]))
def test_checks_never_raise(check, value):
    assert isinstance(check(value), bool)


def test_checks_module_exports_all():
    for check in ALL_CHECKS:
        assert getattr(checks, check.__name__) is check
