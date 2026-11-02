"""Control characters from an SBOM must not reach the console or break HTML."""

from sbom_validation.render.console import render_console
from sbom_validation.render.html_report import render_html
from sbom_validation.results import Finding, Report, RequirementResult, Status

EVIL = "evil\n::error title=x::injected\x1b[31mRED"


def _report(*findings, path="x/sbom.json", problem=None):
    row = RequirementResult("REQ_X", "Title", "5.1", Status.FAILED, "things", tuple(findings))
    results = () if problem else (row,)
    return Report("std", "1", path, "CycloneDX", "1.6", results, problem)


def _assert_clean(text):
    assert "\x1b" not in text
    assert "\r" not in text
    assert not any(line.startswith("::") for line in text.splitlines())
    assert all(ord(c) >= 32 or c == "\n" for c in text)


def test_ref_and_message_controls_are_escaped():
    text = render_console(_report(Finding(EVIL, EVIL)))
    _assert_clean(text)
    assert "\\n::error" in text
    assert "\\x1b[31m" in text


def test_path_controls_are_escaped():
    text = render_console(_report(path=EVIL))
    _assert_clean(text)


def test_other_controls_escaped():
    text = render_console(_report(Finding(None, "a\r\tb\x7fc\x85d\x00e")))
    _assert_clean(text)
    assert "\x7f" not in text and "\x85" not in text
    assert "\\r" in text and "\\t" in text and "\\x7f" in text


def test_problem_stays_multiline_but_escaped():
    text = render_console(_report(problem="line one\n  line two\x1b[0m\nline three"))
    _assert_clean(text)
    lines = text.splitlines()
    i = lines.index("line one")
    assert lines[i : i + 3] == ["line one", "  line two\\x1b[0m", "line three"]


def test_html_escapes_markup_around_controls():
    evil = "</td><script>alert(1)</script>\x1b[31m\n"
    html = render_html(_report(Finding(evil, evil)))
    assert "<script>alert(1)" not in html
    assert "&lt;script&gt;alert(1)" in html
