"""Standalone HTML renderer."""

import json
import re
from html.parser import HTMLParser

from sbom_validation.render.html_report import MAX_FINDINGS, render_html
from sbom_validation.render.json_report import render_json
from sbom_validation.results import Finding, Report, RequirementResult, Status

STD, VER = "bsi-tr-03183-2", "1.1"


def _row(status, n=1, findings=()):
    return RequirementResult(
        f"REQ_X_{n}", f"Title {n}", f"5.{n}", status, "things", tuple(findings)
    )


def _report(*rows, problem=None):
    return Report(STD, VER, "x/sbom.json", "CycloneDX", "1.6", tuple(rows), problem)


def _mixed():
    return _report(
        _row(Status.PASSED, 1),
        _row(Status.FAILED, 2, [Finding("pkg-a", "missing hash")]),
        _row(Status.NOT_VERIFIABLE, 3),
        _row(Status.NOT_EVALUATED, 4),
    )


class _Scan(HTMLParser):
    def __init__(self):
        super().__init__()
        self.attrs: list[tuple[str, str]] = []
        self.tags: list[str] = []
        self.body_rows = 0
        self._in_tbody = False
        self.css = ""
        self._in_style = False

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs.extend((k, v or "") for k, v in attrs)
        if tag == "tbody":
            self._in_tbody = True
        if tag == "tr" and self._in_tbody:
            self.body_rows += 1
        if tag == "style":
            self._in_style = True

    def handle_endtag(self, tag):
        if tag == "tbody":
            self._in_tbody = False
        if tag == "style":
            self._in_style = False

    def handle_data(self, data):
        if self._in_style:
            self.css += data


def _scan(html: str) -> _Scan:
    scan = _Scan()
    scan.feed(html)
    return scan


def test_has_no_external_references():
    html = render_html(
        _report(
            _row(
                Status.FAILED,
                1,
                [Finding("https://x.example/a", "see http://y.example")],
            )
        )
    )
    assert html.startswith("<!doctype html>")
    scan = _scan(html)
    for _, value in scan.attrs:
        assert not re.match(r"\s*(https?:)?//", value, re.I), value
        assert "http://" not in value and "https://" not in value
    assert "url(" not in scan.css.lower()
    assert "@import" not in scan.css.lower()
    assert "link" not in scan.tags
    assert 'name="viewport"' in html and 'charset="utf-8"' in html


def test_one_row_per_requirement():
    report = _mixed()
    scan = _scan(render_html(report))
    assert scan.body_rows == len(report.results) == 4


def test_values_are_escaped():
    evil = "<script>alert(1)</script>"
    html = render_html(
        _report(_row(Status.FAILED, 1, [Finding(evil, evil)]), _row(Status.PASSED, 2))
    )
    assert evil not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert html.lower().count("<script") == 1  # only our own inline script
    assert html.lower().count("</script>") == 1


def test_script_close_in_component_name_cannot_break_out():
    html = render_html(
        _report(_row(Status.FAILED, 1, [Finding("a</script><b>x", "m</script>")]))
    )
    assert "a</script>" not in html and "m</script>" not in html
    assert html.lower().count("</script>") == 1


def test_contains_sort_and_filter_controls():
    html = render_html(_mixed())
    assert html.count("aria-sort=") >= 5
    assert "<button" in html and 'type="search"' in html
    for label in ("All", "Failed", "Not verifiable", "Not evaluated", "Passed"):
        assert label in html
    assert "<label" in html
    assert "<details" in html


def test_html_and_json_agree_on_counts():
    report = _mixed()
    counts = json.loads(render_json(report))["counts"]
    html = render_html(report)
    for key, n in counts.items():
        assert f'data-count="{key}">{n}<' in html
    assert (
        "1 requirement(s) cannot be verified automatically and need manual review."
        in html
    )


def test_no_manual_note_without_not_verifiable():
    html = render_html(_report(_row(Status.PASSED)))
    assert "manual review" not in html


def test_problem_report_renders_errors():
    html = render_html(_report(problem="bad <schema>\n  at /components: not an array"))
    assert "Input problem" in html
    assert "<pre>bad &lt;schema&gt;\n  at /components: not an array</pre>" in html
    assert _scan(html).body_rows == 0
    assert "<table" not in html


def test_findings_are_capped():
    findings = [Finding(f"c{i}", "bad") for i in range(20000)]
    html = render_html(_report(_row(Status.FAILED, 1, findings)))
    assert html.count("<li><code>") == MAX_FINDINGS == 200
    assert "... and 19800 more (see JSON report)" in html
    assert len(html) < 200_000
