"""Documentation helpers on top of sphinx-needs.

* ``needs-summary`` directive: a table counting requirements per
  ``rows`` field value and ``cols`` field value (a dashboard / roadmap).
* Consistency check: warns when a requirement's ``status`` disagrees with its
  code and test evidence (``-W`` turns this into a build failure).
* ``matrix.csv``: the traceability matrix, written next to the HTML output.
"""

from __future__ import annotations

import csv
from pathlib import Path

from docutils import nodes
from docutils.parsers.rst import Directive, directives
from sphinx.util import logging

logger = logging.getLogger(__name__)

# Process requirements that are met by tests and tooling, so need no code marker.
NO_CODE_OK = {"REQ_TRACE_002"}
STATUS_ORDER = ["draft", "approved", "implemented", "verified", "deprecated"]


class needs_summary_placeholder(nodes.General, nodes.Element):
    pass


class NeedsSummary(Directive):
    """``.. needs-summary:: [types]`` with ``:rows:`` and ``:cols:`` fields."""

    optional_arguments = 1
    option_spec = {"rows": directives.unchanged, "cols": directives.unchanged}

    def run(self):
        node = needs_summary_placeholder()
        node["types"] = self.arguments[0] if self.arguments else "req"
        node["rows"] = self.options.get("rows", "origin")
        node["cols"] = self.options.get("cols", "status")
        return [node]


def _requirements(app):
    from sphinx_needs.data import SphinxNeedsData

    needs = SphinxNeedsData(app.env).get_needs_view()
    return [n for n in needs.values() if n["type"] == "req"]


def _value(need, field):
    value = need.get(field)
    return str(value) if value not in (None, "") else "(none)"


def _order(values, field):
    values = sorted(set(values))
    if field == "status":
        return [s for s in STATUS_ORDER if s in values] + [v for v in values if v not in STATUS_ORDER]
    return values


def _cell(text, bold=False):
    para = nodes.paragraph()
    para += nodes.strong(text=text) if bold else nodes.Text(text)
    return nodes.entry("", para)


def _row(cells):
    row = nodes.row()
    for c in cells:
        row += c
    return row


def resolve_summaries(app, doctree, docname):
    for node in list(doctree.findall(needs_summary_placeholder)):
        reqs = _requirements(app)
        rf, cf = node["rows"], node["cols"]
        rows = _order([_value(n, rf) for n in reqs], rf)
        cols = _order([_value(n, cf) for n in reqs], cf)
        table = nodes.table(classes=["needs-summary"])
        tgroup = nodes.tgroup(cols=len(cols) + 2)
        table += tgroup
        for _ in range(len(cols) + 2):
            tgroup += nodes.colspec(colwidth=1)
        head = nodes.thead()
        head += _row([_cell(rf, True)] + [_cell(c, True) for c in cols] + [_cell("total", True)])
        tgroup += head
        body = nodes.tbody()
        for r in rows:
            counts = [sum(1 for n in reqs if _value(n, rf) == r and _value(n, cf) == c) for c in cols]
            body += _row([_cell(r)] + [_cell(str(k) if k else "·") for k in counts] + [_cell(str(sum(counts)), True)])
        totals = [sum(1 for n in reqs if _value(n, cf) == c) for c in cols]
        body += _row([_cell("total", True)] + [_cell(str(k), True) for k in totals] + [_cell(str(len(reqs)), True)])
        tgroup += body
        node.replace_self(table)


def check_consistency(app, env):
    for need in _requirements(app):
        nid, status = need["id"], need.get("status")
        code, test = bool(need.get("code_url")), bool(need.get("test_url"))
        problem = None
        if status in ("draft", "approved") and (code or test):
            problem = f"status '{status}' but code/test markers exist"
        elif status == "implemented" and (not code or test):
            problem = "status 'implemented' needs a code marker and no test marker yet"
        elif status == "verified":
            if not test or (not code and nid not in NO_CODE_OK):
                problem = "status 'verified' needs both a code marker and a test marker"
        if problem:
            logger.warning(f"{nid}: {problem}", location=(need.get("docname"), need.get("lineno")))


def write_matrix(app, exception):
    if exception or app.builder.format != "html":
        return
    out = Path(app.outdir) / "matrix.csv"
    cols = ["id", "title", "origin", "section", "level", "result_kind", "status", "release", "code_markers", "test_markers", "code", "tests"]
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for n in sorted(_requirements(app), key=lambda n: n["id"]):
            code, test = n.get("code_url") or [], n.get("test_url") or []
            w.writerow([n["id"], n["title"], n.get("origin") or "", n.get("section") or "", n.get("level") or "",
                        n.get("result_kind") or "", n.get("status") or "", n.get("release") or "",
                        len(code), len(test), " ".join(code), " ".join(test)])


def setup(app):
    app.add_node(needs_summary_placeholder)
    app.add_directive("needs-summary", NeedsSummary)
    app.connect("doctree-resolved", resolve_summaries)
    app.connect("env-check-consistency", check_consistency)
    app.connect("build-finished", write_matrix)
    return {"parallel_read_safe": False, "parallel_write_safe": False}
