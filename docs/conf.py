"""Sphinx configuration.

Need types, links, statuses and fields live in ``ubproject.toml`` (the single
source of truth shared with ubCode); do not duplicate them here.
"""

project = "SBOM Validation"
author = "SBOM Validation contributors"
copyright = "2026, SBOM Validation contributors"

import os
import sys

sys.path.insert(0, os.path.abspath("_ext"))

extensions = ["sphinx_needs", "sphinx_codelinks", "needs_dashboard"]

root_doc = "index"
exclude_patterns = ["_build", "superpowers", "kb", "_includes"]



def evidence_summary(app, need, needs, *args, **kwargs):
    """Dynamic function: "<n> code · <m> tests" from the codelinks URL fields."""
    code = need.get("code_url") or []
    tests = need.get("test_url") or []
    return f"{len(code)} code · {len(tests)} tests"



def setup(app):
    from sphinx_needs.api import add_dynamic_function

    add_dynamic_function(app, evidence_summary)


# Cards start collapsed: the header keeps type, title, ID, status and level;
# the arrow expands the remaining fields (origin, result kind, evidence, links).
needs_layouts = {
    "sbom_collapsed": {
        "grid": "simple",
        "layout": {
            "head": [
                '<<meta("type_name")>>: **<<meta("title")>>** <<meta_id()>> '
                '<<meta("status")>> <<meta("level")>> '
                '<<collapse_button("meta", collapsed="icon:arrow-down-circle", '
                'visible="icon:arrow-right-circle", initial=True)>> '
            ],
            "meta": ["<<meta_all(no_links=True)>>", "<<meta_links_all()>>"],
        },
    }
}
needs_default_layout = "sbom_collapsed"

needs_from_toml = "../ubproject.toml"
src_trace_config_from_toml = "../ubproject.toml"

html_theme = "furo"
html_title = "SBOM Validation"
html_static_path = ["_static"]
html_css_files = ["needs-theme.css"]
html_js_files = ["expand-all.js"]
