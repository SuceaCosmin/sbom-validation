project = "SBOM Validation"
author = "SBOM Validation contributors"
copyright = "2026, SBOM Validation contributors"

extensions = ["sphinx_needs"]
root_doc = "index"
exclude_patterns = ["_build"]

needs_types = [
    {
        "directive": "req",
        "title": "Requirement",
        "prefix": "REQ_",
        "color": "#BFD8D2",
        "style": "node",
    },
    {
        "directive": "spec",
        "title": "Specification",
        "prefix": "SPEC_",
        "color": "#FEDCD2",
        "style": "node",
    },
    {
        "directive": "impl",
        "title": "Implementation",
        "prefix": "IMPL_",
        "color": "#DF744A",
        "style": "node",
    },
    {
        "directive": "test",
        "title": "Test Case",
        "prefix": "TEST_",
        "color": "#DCB239",
        "style": "node",
    },
]

needs_id_required = True
needs_id_regex = r"^[A-Z0-9_]{5,}$"

needs_links = {
    "references": {
        "incoming": "is referenced by",
        "outgoing": "references",
    },
    "derived_from": {
        "incoming": "is derived from",
        "outgoing": "derives",
    },
    "implements": {
        "incoming": "is implemented by",
        "outgoing": "implements",
    },
    "verifies": {
        "incoming": "is verified by",
        "outgoing": "verifies",
    },
}
