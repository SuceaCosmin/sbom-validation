"""Every BSI requirement need in the docs is claimed by a source marker."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


# @need-ids: REQ_TRACE_002
def test_every_bsi_requirement_has_a_marker():
    docs = (ROOT / "docs" / "requirements" / "bsi_tr_03183_2_v1_1.rst").read_text(encoding="utf-8")
    needed = set(re.findall(r":id:\s*(REQ_BSI11_\w+)", docs))
    assert needed
    claimed: set[str] = set()
    for source in (ROOT / "src").rglob("*.py"):
        for line in source.read_text(encoding="utf-8").splitlines():
            if "# @need-ids:" in line:
                claimed.update(re.findall(r"REQ_BSI11_\w+", line))
    assert needed - claimed == set()
