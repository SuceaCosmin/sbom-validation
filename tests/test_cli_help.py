"""The exit codes are documented in --help and the README."""

from pathlib import Path

from sbom_validation.cli import main

MEANINGS = {
    "0": "no requirement failed",
    "1": "at least one requirement failed",
    "2": "input problem",
    "3": "usage",
    "4": "internal error",
}


def test_help_output_has_exit_code_table(capsys):
    assert main(["--help"]) == 0
    out = capsys.readouterr().out
    assert "Exit codes" in out
    for code, meaning in MEANINGS.items():
        line = next((l for l in out.splitlines() if l.strip().startswith(code + " ")), None)
        assert line is not None, f"exit code {code} missing from --help"
        assert meaning in line


def test_readme_documents_exit_codes():
    readme = (Path(__file__).parent.parent / "README.md").read_text(encoding="utf-8")
    assert "validation behavior has not yet been implemented" not in readme
    for code, meaning in MEANINGS.items():
        assert f"| {code} |" in readme
        assert meaning in readme
    assert "compliant" not in readme.lower()
