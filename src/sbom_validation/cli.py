"""Command-line interface."""

import argparse
import os
import sys
import traceback
from pathlib import Path
from typing import NoReturn

from sbom_validation.engine import run
from sbom_validation.errors import UnsupportedFormat, UsageProblem
from sbom_validation.render.console import render_console
from sbom_validation.render.html_report import render_html
from sbom_validation.render.json_report import render_json
from sbom_validation.results import ExitCode, exit_code_for
from sbom_validation.standards import supported

# @need-ids: REQ_CLI_001, REQ_OFFLINE_001, REQ_REPORT_001


class _UsageExit(Exception):
    """Raised by the parser instead of exiting, carrying the exit code."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


class _Parser(argparse.ArgumentParser):
    """Parser whose argument errors are USAGE (3), not argparse's 2."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        sys.stderr.write(f"Supported standard and version combinations: {_combinations()}.\n")
        raise _UsageExit(ExitCode.USAGE)

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        if message:
            sys.stderr.write(message)
        raise _UsageExit(status)


def _combinations() -> str:
    return ", ".join(
        f"{standard} {version}"
        for standard, versions in supported().items()
        for version in versions
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="sbom-validation",
        description="Validate an SBOM (CycloneDX or SPDX 2.x JSON) against a standard.",
        epilog=f"Supported standard and version combinations: {_combinations()}.",
    )
    parser.add_argument("sbom_path", metavar="SBOM_PATH", type=Path, help="SBOM file")
    parser.add_argument("--standard", required=True, help="standard to check against")
    parser.add_argument(
        "--standard-version", required=True, help="version of the standard"
    )
    parser.add_argument("--json", type=Path, metavar="PATH", help="write a JSON report")
    parser.add_argument("--html", type=Path, metavar="PATH", help="write an HTML report")
    return parser


def _error(message: str) -> None:
    sys.stderr.write(message + "\n")


def _write(path: Path, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def main(argv: list[str] | None = None) -> int:
    """Run the validator; return the process exit code."""
    try:
        args = _build_parser().parse_args(argv)
    except _UsageExit as exc:
        return exc.code

    outputs = [(opt, p) for opt, p in (("--json", args.json), ("--html", args.html)) if p]
    for option, path in outputs:
        parent = path.parent
        if not parent.is_dir():
            _error(f"{option}: output directory does not exist: {parent}")
            return ExitCode.USAGE

    try:
        report = run(args.sbom_path, args.standard, args.standard_version)
    except UsageProblem as exc:
        _error(exc.message)
        return ExitCode.USAGE
    except UnsupportedFormat as exc:
        _error(exc.message)
        return ExitCode.USAGE
    except Exception as exc:  # noqa: BLE001 - last-resort boundary
        if os.environ.get("SBOM_VALIDATION_DEBUG"):
            traceback.print_exc()
        _error(f"internal error: {type(exc).__name__}: {exc}")
        return ExitCode.INTERNAL

    try:
        sys.stdout.write(render_console(report))
        sys.stdout.flush()
        renderers = {"--json": render_json, "--html": render_html}
        for option, path in outputs:
            try:
                _write(path, renderers[option](report))
            except OSError as exc:
                _error(f"{option}: cannot write {path}: {exc.strerror or exc}")
                return ExitCode.USAGE
    except Exception as exc:  # noqa: BLE001 - last-resort boundary
        if os.environ.get("SBOM_VALIDATION_DEBUG"):
            traceback.print_exc()
        _error(f"internal error: {type(exc).__name__}: {exc}")
        return ExitCode.INTERNAL
    return exit_code_for(report)
