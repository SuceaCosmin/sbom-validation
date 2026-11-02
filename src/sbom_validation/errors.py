"""Exceptions raised by the SBOM validator."""

NESTING_MESSAGE = "document is nested too deeply to process"


class SbomValidationError(Exception):
    """Base class carrying a user-facing message."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class InputProblem(SbomValidationError):
    """The SBOM input could not be read or parsed."""


class UnsupportedFormat(SbomValidationError):
    """The SBOM format or version is not supported."""


class UsageProblem(SbomValidationError):
    """The command line was used incorrectly."""
