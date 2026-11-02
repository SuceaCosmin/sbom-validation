"""Allow ``python -m sbom_validation``."""

from sbom_validation.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
