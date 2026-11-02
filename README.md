# SBOM Validation

A Python project for validating Software Bill of Materials (SBOM) documents
against industry specifications. Requirements and their links to standards,
implementation, and tests are maintained with Sphinx and Sphinx-Needs.

## Initial scope

- SBOM formats: CycloneDX and SPDX.
- Initial standards reference: BSI TR-03183-2, Software Bill of Materials,
  version 2.1.0.
- Detailed format versions, serializations, and validation rules will be
  specified as traceable requirements before implementation.

The current repository establishes the package and requirements-documentation
foundation; validation behavior has not yet been implemented.
The checked-in `ubproject.toml` configures matching Sphinx-Needs artifacts
and ubCode Codelinks for source-level traceability.

## Development

Requires Python 3.11 or newer and Poetry.

```powershell
poetry install --with docs,test
poetry run pytest
poetry run sphinx-build -W -b html docs docs/_build/html
```

See [docs/requirements.rst](docs/requirements.rst) for the initial requirements
and standards references.
