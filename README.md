# SBOM Validation

A Python project for validating Software Bill of Materials (SBOM) documents
against industry specifications. Requirements and their links to standards,
implementation, and tests are maintained with Sphinx and Sphinx-Needs.

## Initial scope

- SBOM formats: CycloneDX (1.4 and higher) and SPDX 2.x (2.3 and higher) in
  JSON. SPDX 3.x is not supported yet and will follow with the newer BSI
  guideline version that requires it.
- First standard: BSI TR-03183-2, Software Bill of Materials, version 1.1.
  Later versions of the guideline will be added progressively.
- Requirements are maintained as traceable needs; the draft mapping from each
  BSI requirement to SBOM elements is in
  [docs/mappings/bsi-tr-03183-2-v1.1.md](docs/mappings/bsi-tr-03183-2-v1.1.md).

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
