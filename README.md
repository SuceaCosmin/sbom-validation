# SBOM Validation

A Python command-line tool that checks a Software Bill of Materials (SBOM)
against a published standard and reports which requirements are met, which
fail, and which cannot be decided from the SBOM alone. Requirements and their
links to standards, implementation, and tests are maintained with Sphinx and
Sphinx-Needs.

## Scope

- SBOM formats: CycloneDX (1.4 and higher) and SPDX 2.x (2.3 and higher), JSON
  only. SPDX 3.x is not supported yet and is deferred to the newer BSI
  guideline version that requires it.
- Standard: BSI TR-03183-2, Software Bill of Materials, version 1.1
  (`--standard bsi-tr-03183-2 --standard-version 1.1`). Later versions of the
  guideline will be added progressively.
- Fully offline: the official CycloneDX and SPDX JSON schemas are bundled and
  nothing is fetched at run time.
- Requirements that cannot be decided from the SBOM alone are reported as
  "not verifiable" for manual review; they never change the exit code.
- The draft mapping from each BSI requirement to SBOM elements is in
  [docs/mappings/bsi-tr-03183-2-v1.1.md](docs/mappings/bsi-tr-03183-2-v1.1.md).

The checked-in `ubproject.toml` configures matching Sphinx-Needs artifacts
and ubCode Codelinks for source-level traceability.

## Usage

```powershell
poetry install
poetry run sbom-validation sbom.cdx.json --standard bsi-tr-03183-2 --standard-version 1.1 --json report.json --html report.html
```

Outputs:

- Console: always printed to standard output; a short ASCII summary with the
  failed requirements and their first findings.
- `--json PATH`: a machine-readable report with every requirement row.
- `--html PATH`: a standalone HTML report.

Run `sbom-validation --help` for all options.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | OK: no requirement failed |
| 1 | at least one requirement failed |
| 2 | input problem: the SBOM could not be read, parsed or schema-validated |
| 3 | usage, configuration or unsupported-format error |
| 4 | internal error |

### Use in CI

The tool has a single behaviour and the CI job decides what an exit code
means. For example, run it in a development job that is marked
allowed-to-fail, so findings stay visible without stopping the pipeline, and
run the same command in a release job that blocks on any non-zero exit code.

## Development

Requires Python 3.11 or newer and Poetry.

```powershell
poetry install --with docs,test
poetry run pytest
poetry run sphinx-build -W -b html docs docs/_build/html
```

See [docs/requirements.rst](docs/requirements.rst) for the initial requirements
and standards references.
