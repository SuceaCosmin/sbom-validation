# SBOM Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A command-line tool that validates one SPDX 2.x or CycloneDX SBOM against BSI TR-03183-2 v1.1 and reports console, JSON and standalone HTML results with CI-usable exit codes.

**Architecture:** A format layer loads and schema-validates an SBOM and converts it to a format-neutral model. A standards layer holds self-contained rule sets (standard plus version) whose rules run against that model. An engine runs the pipeline and builds one `Report`, and three renderers plus a CLI present it. Adding a standard version means adding one rule-set module and its requirements, with no engine change.

**Tech Stack:** Python >=3.11, Poetry, pytest, `jsonschema` (with `referencing`, for offline `$ref` resolution), `license-expression` (bundled SPDX licence list), `packageurl-python`. HTML is generated with the standard library only.

**Spec:** [docs/superpowers/specs/2026-11-02-sbom-validation-design.md](../specs/2026-11-02-sbom-validation-design.md)

## Global Constraints

- Python 3.11 or newer; Poetry; package `sbom_validation` under `src/`.
- Windows and Linux: no shell-specific code, `pathlib` for paths, files opened with explicit UTF-8 (accept a UTF-8 BOM on input), tests pass on both.
- Fully offline at run time: schemas, the SPDX licence list and all rule data ship in the package; no network calls anywhere.
- One SBOM file per run; JSON serialization only in the first release (other serializations are later work).
- First release: BSI TR-03183-2 v1.1 (2023-11-28), SPDX 2.x (2.3 or higher 2.x with a bundled schema), CycloneDX 1.4 up to the newest bundled schema. SPDX 3.x input is reported as an unsupported format with the usage exit code.
- Only MUST-level elements are ever evaluated or reported; SHOULD/MAY are never reported in any output.
- Undecidable requirements are `NOT_VERIFIABLE`, never errors, and never change the exit code.
- The report never uses the word "compliant"; it states passed, failed and not-verifiable counts.
- One behavior, no modes: any failed requirement gives a non-zero exit code.
- Every rule traces to a `req` need (`:references:` the BSI spec need, section cited); code and tests link to it with `# @need-ids:` markers (Python) as described in `docs/requirements.rst`.
- Exit codes: `0` ok, `1` non-compliant, `2` input problem (missing, unreadable, unparseable, schema-invalid), `3` usage/configuration/unsupported standard, version or format, `4` internal failure.

## Review Focus

Failure modes the spec implies but no rule's own tests cover:

- Firmware-scale SBOM (tens of thousands of components) must validate in seconds and must not recurse deeply on the dependency graph.
- An SBOM with zero components, or components with no relationship data at all, must produce clear rows, not a crash or a vacuous pass.
- A UTF-8 file with a BOM, and Windows paths with spaces and non-ASCII characters, for both input and report output paths.
- Report output into a directory that does not exist or is not writable must give a usage-style error, not a traceback.
- Hashes in lowercase or uppercase, licence values `NOASSERTION`/`NONE`, and duplicated component references must not produce false passes or crashes.

Each is pinned by a test named in the task that owns the code (tasks 3, 4, 7, 10, 11).

---

## File Structure

```
src/sbom_validation/
  results.py            Status, Finding, RequirementResult, Report, ExitCode
  errors.py             InputProblem, UnsupportedFormat, UsageProblem
  model.py              Party, Component, Sbom (format-neutral)
  formats/
    __init__.py         load_sbom(path) -> Sbom
    detect.py           detect_format(data) -> FormatInfo
    schemas.py          validate_schema(data, info) -> None (raises InputProblem)
    cyclonedx.py        to_model(data) -> Sbom
    spdx2.py            to_model(data) -> Sbom
    schemas/            bundled JSON schemas (package data)
  checks.py             form checks (email/URL, sha256, timestamp, URI, purl, cpe, licence)
  standards/
    __init__.py         get_rule_set(standard, version), supported()
    base.py             Rule, RuleSet
    bsi_tr_03183_2/v1_1.py
  engine.py             run(path, standard, version) -> Report
  render/ console.py, json_report.py, html_report.py
  cli.py                main(argv) -> int
docs/mappings/bsi-tr-03183-2-v1.1.md   owner-reviewed element mapping
docs/requirements.rst                  updated baseline + BSI v1.1 requirements
tests/ (mirrors src/) and tests/samples/
.github/workflows/ci.yml
```

---

### Task 1: Requirements baseline and project setup

**Files:**
- Modify: `README.md`, `docs/requirements.rst`, `pyproject.toml`
- Create: `docs/mappings/bsi-tr-03183-2-v1.1.md`, `.github/workflows/ci.yml`

**Interfaces:**
- Produces: need IDs used by every later task via `# @need-ids:`; console script `sbom-validation = sbom_validation.cli:main`.

- [ ] **Step 1:** In `docs/requirements.rst` replace the v2.1.0 BSI spec need with `SPEC_BSI_TR03183_2_V1_1` (v1.1, URL from design doc section 12), keep `SPEC_BSI_TR03183_2` out, replace the SPDX 3.0.1 and CycloneDX 1.7 spec needs with `SPEC_SPDX_2_3` and `SPEC_CYCLONEDX_1_4`, and update the existing `REQ_FMT_001`/`REQ_TRACE_001` `:references:`.
- [ ] **Step 2:** Add one `req` per design section 8 row, `:references: SPEC_BSI_TR03183_2_V1_1`, title stating the section, IDs: `REQ_BSI11_FORMATS`, `REQ_BSI11_DEPTH`, `REQ_BSI11_BUILD`, `REQ_BSI11_SBOM_CREATOR`, `REQ_BSI11_TIMESTAMP`, `REQ_BSI11_CMP_CREATOR`, `REQ_BSI11_CMP_NAME`, `REQ_BSI11_CMP_VERSION`, `REQ_BSI11_CMP_DEPS`, `REQ_BSI11_CMP_LICENCE`, `REQ_BSI11_CMP_HASH`, `REQ_BSI11_SBOM_URI`, `REQ_BSI11_SRC_URI`, `REQ_BSI11_EXE_URI`, `REQ_BSI11_SRC_HASH`, `REQ_BSI11_OTHER_IDS`, `REQ_BSI11_ONE_PER_VERSION`, `REQ_BSI11_COMPONENT_EXEC`. Also add product-level needs for the tool: `REQ_CLI_001` (exit codes), `REQ_OFFLINE_001`, `REQ_REPORT_001` (console/JSON/HTML), `REQ_SEVERITY_001` (MUST-only reporting). Each body is a single "shall" sentence.
- [ ] **Step 3:** Write `docs/mappings/bsi-tr-03183-2-v1.1.md`: per requirement ID, the CycloneDX and SPDX 2.x element(s) examined (JSON paths), read from the v1.1 PDF. Mark it `Status: awaiting owner review`. Tasks 3, 4 and 7 implement exactly this mapping; **stop and get the owner's approval of this file before Task 3.**
- [ ] **Step 4:** In `pyproject.toml` add runtime dependencies `jsonschema`, `license-expression`, `packageurl-python`, the `[project.scripts]` entry `sbom-validation = "sbom_validation.cli:main"`, and package-data inclusion for `formats/schemas/*.json`. Run `poetry lock` and `poetry install --with docs,test`.
- [ ] **Step 5:** Fix `README.md` (BSI v1.1 first, later versions to follow, SPDX 2.x first). Add `.github/workflows/ci.yml` running `poetry run pytest` and the Sphinx build on `ubuntu-latest` and `windows-latest`.
- [ ] **Step 6:** Run `poetry run sphinx-build -W -b html docs docs/_build/html`. Expected: succeeds with no warnings.
- [ ] **Step 7:** Commit `docs: BSI v1.1 requirements baseline and project setup`.

---

### Task 2: Result model and exit codes

**Files:**
- Create: `src/sbom_validation/results.py`, `src/sbom_validation/errors.py`, `tests/test_results.py`

**Interfaces:**
- Produces:
  - `class Status(str, Enum)`: `PASSED`, `FAILED`, `NOT_VERIFIABLE`, `NOT_EVALUATED`.
  - `@dataclass(frozen=True) Finding(component_ref: str | None, message: str)`.
  - `@dataclass(frozen=True) RequirementResult(id: str, title: str, section: str, status: Status, examined: str, findings: tuple[Finding, ...] = ())`.
  - `@dataclass(frozen=True) Report(standard: str, version: str, sbom_path: str, sbom_format: str | None, sbom_format_version: str | None, results: tuple[RequirementResult, ...], problem: str | None = None)`; method `counts() -> dict[Status, int]`.
  - `class ExitCode(IntEnum)`: `OK=0, NON_COMPLIANT=1, INPUT_PROBLEM=2, USAGE=3, INTERNAL=4`; function `exit_code_for(report: Report) -> ExitCode`.
  - Exceptions `InputProblem`, `UnsupportedFormat`, `UsageProblem`, each carrying `message: str`.

- [ ] **Step 1:** Write tests: `test_not_verifiable_never_changes_exit_code` (report with only `NOT_VERIFIABLE`/`PASSED` → `OK`), `test_any_failed_is_non_compliant`, `test_problem_report_is_input_problem` (report with `problem` set → `INPUT_PROBLEM`), `test_counts_cover_all_statuses`.
- [ ] **Step 2:** Run `poetry run pytest tests/test_results.py -v`. Expected: FAIL (module missing).
- [ ] **Step 3:** Implement as specified.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Commit `feat: result model and exit codes`.

---

### Task 3: Neutral model and CycloneDX loader

**Files:**
- Create: `src/sbom_validation/model.py`, `src/sbom_validation/formats/cyclonedx.py`, `tests/test_cyclonedx_loader.py`, `tests/samples/cyclonedx/` (compliant sample)

**Interfaces:**
- Produces in `model.py`: `Party(name: str | None, email: str | None, url: str | None)`; `Component(ref: str, name: str | None, version: str | None, creators: tuple[Party, ...], licenses: tuple[str, ...], sha256: str | None, hashes: tuple[tuple[str, str], ...], dependencies: tuple[str, ...] | None, source_uri: str | None, executable_uri: str | None, source_sha256: str | None, identifiers: tuple[str, ...], is_primary: bool)`; `Sbom(format: str, spec_version: str, creators: tuple[Party, ...], timestamp: str | None, uri: str | None, components: tuple[Component, ...])`. `dependencies=None` means the SBOM carries no relationship data for that component; an empty tuple means it explicitly has none.
- Produces in `cyclonedx.py`: `to_model(data: dict) -> Sbom`, following the approved mapping file. Primary component is `metadata.component`; nested components are flattened.

- [ ] **Step 1:** Write tests against a compliant sample: `test_maps_primary_and_nested_components`, `test_hash_is_normalised_lowercase`, `test_missing_dependency_graph_gives_none`, `test_zero_components`, `test_duplicate_bom_refs_do_not_crash`, `test_license_noassertion_is_kept_verbatim`.
- [ ] **Step 2:** Run; expected FAIL.
- [ ] **Step 3:** Implement `to_model` iteratively (explicit stack, no recursion) so deep nesting is safe.
- [ ] **Step 4:** Run; expected PASS.
- [ ] **Step 5:** Commit `feat: neutral model and CycloneDX loader`.

---

### Task 4: SPDX 2.x loader

**Files:**
- Create: `src/sbom_validation/formats/spdx2.py`, `tests/test_spdx2_loader.py`, `tests/samples/spdx2/`

**Interfaces:**
- Consumes: `model.Sbom`, `model.Component`, `model.Party`.
- Produces: `to_model(data: dict) -> Sbom`, per the approved mapping. Packages become components; the package named by `documentDescribes`/`DESCRIBES` is `is_primary`; dependencies come from `DEPENDS_ON`/`DEPENDENCY_OF` relationships; if no relationships exist at all, `dependencies` is `None`.

- [ ] **Step 1:** Write tests: `test_packages_become_components`, `test_dependency_relationships_both_directions`, `test_no_relationships_gives_none`, `test_checksums_normalised_lowercase`, `test_noassertion_and_none_kept_verbatim`, `test_zero_packages`.
- [ ] **Step 2:** Run; expected FAIL. **Step 3:** Implement. **Step 4:** Run; expected PASS.
- [ ] **Step 5:** Commit `feat: SPDX 2.x loader`.

---

### Task 5: Format detection and offline schema validation

**Files:**
- Create: `src/sbom_validation/formats/detect.py`, `schemas.py`, `__init__.py`, `formats/schemas/*.json`, `tests/test_formats.py`

**Interfaces:**
- Produces: `FormatInfo(format: str, version: str)`; `detect_format(data: dict) -> FormatInfo` (raises `InputProblem` if neither format; raises `UnsupportedFormat` for SPDX 3.x or a version with no bundled schema); `validate_schema(data: dict, info: FormatInfo) -> None` (raises `InputProblem` with all schema error paths and messages); `load_sbom(path: Path) -> tuple[Sbom, FormatInfo]` (reads UTF-8 with or without BOM, JSON only).
- Bundled schemas: CycloneDX 1.4, 1.5, 1.6 (with their referenced `spdx.schema.json` and `jsf-0.82.schema.json`) and SPDX 2.3, taken from the official repositories with their source URL and version recorded in `formats/schemas/README.md`. References resolve through a local `referencing.Registry`; the validator never fetches.

- [ ] **Step 1:** Write tests: `test_detects_cyclonedx_and_spdx2`, `test_spdx3_is_unsupported_format`, `test_unknown_document_is_input_problem`, `test_utf8_bom_file_loads`, `test_missing_file_is_input_problem`, `test_invalid_json_is_input_problem`, `test_schema_failure_lists_paths`, `test_validation_makes_no_network_call` (monkeypatch `socket.socket` to raise).
- [ ] **Step 2:** Run; expected FAIL. **Step 3:** Implement. **Step 4:** Run; expected PASS.
- [ ] **Step 5:** Commit `feat: format detection and offline schema validation`.

---

### Task 6: Form checks

**Files:**
- Create: `src/sbom_validation/checks.py`, `tests/test_checks.py`

**Interfaces:**
- Produces, all `-> bool`: `is_email(s: str)`, `is_url(s: str)`, `is_uri(s: str)`, `is_sha256(s: str)` (64 hex, either case), `is_rfc3339(s: str)`, `is_purl(s: str)`, `is_cpe(s: str)`, `is_spdx_licence_expression(s: str)`. Licence check uses `license-expression` with its bundled SPDX list and accepts `LicenseRef-scancode-*` and `LicenseRef-<entity>-*`; it rejects `NOASSERTION` and `NONE`.

- [ ] **Step 1:** Write parametrised tests with exact values: `is_sha256("a"*64)` true, 63 chars false, non-hex false; `is_rfc3339("2023-11-28T10:00:00Z")` true, `"2023-11-28"` false; `is_spdx_licence_expression("MIT OR Apache-2.0")` true, `"MIT WITH Classpath-exception-2.0"` true, `"LicenseRef-scancode-foo"` true, `"LicenseRef-acme-1"` true, `"NOASSERTION"` false, `"Proprietary"` false; `is_purl("pkg:npm/foo@1.0.0")` true, `"foo"` false; `is_email("a@b.co")` true, `"a@"` false; `is_url("https://x.org/a")` true, `"x.org"` false.
- [ ] **Step 2:** Run; expected FAIL. **Step 3:** Implement. **Step 4:** Run; expected PASS.
- [ ] **Step 5:** Commit `feat: form checks`.

---

### Task 7: Rule framework and BSI TR-03183-2 v1.1 rule set

**Files:**
- Create: `src/sbom_validation/standards/base.py`, `standards/__init__.py`, `standards/bsi_tr_03183_2/__init__.py`, `standards/bsi_tr_03183_2/v1_1.py`, `tests/test_bsi_v1_1.py`, per-rule samples in `tests/samples/{cyclonedx,spdx2}/bsi_v1_1/`

**Interfaces:**
- Consumes: `model.*`, `checks.*`, `results.*`.
- Produces:
  - `@dataclass(frozen=True) Rule(id: str, title: str, section: str, check: Callable[[Sbom], RequirementResult] | None)`; `check=None` means the rule is always `NOT_VERIFIABLE`.
  - `@dataclass(frozen=True) RuleSet(standard: str, version: str, accepts: Callable[[FormatInfo], bool], rules: tuple[Rule, ...])`.
  - `get_rule_set(standard: str, version: str) -> RuleSet` (raises `UsageProblem` naming supported combinations); `supported() -> dict[str, tuple[str, ...]]`.
  - `v1_1.RULE_SET`: one `Rule` per `REQ_BSI11_*` ID from Task 1, `accepts` true for CycloneDX >=1.4 and SPDX 2.x >=2.3.
- Semantics (design section 6.3 and 12): every component is checked including the primary; a requirement fails if any component fails and lists each failing component; alternatives pass if any one holds; conditional requirements (`SBOM_URI`, `SRC_URI`, `EXE_URI`, `SRC_HASH`, `OTHER_IDS`) fail only when a present value is malformed and are `PASSED` with `examined` noting "none present" otherwise; `CMP_DEPS` fails for a component whose `dependencies` is `None`; `DEPTH`, `BUILD`, `ONE_PER_VERSION`, `COMPONENT_EXEC` are `NOT_VERIFIABLE`.

- [ ] **Step 1:** For every machine-checkable rule write a pair of tests, `test_<rule>_passes_on_compliant` and `test_<rule>_fails_on_single_gap`, each over both formats, using samples that differ by exactly one gap. Plus: `test_failing_components_are_listed` (100 components, 3 without a name → one row, 3 findings), `test_empty_components_is_not_a_vacuous_pass` (`CMP_*` rules `FAILED` with message "no components"), `test_noassertion_licence_fails`, `test_uppercase_hash_passes`, `test_unsupported_version_is_a_failed_formats_row` (CycloneDX 1.3 data through `accepts`), `test_unknown_version_raises_usage_problem`, `test_not_verifiable_rules_never_fail`.
- [ ] **Step 2:** Run; expected FAIL. **Step 3:** Implement base types, the registry and `v1_1`. **Step 4:** Run; expected PASS.
- [ ] **Step 5:** Commit `feat: BSI TR-03183-2 v1.1 rule set`.

---

### Task 8: Engine

**Files:**
- Create: `src/sbom_validation/engine.py`, `tests/test_engine.py`

**Interfaces:**
- Consumes: `formats.load_sbom`, `standards.get_rule_set`, `results.*`.
- Produces: `run(path: Path, standard: str, version: str) -> Report`. Pipeline: resolve rule set (`UsageProblem` propagates) → load and schema-validate (`InputProblem` becomes `Report.problem`, no results; `UnsupportedFormat` propagates) → if `accepts` is false, results are the `FORMATS` row `FAILED` and all other rules `NOT_EVALUATED` → otherwise run all rules.

- [ ] **Step 1:** Write tests: `test_compliant_sample_has_no_failed_rows`, `test_schema_invalid_gives_problem_and_no_results`, `test_cyclonedx_1_3_fails_formats_and_skips_others`, `test_spdx3_raises_unsupported_format`, `test_results_follow_rule_set_order`, `test_large_sbom_runs_quickly` (generate 20,000 components; assert completes under 10 seconds).
- [ ] **Step 2:** Run; expected FAIL. **Step 3:** Implement. **Step 4:** Run; expected PASS.
- [ ] **Step 5:** Commit `feat: validation engine`.

---

### Task 9: Console and JSON reports

**Files:**
- Create: `src/sbom_validation/render/console.py`, `render/json_report.py`, `tests/test_render_text.py`

**Interfaces:**
- Produces: `render_console(report: Report) -> str`; `render_json(report: Report) -> str` (UTF-8-safe, `schema_version` field first, then standard, version, sbom, counts, results, problem).

- [ ] **Step 1:** Write tests: `test_console_lists_failed_rows_and_counts`, `test_console_never_says_compliant` (assert `"compliant" not in output.lower()`), `test_console_notes_manual_review_for_not_verifiable`, `test_json_round_trips_all_results`, `test_json_and_console_agree_on_counts`, `test_problem_report_shows_schema_error_details`.
- [ ] **Step 2:** Run; expected FAIL. **Step 3:** Implement. **Step 4:** Run; expected PASS.
- [ ] **Step 5:** Commit `feat: console and JSON reports`.

---

### Task 10: HTML report

**Files:**
- Create: `src/sbom_validation/render/html_report.py`, `tests/test_render_html.py`

**Interfaces:**
- Produces: `render_html(report: Report) -> str`. One standalone document: inline CSS and JavaScript, a table with one row per requirement (status, requirement ID, title, spec section, element examined, failing-component details expandable), click-to-sort columns and a status filter, counts at the top, the manual-review note, and the schema error list when `problem` is set. All values HTML-escaped.

- [ ] **Step 1:** Write tests: `test_has_no_external_references` (no `http://` or `https://` in `src=`, `href=` or CSS `url(`; spec URLs appear only as text), `test_one_row_per_requirement`, `test_values_are_escaped` (component name `<script>` appears escaped), `test_contains_sort_and_filter_controls`, `test_html_and_json_agree_on_counts`, `test_problem_report_renders_errors`.
- [ ] **Step 2:** Run; expected FAIL. **Step 3:** Implement with string templating. **Step 4:** Run; expected PASS.
- [ ] **Step 5:** Commit `feat: standalone HTML report`.

---

### Task 11: CLI and end-to-end

**Files:**
- Create: `src/sbom_validation/cli.py`, `tests/test_cli.py`

**Interfaces:**
- Consumes: `engine.run`, `render.*`, `results.exit_code_for`, `standards.supported`.
- Produces: `main(argv: list[str] | None = None) -> int`. Usage: `sbom-validation SBOM_PATH --standard bsi-tr-03183-2 --standard-version 1.1 [--json PATH] [--html PATH]`; console always printed. Any `UsageProblem` or `UnsupportedFormat` prints one clear line (naming supported versions and how to request one) and returns `ExitCode.USAGE`; any other exception returns `ExitCode.INTERNAL` with a one-line message. Output directories are not created; a missing or unwritable one is `USAGE`.

- [ ] **Step 1:** Write tests (call `main` directly, plus one `subprocess` test of `python -m`-equivalent entry): `test_compliant_returns_0`, `test_single_gap_returns_1`, `test_schema_invalid_returns_2`, `test_missing_file_returns_2`, `test_unknown_version_returns_3_and_lists_supported`, `test_spdx3_returns_3`, `test_unwritable_output_dir_returns_3`, `test_path_with_spaces_and_unicode`, `test_all_three_outputs_in_one_run`, `test_no_network` (socket patched to raise).
- [ ] **Step 2:** Run; expected FAIL. **Step 3:** Implement with `argparse`. **Step 4:** Run `poetry run pytest -v`; expected all PASS.
- [ ] **Step 5:** Run `poetry run sphinx-build -W -b html docs docs/_build/html`; expected no warnings. Confirm every `REQ_BSI11_*` has an `# @need-ids:` marker in `v1_1.py` and a `verifies` link from a test need in docs.
- [ ] **Step 6:** Commit `feat: command-line interface`.

---

## Self-Review

- **Spec coverage:** G1 → tasks 8, 11; G2 → 7; G3 → 3, 4, 5; G4 → 5, 6, 11 (no-network tests); G5 → 2, 11; G6 → 9, 10; G7 → 1 (CI matrix), 3, 5, 11; G8 → 7 (rule set is self-contained). Section 6.2 pipeline → 5, 8; 6.3 → 7; 6.4 → 2, 11; 6.5 → 9, 10; section 12 calls → 7, 8, 9, 11; SPDX 3.x deferral → 5, 11; README follow-up → 1. Non-goals (batch, container, JUnit, German versions, network) have no tasks, by design.
- **Open dependency:** the owner must approve `docs/mappings/bsi-tr-03183-2-v1.1.md` (Task 1, Step 3) before Task 3.
- **Proportion:** the plan states signatures, semantics and test names; bodies are left to the implementer.
