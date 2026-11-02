# SBOM Validation: Design

Date: 2026-11-02
Status: draft, awaiting approval

Items marked **[Decided]** were decided by the project owner. Items marked
**[Call]** are the designer's own choices and are open to correction.

## 1. Intent and why

A team supported by the project owner falls under the EU Cyber Resilience Act
(CRA) and must produce SBOMs. They target compliance with the BSI technical
guideline TR-03183-2 (minimum SBOM elements) and asked how compliant the SBOMs
produced by a custom generator are. The owner's manual analysis answered that
once, on request, and does not scale.

This project is a systematic, repeatable SBOM validator that:

1. serves as a **quality gate** in CI, including release workflows;
2. serves SBOM **generator developers** as a benchmark for the SBOMs they
   produce;
3. produces a **detached, human-readable report** that people can use as a
   reference outside the CI and repository context.

Typical inputs are firmware and product-level SBOMs for automotive products,
in both SPDX and CycloneDX.

## 2. Goals

- G1. Validate one SBOM file against a user-selected standard and version.
- G2. First supported standard: BSI TR-03183-2 **v1.1** (2023-11-28), the first
  English version. Later versions follow progressively: 2.0.0, then 2.1.0.
  Later standards follow: NTIA minimum elements first.
- G3. Support both SPDX and CycloneDX, in the format versions each supported
  spec version allows.
- G4. Work fully offline, with no network access at run time, so it runs
  behind proxies. Schemas and rule data ship inside the package.
- G5. Run unattended in CI and signal the outcome through exit codes.
- G6. Emit console, JSON and standalone HTML reports.
- G7. Run on Windows and Linux.
- G8. Make adding a new standard or version a self-contained change that does
  not alter the core.

## 3. Non-goals

- N1. Generating SBOMs.
- N2. Validating more than one SBOM per run. Batch mode may come later and the
  design should not make it hard to add, but it is not built now. **[Decided]**
- N3. Container image distribution. Out of scope for now; do not make it hard
  to add later. **[Decided]**
- N4. German-language spec versions. Only English-language versions are
  supported, so BSI TR-03183-2 v1.0 (German only) is out. **[Decided]**
- N5. Vulnerability analysis, VEX or CSAF handling.
- N6. Fetching anything from the network at run time.
- N7. JUnit XML or other CI-specific report formats. Possibly later.

## 4. Anti-goals

A result that technically works but is a failure:

- Reporting recommended or optional elements as warnings or info. This spams
  users with no added value. **[Decided]**
- A gate that can never pass because everything is raised as an error.
- Any hidden network dependency that breaks behind a proxy.
- A report that differs between console, JSON and HTML in what it counts as a
  finding.

## 5. Constraints

- Python 3.11 or newer, Poetry, per the existing [pyproject.toml](../../../pyproject.toml).
  **[Decided]**
- Distributed as a Python package that CI runners can install. **[Decided]**
- Windows and Linux. No shell-specific behavior, careful path and encoding
  handling, tests that run on both. **[Decided]**
- Traceability follows the repository's existing Sphinx-Needs and ubCode setup
  (`req`, `spec`, `impl`, `test` needs and their links; see
  [ubproject.toml](../../../ubproject.toml)). Rules, code and tests link back
  to requirements.
- Standards' text is not redistributed beyond short rule descriptions and
  section references. **[Call]**

## 6. Behavior

### 6.1 Invocation **[Call]**

A command-line tool. The user supplies the SBOM path and selects the standard
and version, for example standard `bsi-tr-03183-2`, version `1.1`. Selecting
an unsupported version is a distinct, clearly reported error that names the
supported versions and how to request one. It does not prompt.

### 6.2 Input handling

1. Read the file and detect whether it is SPDX or CycloneDX, and which format
   version. **[Call]** Serializations to support: JSON for both; further
   serializations (XML, SPDX tag-value, YAML) are left to the builder to
   sequence, with JSON first.
2. Validate against the matching official schema, bundled offline.
3. Check that the format and version are accepted by the selected spec version
   (for BSI TR-03183-2 v1.1: CycloneDX 1.4 or higher, SPDX 2.3 or higher).
4. Run the spec version's rules.

An unreadable file, an unparseable file, or a file that fails schema validation
is an **error that stops the run** (no rule evaluation) with its own exit code.
**[Decided]**

### 6.3 What is reported

- Only **required** elements are evaluated and reported (the spec's MUST,
  SHALL, REQUIRED). Recommended and optional elements (SHOULD, MAY) are never
  reported, in any output. **[Decided]**
- An unmet required element is an **error**.
- A requirement that cannot be decided from the SBOM alone is reported as
  **not verifiable**, never as an error. **[Decided]** Examples from BSI
  TR-03183-2 v1.1: that the SBOM was created at build time, and that
  dependency resolution reached the first component outside the scope of
  delivery.
- Conditional requirements (MUST "if it exists and its prerequisites are
  fulfilled", such as SBOM URI, source code URI, source code hash): the tool
  cannot know whether the information should exist. **[Call]** When the field
  is present it is checked for correct form; when absent it is not an error
  and is not reported.
- Severity comes from the spec itself and is stored as data with each rule,
  not in code, so a new spec version brings its own levels.

### 6.4 Exit behavior **[Decided]** with codes as **[Call]**

There is a single behavior and no "warn" or "gate" modes. CI decides whether a
failing exit code blocks, for example by marking a development job as allowed
to fail and a release job as not.

Distinct exit codes, exact numbers left to the builder:

- success: no errors;
- non-compliant: at least one required element unmet;
- input problem: file missing, unreadable, unparseable, or schema-invalid;
- usage or configuration problem: bad arguments, unsupported standard or
  version, or an internal failure.

"Not verifiable" items never change the exit code.

### 6.5 Reports **[Decided]**

All outputs describe the same set of results.

- **Console:** short summary suitable for a CI log.
- **JSON:** machine-readable full result, for archiving and tooling.
- **HTML:** a single standalone file, openable outside CI and the repository,
  with sorting and filtering built in. No external scripts, fonts or links, so
  it works offline. It is a full checklist of **required** elements, one row
  per requirement, with: status (passed, failed, not verifiable), the SBOM
  element(s) examined, and the spec reference (document, version, section).

Whether the report shows a compliance percentage or count summary in addition
to rows is left to the builder; counts of passed, failed and not-verifiable
rows are enough. **[Call]**

## 7. Extensibility and structure

- A **standard plus version** is the unit the user selects. **[Decided]**
- Each standard version is a self-contained rule set, carrying its accepted
  formats and version ranges, its requirements with severity from the spec,
  and the mapping to SPDX and CycloneDX elements. Adding one does not change
  the core engine. **[Call]**
- Format support (SPDX, CycloneDX) is separate from standards support, so a
  rule is written once against a format-neutral view of the SBOM where
  possible. **[Call]**
- Single-file operation is the current scope, but the code should not assume
  it so strongly that batch mode requires a rewrite. **[Decided]** as a goal,
  mechanism left to the builder.

## 8. First rule set: BSI TR-03183-2 v1.1

Source: English PDF of v1.1, dated 2023-11-28 (listed in the BSI archive as
"Version 1.1 (outdated)"; the file name says v2_2_0 but the content is v1.1).
Read in full by the designer. Requirement IDs are to be assigned during
planning and must trace to section numbers below.

| Section | Requirement | Level | Machine-checkable |
| --- | --- | --- | --- |
| 4 | SBOM is CycloneDX 1.4 or higher, or SPDX 2.3 or higher | MUST | yes |
| 5.1 | Recursive dependency resolution at least up to and including the first component outside the scope of delivery | MUST | no (not verifiable) |
| 5.1 | SBOM created as part of the build process (Build SBOM) | MUST | no (not verifiable) |
| 5.2.1 | SBOM creator: an email address, or a URL if none is available | MUST | yes |
| 5.2.1 | Timestamp, as the format specifies | MUST | yes |
| 5.2.2 | Component creator: an email address, or a URL if none is available | MUST | yes |
| 5.2.2 | Component name | MUST | yes |
| 5.2.2 | Component version; Semantic or Calendar Versioning is a SHOULD and is therefore not reported | MUST (SHOULD for scheme) | yes |
| 5.2.2 | Dependencies: all components this one directly depends on | MUST | partly: the relationship data can be checked, completeness cannot |
| 5.2.2 | Licence as SPDX identifier or expression; `LicenseRef-scancode-` for IDs from the ScanCode LicenseDB; otherwise `LicenseRef-<entity>-` | MUST | yes for form; whether the licence is correct is not verifiable |
| 5.2.2 | SHA-256 hash of the executable component | MUST | yes |
| 5.3.1 | SBOM URI | MUST if it exists | form only, when present |
| 5.3.2 | Source code URI | MUST if it exists | form only, when present |
| 5.3.2 | URI of the executable form | MUST if it exists | form only, when present |
| 5.3.2 | SHA-256 of the source code | MUST if it exists | form only, when present |
| 5.3.2 | Other unique identifiers (CPE, purl) | MUST if it exists | form only, when present |
| 3.1 | A new, separate SBOM for each software version | MUST | no (not verifiable) |
| 3.2 | A component corresponds to a single executable file | MUST | no (not verifiable) |

The table is the designer's reading and is the starting point for requirement
authoring, not a substitute for it. The builder should re-read the source
sections when writing each requirement.

Known later versions to add progressively, with archive links as found on the
BSI page:

- v2.0.0 (2024-10-10, English) and v2.1.0 (2025-08-20, English). Their
  requirements have not been read. The later guideline sets CycloneDX 1.6 or
  higher and SPDX 3.0.1 or higher, per secondary sources. **[Not verified]**

## 9. Test strategy **[Call]**

There are no real sample SBOMs yet. Samples will be created during
implementation. For each rule, include a compliant sample and a sample with a
single known gap, so each rule is tested in isolation, in both SPDX and
CycloneDX. Also include samples for the input-problem paths (unreadable,
unparseable, schema-invalid) and for each exit code. Tests must pass on
Windows and Linux.

## 10. Left to the builder

- Internal architecture, module layout and parsing libraries, provided the
  tool works offline and on both platforms.
- Exact exit code numbers and CLI flag names.
- Report layout and styling details.
- The order in which serializations beyond JSON are supported.
- Requirement IDs and decomposition into traceable needs.
- How bundled schemas are sourced and refreshed; they must be pinned and
  shipped in the package.

## 11. Repository follow-ups

- [README.md](../../../README.md) names BSI TR-03183-2 v2.1.0 as the initial
  standards reference. Update it to say v1.1 first, with later versions to
  follow.

## 12. Further calls made after a builder review **[Call]**

All of these are the designer's choices and are open to correction.

- **Which components are checked.** Every component in the SBOM is checked,
  including the primary component. The guideline defines a component as a
  single executable file, so the SBOM is expected to list only such
  components, and the tool does not try to detect "executable" itself.
- **Aggregation.** The report has one row per requirement. A requirement fails
  if any component fails it, and the row lists each failing component and
  what was wrong. Alternatives inside one requirement (email or URL; SPDX ID,
  expression or LicenseRef) pass if any one is satisfied. Single-gap test
  samples follow from this.
- **Mappings to SPDX and CycloneDX.** The builder drafts the mapping for each
  rule from the source PDF and the owner reviews it before it is trusted. The
  v1.1 PDF is at
  `https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_2_0.pdf?__blob=publicationFile&v=9`
  (the file name says v2_2_0; the content is v1.1). The builder must obtain
  and read it.
- **"Form only" checks.** Valid URI syntax, a 64-character hexadecimal SHA-256,
  an RFC 3339 timestamp, valid purl and CPE syntax, and SPDX licence
  expressions validated against a pinned SPDX licence list bundled in the
  package.
- **Unsupported format version.** A schema-valid SBOM in a format version the
  spec does not accept (for example CycloneDX 1.3) is a failed row for the
  section 4 requirement and gives the non-compliant exit code. Rules that need
  the format are reported as not evaluated.
- **SPDX 3.x. [Decided]** The first release supports SPDX 2.x only (2.3 and
  any later 2.x version with a bundled schema). SPDX 3.0 support arrives later,
  together with the newer BSI TR version that requires it, and is not designed
  or built now. An SPDX 3.x file given to the first release is reported as a
  format the tool does not yet support, with the usage-or-configuration exit
  code, and not as a spec failure. **[Call]** for that last behavior. The
  supported CycloneDX versions are 1.4 up to the newest version the package
  bundles a schema for, with the exact list left to the builder.
- **Schema failures.** Per the decision in section 6.2 the run stops. The
  schema error details are reported in the console, JSON and HTML outputs, so
  the generator developer can see them.
- **Wording.** The report never calls an SBOM "compliant". It states how many
  required elements passed, failed and are not verifiable, and says that
  not-verifiable items need manual review.
- **Command line.** One run may write all three outputs; output paths are
  flags, with the console as the default. An internal failure has its own exit
  code, separate from usage or configuration problems.
- **Traceability.** One requirement need per row of the section 8 table, split
  further only where a row is not atomic. The documentation build's checks
  are the trace gate.
