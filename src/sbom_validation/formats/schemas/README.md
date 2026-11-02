# Bundled JSON schemas

These files are copies of the official schemas, downloaded once at development
time. The validator never fetches anything at run time: `$ref` targets resolve
through a local `referencing.Registry` built from these files (keyed by each
schema's `$id`).

| File | Version | Source URL | SHA-256 (first 16) |
|------|---------|------------|--------------------|
| `bom-1.4.schema.json` | CycloneDX 1.4 | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.4.schema.json | c22ea18d8ede3dba |
| `bom-1.5.schema.json` | CycloneDX 1.5 | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.5.schema.json | 2d956c1d05c09269 |
| `bom-1.6.schema.json` | CycloneDX 1.6 | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.schema.json | 18f57f7482593bad |
| `bom-1.7.schema.json` | CycloneDX 1.7 | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.7.schema.json | 73308edec3ab2d38 |
| `spdx.schema.json` | CycloneDX SPDX licence-id enum (referenced by all `bom-*`) | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/spdx.schema.json | 4b345e2329f209f3 |
| `jsf-0.82.schema.json` | JSON Signature Format 0.82 (referenced by all `bom-*`) | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/jsf-0.82.schema.json | 8bae002c25e723db |
| `cryptography-defs.schema.json` | CycloneDX cryptography definitions (referenced by `bom-1.7`) | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/cryptography-defs.schema.json | 013919cfb1c6209f |
| `spdx-schema-2.3.json` | SPDX 2.3 | https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json | 239208b7ac287b3c |

Downloaded 2026-11-02. The CycloneDX files come from the `master` branch of
github.com/CycloneDX/specification (the `schema/` directory); the SPDX file
comes from the `v2.3` tag of github.com/spdx/spdx-spec.

## Provenance

The exact master commit at download time was not recorded. Instead, the last
commit that modified each CycloneDX file was looked up through the GitHub API
and the file at that commit was confirmed byte-identical to the bundled copy:

| File | Last commit touching it (content identical to bundled copy) |
|------|--------------------------------------------------------------|
| `bom-1.4.schema.json`, `bom-1.5.schema.json` | 840bcd79c9a190ed51d1eda2db904abc85f78f32 |
| `bom-1.6.schema.json`, `bom-1.7.schema.json` | 0bd48c88d1b1877c7a3536252e06893850763190 |
| `spdx.schema.json` | fa52ed661ce4f768e131597dc4c3466114bc955b |
| `jsf-0.82.schema.json` | c874aa2a4360b986158e0db98e29b555f113e726 |
| `cryptography-defs.schema.json` | 463ad607417932279d87ff020d4a335e26abfcd9 |

## How to refresh

1. Download each file again from the URL in the table above (development time
   only; the validator itself never fetches). To add a CycloneDX version, add
   `bom-<version>.schema.json` and register it in `_SCHEMA_FILES` in
   `schemas.py`, and raise `NEWEST_CYCLONEDX` in `detect.py`.
2. Recompute the hashes, for example with Python:
   `hashlib.sha256(Path(name).read_bytes()).hexdigest()[:16]`, and update the
   table.
3. Re-run `poetry run pytest`, in particular `test_all_samples_are_schema_valid`
   and `test_all_bundled_cyclonedx_schemas_resolve`.

## Scope of validation

Validation is structural only: JSON Schema `format` keywords (for example
`date-time`, `uri`, `idn-email`) are intentionally not enforced.
