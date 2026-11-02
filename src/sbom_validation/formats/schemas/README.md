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
