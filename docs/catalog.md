[← Patchwatch](../README.md)

# Vulnerability catalog

The editable source is [`src/patchwatch/data/catalog.json`](../src/patchwatch/data/catalog.json). CI validates it against [the schema](../src/patchwatch/data/schema.json) and checks fix/version consistency.

```sh
# Follow reviewed updates on main. This trusts this repository's maintainers.
patchwatch catalog sync --url \
  https://raw.githubusercontent.com/BennettSchwartz/patchwatch/main/src/patchwatch/data/catalog.json

# Or pin an independently reviewed commit and SHA-256.
patchwatch catalog sync --url https://raw.githubusercontent.com/OWNER/REPO/COMMIT/catalog.json \
  --sha256 EXPECTED_SHA256

# Work on your own catalog.
patchwatch catalog export ./catalog.json
patchwatch catalog validate ./catalog.json
patchwatch scan --catalog ./catalog.json --root ~/projects
```

An invalid or checksum-mismatched download leaves the prior catalog untouched. A pinned checksum intentionally prevents automatic adoption of different catalog contents. Failed synchronization stops that monitoring cycle; it is not treated as a clean scan. Catalog timestamps and hashes are included in reports.

A rule for an unfamiliar tool can still describe remediation:

```json
{
  "id": "EXAMPLE-2026-001",
  "summary": "Example only; replace with a real advisory",
  "severity": "high",
  "references": ["https://example.com/security/advisory"],
  "affected": [{
    "ecosystem": "Tool",
    "package": "example-cli",
    "versions": ">=1.0,<1.4.2",
    "fixed": "1.4.2",
    "command": ["example-cli", "self", "update", "--version", "1.4.2"],
    "instructions": "Update the tool, then run example-cli --version."
  }]
}
```

Add it to the catalog's `advisories` array. For tools without a detector, supply the observed version:

```sh
patchwatch plan --catalog ./catalog.json --root ./project --tool example-cli=1.3.0
```

Commands are argument arrays, displayed literally for review. They are never shell-evaluated or automatically run. `fixed: null` means no known fixed version. Version ranges use Python packaging specifiers, including unions expressed as separate affected entries; Homebrew dates/revisions are normalized for comparison. OSV uses its own ecosystem-aware version matching. Unsupported version syntax becomes a coverage warning, never a clean result.
