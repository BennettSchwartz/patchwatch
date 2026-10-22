# Contributing advisories

See the [catalog format guide](docs/catalog.md) for examples and the [development guide](docs/development.md) for setup and checks.

Edit `src/patchwatch/data/catalog.json` in a pull request. Update its UTC `updated` timestamp and run catalog validation and tests.

Each advisory needs a stable identifier (prefer a GHSA/CVE; use a `PW-` identifier for a sourced incident without one), a concise summary, severity, primary-source HTTPS references, and affected package entries. Specify exact affected ranges and a fixed version or null. Distinguish the first security fix from a later recommended compatibility release when defining the affected range.

Use an array of literal arguments for optional commands. Keep commands portable and source them from the vendor’s guidance. Commands are presented as operator instructions. Automatic actions are implemented and tested in the CLI's adapters.

For a pinned Python wheel, provide its HTTPS URL, basename, and independently verified SHA-256. The wheel’s package/version must match the plan. Verify the artifact against an independently trusted source when reviewing the catalog change.

Add a boundary regression test for affected and fixed versions. Separate advisories for materially different affected ranges/severities. Describe affected configurations with the specificity supported by the source.

OSV supplies advisory discovery; humans maintain the curated fix policy. Preserve the release branches associated with each source’s fix.
