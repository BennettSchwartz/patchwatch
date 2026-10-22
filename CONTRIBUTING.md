# Contributing advisories

Edit `src/patchwatch/data/catalog.json` in a pull request. Update its UTC `updated` timestamp and run catalog validation and tests.

Each advisory needs a stable identifier (prefer a GHSA/CVE; use a `PW-` identifier for a sourced incident without one), a concise summary, severity, primary-source HTTPS references, and affected package entries. Specify exact affected ranges and a fixed version or null. Do not confuse a recommended compatibility release with the first security fix; the affected range and recommended target may differ.

Use an array of literal arguments for optional commands. Do not add credentials, machine paths, shell pipelines, or commands from unverified forum posts. Commands are documentation only. Automatic actions are implemented and tested in the CLI's adapters.

For a pinned Python wheel, provide its HTTPS URL, basename, and independently verified SHA-256. The CLI rejects a wheel whose package/version does not match the plan. Review both the artifact and the catalog change: a hash supplied by an untrusted catalog is not independent authenticity.

Add a boundary regression test for affected and fixed versions. Separate advisories for materially different affected ranges/severities. Avoid broad claims that all versions or all installations are exploitable when evidence only establishes certain configurations.

OSV supplies advisory discovery; humans maintain the curated fix policy. Do not automatically promote an OSV branch fix to a universal target.
