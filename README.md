<div align="center">

# Patchwatch

**Find vulnerable packages across your machine and get them patched.**

A CLI for checking project dependencies and installed software against a shared vulnerability catalog.

[![CI](https://img.shields.io/github/actions/workflow/status/BennettSchwartz/patchwatch/ci.yml?branch=main&style=for-the-badge&logo=githubactions&logoColor=white&label=CI)](https://github.com/BennettSchwartz/patchwatch/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/BennettSchwartz/patchwatch?style=for-the-badge&logo=github&logoColor=white)](https://github.com/BennettSchwartz/patchwatch/releases/latest)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](pyproject.toml)
[![Platforms](https://img.shields.io/badge/macOS%20%7C%20Linux-supported-555555?style=for-the-badge)](docs/usage.md#coverage-and-limitations)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

[Getting started](#quick-start) · [Documentation](docs/usage.md) · [Vulnerability catalog](docs/catalog.md) · [Contributing](CONTRIBUTING.md)

</div>

## Why Patchwatch?

Updating your main installation can leave older copies inside virtual environments and other developer tools. Patchwatch identifies which copies are affected and shows you how to fix them.

Its shared catalog lives here on GitHub: affected versions, recommended updates, source references, and instructions for tools that need a manual fix. Optional [OSV](https://osv.dev/) lookups extend scans across supported package ecosystems.

## What it does

- **Scan projects across 10 package ecosystems** with per-project findings and dependency-file locations. See [language coverage](docs/projects.md).
- **Discover installed packages** across Python environments, Homebrew, service binaries, and CLI tools.
- **Turn advisories into update plans** with affected locations and fixed versions.
- **Fix project dependencies** through their package manager. Review the proposed commands and confirm in the terminal.
- **Roll back an update** using saved dependency files or Python package snapshots.
- **Monitor for new advisories** with recurring scans and optional approved updates.

## Quick start

Install with [uv](https://docs.astral.sh/uv/) and scan a project:

```sh
uv tool install 'git+https://github.com/BennettSchwartz/patchwatch.git'
patchwatch scan --project ~/projects/my-app --intelligence
```

Requires **Python 3.11+** on **macOS or Linux**. Scanning is read-only. OSV lookup sends package names and versions; local paths and source files stay on your machine.

Follow the [usage guide](docs/usage.md) to review a plan, apply fixes or set up monitoring.

## A catalog we can maintain together

The [catalog](src/patchwatch/data/catalog.json) is plain JSON, reviewed through pull requests and validated in CI. It supports affected version ranges, fixed releases, advisory links, verified Python wheels, and optional remediation commands.

The catalog includes **60 advisories reaching back to 2010**, with recovery guidance for documented package compromises. Browse the [advisory index](docs/advisories.md) or [contribute a verified fix](CONTRIBUTING.md).

Import records from [CVE List](https://www.cve.org/) or [GitHub Advisory Database](https://github.com/advisories). [OSV](https://osv.dev/) discovers additional advisories during scans. [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [EPSS](https://www.first.org/epss/) help prioritize findings using exploitation evidence and estimated likelihood. See [sources and service checks](docs/sources.md).

---

[Usage guide](docs/usage.md) · [Catalog format](docs/catalog.md) · [Development](docs/development.md) · [MIT license](LICENSE)
