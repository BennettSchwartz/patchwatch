<div align="center">

# Patchwatch

**Find vulnerable packages across your machine and get them patched.**

A CLI for checking the tools and environments on your machine against a shared vulnerability catalog.

[![CI](https://img.shields.io/github/actions/workflow/status/BennettSchwartz/patchwatch/ci.yml?branch=main&style=for-the-badge&logo=githubactions&logoColor=white&label=CI)](https://github.com/BennettSchwartz/patchwatch/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/BennettSchwartz/patchwatch?style=for-the-badge&logo=github&logoColor=white)](https://github.com/BennettSchwartz/patchwatch/releases/latest)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](pyproject.toml)
[![Platforms](https://img.shields.io/badge/macOS%20%7C%20Linux-supported-555555?style=for-the-badge)](docs/usage.md#coverage-and-limitations)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

[Getting started](#quick-start) · [Documentation](docs/usage.md) · [Vulnerability catalog](docs/catalog.md) · [Contributing](CONTRIBUTING.md)

</div>

## Why Patchwatch?

Updating your main installation can leave older copies inside virtual environments and other developer tools. Patchwatch identifies which copies are affected and shows you how to fix them.

Its shared catalog lives here on GitHub: affected versions, recommended updates, source references, and instructions for tools that need a manual fix. Optional [OSV](https://osv.dev/) lookups extend scans to published PyPI and npm advisories.

## What it does

- **Discover installed packages** across Python environments, Homebrew, known CLI tools, and npm lockfiles.
- **Turn advisories into update plans** with affected locations and fixed versions.
- **Apply supported fixes** to Python virtual environments and active Homebrew formulae when you opt in.
- **Recover from a Python update** using package snapshots. Rollback checks for later file changes before restoring them.
- **Check again on a schedule** with foreground monitoring or a macOS LaunchAgent.

## Quick start

Install with [uv](https://docs.astral.sh/uv/) and scan a project:

```sh
uv tool install 'git+https://github.com/BennettSchwartz/patchwatch.git'
patchwatch scan --root ~/projects/my-app --osv
```

Requires **Python 3.11+** on **macOS or Linux**. Scanning is read-only. OSV lookup sends package names and versions; local paths and source files stay on your machine.

Follow the [usage guide](docs/usage.md) to review a plan, apply a fix, roll back a Python update, or enable monitoring.

## A catalog we can maintain together

The [catalog](src/patchwatch/data/catalog.json) is plain JSON, reviewed through pull requests and validated in CI. It supports affected version ranges, fixed releases, advisory links, verified Python wheels, and optional remediation commands.

The bundled rules currently cover the **eMudhra/emSign certificate incident**. Use OSV for broader advisory discovery, or [contribute a rule](CONTRIBUTING.md) with a verified fix. Custom commands are displayed for review, never automatically executed.

## Scope

Automatic fixes currently cover **Python virtual environments and active Homebrew formulae**. Other installations and OSV-only findings receive manual guidance. Python updates support snapshot rollback; Homebrew updates do not.

Patchwatch checks known advisories and installed versions. Its coverage is local; remote hosts and container images need separate checks. You’ll still need to test your applications after updating. See the [coverage details](docs/usage.md#coverage-and-limitations).

---

[Usage guide](docs/usage.md) · [Catalog format](docs/catalog.md) · [Development](docs/development.md) · [MIT license](LICENSE)
