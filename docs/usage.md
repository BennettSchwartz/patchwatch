[← Patchwatch](../README.md)

# Using Patchwatch

## Install

Requires Python 3.11+ on macOS or Linux. `uv` is recommended for environment updates.

```sh
uv tool install 'git+https://github.com/BennettSchwartz/patchwatch.git'
patchwatch --help
```

For development:

```sh
uv sync --extra dev
uv run patchwatch --help
```

## Start with a scan

```sh
# Read installed metadata under a project; also inventory Homebrew and known PATH tools.
patchwatch scan --root ~/projects/my-app

# Check newly published OSV advisories too.
patchwatch scan --root ~/projects/my-app --osv

# Full default inventory: home directory and standard local Python locations.
patchwatch inventory --json

# Restrict strictly to this environment; useful for applying a focused fix.
patchwatch scan --root ~/projects/my-app/.venv --no-homebrew --no-tools

# Machine-readable output and CI status.
patchwatch scan --root ~/projects/my-app --json --output report.json
```

OSV requests send package ecosystem, name, and installed version. Paths and project source are not sent. OSV is opt-in because package names can reveal private dependencies.

Exit codes: **0** = no findings (or successful requested operation); **1** = findings/manual or failed fixes; **2** = incomplete scan or operational error; **130** = interrupted. `inventory` is descriptive and returns 0 even with coverage warnings; use `scan` for enforcement.

## Plan, apply, undo

```sh
patchwatch plan --root ~/projects/my-app/.venv --no-homebrew --no-tools

# No --apply: fix also previews the plan.
patchwatch fix --root ~/projects/my-app/.venv --no-homebrew --no-tools

# Apply one action ID copied from the plan.
patchwatch fix --root ~/projects/my-app/.venv --no-homebrew --no-tools \
  --only ACTION_ID --apply

# Restore a Python package from the run ID in the update receipt.
patchwatch rollback RUN_UUID --apply
```

Supported automatic actions:

- **Python virtual environments:** pin the catalog's fixed version; save original package files and declared scripts; install a wheel with uv or pip; check the installed version and dependency consistency. Catalog wheel artifacts are SHA-256 checked and their package/version metadata must match. Source distributions are not built.
- **Active Homebrew formulae:** upgrade through Homebrew, retain old kegs, and check that a fixed version is installed. This may update dependencies. Homebrew actions do **not** have automatic rollback.

Snapshots and receipts live in `~/.local/state/patchwatch/runs/`. Override with `PATCHWATCH_STATE_DIR`. Rollback refuses to overwrite files modified since the update, checks backup hashes, and invalidates generated Python bytecode. A dependency-check failure remains a failed fix; use the recorded run ID to roll back. An interrupted install might require manual recovery from its snapshot.

Base Python installations, administrator-owned files, ensurepip seeds, npm lockfiles, standalone runtimes, unsupported tools, and OSV-only fixes are reported with manual guidance. Patchwatch does not execute custom commands from the catalog, silently rewrite project lockfiles, elevate privileges, or claim that a version check proves application behavior. Backups contain the previous vulnerable package; protect and eventually retire them after validating the upgrade.

## Monitor

```sh
# Foreground: refresh the configured catalog and scan once a day.
patchwatch watch --root ~/projects --interval 86400 --osv

# One cycle, suitable for cron/systemd or CI.
patchwatch watch --once --root ~/projects --osv

# macOS LaunchAgent: runs at login/load and every 24 hours.
patchwatch schedule install --root ~/projects --interval 86400 --osv
patchwatch schedule show
patchwatch status
patchwatch schedule remove
```

Monitoring reports by default. Add `--apply` to `watch` or `schedule install` only to enable automatic built-in fixes. Incomplete inventories block automatic updates. Use focused roots to avoid protected folders and unrelated environments. Do not run concurrent independent state directories against the same environments; the operation lock coordinates processes sharing one state directory.

Monitoring writes `last-report.json` and scheduled logs under the state directory. No background service is installed merely by installing the CLI. Logs are local; configure rotation for long-lived deployments.

## Coverage and limitations

- Python `.dist-info` metadata and ensurepip wheels, Homebrew installed formulae, known PATH tools (`uv`, `bun`, `node`, `go`, `pixi`), npm package-lock v2/v3.
- Discovery reads Python metadata without importing discovered packages or executing their interpreters. Explicit fixes run the selected environment's interpreter/package manager; only fix environments you trust.
- Symlinked directories, common caches, backups, container data, and selected macOS private folders are excluded. A directory budget prevents an unbounded traversal. Reports include exclusions, scan roots, and errors.
- No detection of zero-days, malicious packages without advisories, actual exploitation, app-embedded signed bundles, remote servers, or container-image contents. Other lockfile formats are not currently parsed.
- Retained Homebrew kegs can still appear vulnerable even when the active tool is patched. They are manual findings because existing consumers may still reference them.
- The bundled catalog starts with the eMudhra/emSign certificate incident. It is not a complete vulnerability database. Use `--osv` for broader published PyPI/npm advisories. OSV findings require curated remediation to avoid choosing the wrong fixed release branch.
- Live HTTPS reachability, application regression tests, process restarts, image rebuilds, and lockfile persistence remain the operator's responsibility.

