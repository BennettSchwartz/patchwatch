[← Patchwatch](../README.md)

# Project scans

Scan a project and its nested dependency files:

```sh
patchwatch scan --project . --intelligence
patchwatch plan --project .
```

`--project` enables OSV discovery and scopes inventory to the chosen directory. Repeat it to check several repositories. The JSON report groups dependencies and findings by project and records the source file for each dependency. Shared dependency versions use one OSV lookup across all projects.

Project scans cover **10 package ecosystems**. Language coverage follows the package manager used by the project:

| Ecosystem | Languages commonly served | Dependency files |
| --- | --- | --- |
| PyPI | Python | `uv.lock`, `poetry.lock`, `Pipfile.lock`, pinned `requirements.txt` |
| npm | JavaScript, TypeScript | `package-lock.json` v1–v3, `npm-shrinkwrap.json`, `pnpm-lock.yaml` v5/v6/v9, Yarn Classic and Berry `yarn.lock` |
| Go | Go | `go.mod`, including versioned replacements |
| crates.io | Rust | `Cargo.lock` |
| RubyGems | Ruby | `Gemfile.lock` |
| Packagist | PHP | `composer.lock` |
| Maven | Java, Kotlin, Scala and other JVM languages | Gradle lockfiles, `maven-dependencies.json` export |
| NuGet | C#, F#, Visual Basic | `packages.lock.json` |
| Pub | Dart / Flutter | `pubspec.lock` |
| Hex | Elixir, Erlang | `mix.lock` |

The readers cover 18 dependency filenames. They inspect dependency metadata; application source analysis is a separate task. Package vulnerability matching for the added ecosystems comes from [OSV's ecosystem databases](https://google.github.io/osv.dev/data/).

## Coverage

Resolved lockfiles include transitive dependencies recorded by the package manager. `go.mod` covers its declared requirements; older module files can require additional graph resolution. Python requirements should contain exact pins, such as a reviewed environment export. Environment markers and optional dependency groups are scanned together, so reports can include dependencies for other deployment platforms.

Recognized manifests without a corresponding dependency file produce a coverage warning. Nested workspace manifests can use an ancestor lockfile within the scan roots. Maven projects use a JSON dependency-tree export generated for each module with `mvn dependency:tree -DoutputType=json -DoutputFile=maven-dependencies.json` (dependency plugin 3.7+). Refresh exports after dependency changes; see the [Maven export documentation](https://maven.apache.org/plugins/maven-dependency-plugin/examples/tree-mojo.html). NuGet projects should enable `RestorePackagesWithLockFile` and restore to produce `packages.lock.json`.

Git and local replacements receive review warnings where their identity cannot be matched to a registry release. Private registries and patched distributions need their own provenance review. A library's reported version alone does not establish whether a vendor backport applies.

Project mode omits machine-wide Homebrew and PATH tool inventory. Use `--root` for the broader inventory behavior. Coverage warnings produce exit code 2; findings produce exit code 1; a completed scan with no findings returns 0.

## Update plans

```sh
patchwatch fix --project .
patchwatch fix --project . --yes
patchwatch rollback RUN_UUID --apply
```

The first command displays the proposed package-manager operations and asks for confirmation. The second supplies approval for an unattended run. `patchwatch plan --project .` previews the actions.

| Manager | Files published after verification |
| --- | --- |
| npm | `package.json` and the npm lockfile |
| pnpm | `package.json`, `pnpm-lock.yaml`, and an existing workspace catalog when updated |
| Yarn Classic / Berry | `package.json` and `yarn.lock` |
| uv / Poetry | `pyproject.toml` and the owning lockfile |
| Cargo | `Cargo.toml` and `Cargo.lock` |
| Composer | `composer.json` and `composer.lock` |
| Bundler | `Gemfile` and `Gemfile.lock` |
| Go | `go.mod` and `go.sum` |
| Dart Pub | `pubspec.yaml` and `pubspec.lock` |
| Mix | `mix.exs` and `mix.lock` |

These adapters cover 8 of the 10 scanned ecosystems. Maven/Gradle and NuGet currently produce findings and update guidance. The CLI explains when a required package manager is missing. Pinned `requirements.txt` and Pipenv locks also retain manual guidance.

For each dependency file, Patchwatch groups affected packages into one update transaction. It snapshots the original files and runs the package manager in a temporary project copy. Managers resolve updates according to their normal dependency rules; Go selects the latest release of the selected module. JavaScript lifecycle scripts are disabled, Composer plugins/scripts are disabled, and uv builds are disabled. Bundler and Mix evaluate their project configuration.

Before publishing, Patchwatch rescans the resulting dependency graph with the local catalog and OSV when enabled. The selected packages must be clear of reported advisories, and the graph must introduce no additional advisory findings. Unresolved constraints produce a failed update receipt with the original project files preserved. Concurrent edits also stop publication.

Verified dependency files are copied back with a receipt recording resolved versions. Rollback restores their previous contents after checking for later edits. Files outside the adapter's publication list remain in the temporary copy; unexpected changes to existing project source files stop the transaction. Staging supports regular files up to 20,000 files / 256 MiB, excluding common caches and dependency directories.

Install or sync from the updated files, then run the project's tests. Runtime services and deployed images follow their normal release workflow. Project rollback covers dependency files; package-manager caches and external effects of project configuration are outside that snapshot.

## Offline scans and reports

```sh
patchwatch scan --project . --offline --json > patchwatch-report.json
```

Offline scans use the local curated catalog. The bundled historical rules cover selected PyPI/npm packages and service incidents. OSV provides advisory matching for the other project ecosystems during online scans. `--offline` also disables KEV and EPSS requests.

Online scans send package identities and versions to OSV. Reports contain local project paths and can be retained as CI artifacts. Treat report files according to your repository's access policy.
