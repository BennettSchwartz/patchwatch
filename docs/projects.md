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

`patchwatch plan --project .` includes the project directory, advisory fix guidance, and an available package-manager command. The operator selects a compatible fixed release and reviews manifest constraints before regenerating the lockfile. Run the project's tests and scan again after updating.

Automatic application remains available for the supported installed Python environments and Homebrew packages described in the [usage guide](usage.md). Project lockfile plans are reviewed and run through the owning package manager.

## Offline scans and reports

```sh
patchwatch scan --project . --offline --json > patchwatch-report.json
```

Offline scans use the local curated catalog. The bundled historical rules cover selected PyPI/npm packages and service incidents. OSV provides advisory matching for the other project ecosystems during online scans. `--offline` also disables KEV and EPSS requests.

Online scans send package identities and versions to OSV. Reports contain local project paths and can be retained as CI artifacts. Treat report files according to your repository's access policy.
