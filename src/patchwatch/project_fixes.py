"""Stage package-manager updates, verify dependency graphs, and publish recoverable files."""

import hashlib
import json
import os
import re
import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

from . import inventory, projects, scanner

# Commands resolve within the manifest's constraints. Verification decides whether
# the resulting graph fixes the findings before any project files are published.
ADAPTERS = {
    "go.mod": ("go", ["get", "{name}@latest"], ["go.mod", "go.sum"]),
    "yarn.lock": (
        "yarn",
        ["upgrade", "{name}", "--ignore-scripts", "--non-interactive"],
        ["package.json", "yarn.lock"],
    ),
    "package-lock.json": (
        "npm",
        ["update", "{name}", "--package-lock-only", "--ignore-scripts"],
        ["package.json", "package-lock.json"],
    ),
    "npm-shrinkwrap.json": (
        "npm",
        ["update", "{name}", "--package-lock-only", "--ignore-scripts"],
        ["package.json", "npm-shrinkwrap.json"],
    ),
    "pnpm-lock.yaml": (
        "pnpm",
        ["update", "{name}", "--lockfile-only", "--ignore-scripts", "--ignore-pnpmfile"],
        ["package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"],
    ),
    "uv.lock": ("uv", ["lock", "--upgrade-package", "{name}", "--no-build"], ["pyproject.toml", "uv.lock"]),
    "poetry.lock": (
        "poetry",
        ["--no-plugins", "update", "--lock", "{name}"],
        ["pyproject.toml", "poetry.lock"],
    ),
    "Cargo.lock": ("cargo", ["update", "--package", "{name}"], ["Cargo.toml", "Cargo.lock"]),
    "composer.lock": (
        "composer",
        [
            "--no-plugins",
            "--no-scripts",
            "update",
            "{name}",
            "--with-dependencies",
            "--no-install",
            "--no-interaction",
        ],
        ["composer.json", "composer.lock"],
    ),
    "Gemfile.lock": ("bundle", ["lock", "--update", "{name}"], ["Gemfile", "Gemfile.lock"]),
    "pubspec.lock": (
        "dart",
        ["pub", "upgrade", "{name}", "--no-precompile"],
        ["pubspec.yaml", "pubspec.lock"],
    ),
    "mix.lock": ("mix", ["deps.update", "{name}"], ["mix.exs", "mix.lock"]),
}
SKIP = inventory.PRUNE | {
    ".venv",
    "venv",
    "vendor",
    ".bundle",
    ".dart_tool",
    "_build",
    "deps",
    ".gradle",
    "dist",
    ".build",
    ".tox",
    "__pycache__",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fingerprints(root, names):
    result = {}
    for name in names:
        path = root / name
        if path.is_symlink() or path.resolve() != path.absolute() or (path.exists() and not path.is_file()):
            raise ValueError(f"Expected a regular project file: {path}")
        result[name] = digest(path) if path.exists() else None
    return result


def key(finding):
    p = finding["package"]
    return (p["ecosystem"], p["name"], finding["advisory"])


def configure(action, report):
    p = action["package"]
    lockfile = Path(p["lockfile"])
    adapter = ADAPTERS.get(lockfile.name)
    if not adapter:
        return
    manager, args, names = adapter
    if lockfile.name == "yarn.lock" and "__metadata:" in lockfile.read_text():
        args = ["up", "{name}", "--recursive", "--mode=update-lockfile"]
    if not re.fullmatch(r"[A-Za-z0-9@][A-Za-z0-9@/._+-]*", p["name"]):
        action["reason"] = "Package identity needs manual review"
        return
    executable = shutil.which(manager)
    if not executable:
        action["reason"] = f"Install {manager} to enable this project update"
        return
    root = Path(p["project"])
    if not (root / names[0]).is_file():
        action["reason"] = f"Project update requires {names[0]}"
        return
    try:
        before = fingerprints(root, names)
    except ValueError as exc:
        action["reason"] = str(exc)
        return
    command = [str(Path(executable).absolute()), *[a.replace("{name}", p["name"]) for a in args]]
    action.update(
        supported=True,
        adapter="project",
        manager=manager,
        commands=[command],
        reason=f"{manager} resolves an update within project constraints; the dependency graph is checked before publishing",
        target_version=None,
        instructions=[
            text
            for text in action.get("instructions", [])
            if text and not text.startswith("Run dependency updates in ")
        ],
        files=names,
        before_hashes=before,
        packages=[p],
        working_directory=str(root),
        baseline=[list(key(f)) for f in report["findings"] if f["package"].get("lockfile") == str(lockfile)],
        catalog_rules=report.get("catalog_rules", []),
        online=report.get("osv_enabled", False),
    )


def group(actions):
    grouped, result = {}, []
    for action in actions:
        if action.get("adapter") != "project":
            result.append(action)
            continue
        location = action["package"]["lockfile"]
        if location not in grouped:
            grouped[location] = action
            action["id"] = hashlib.sha256(location.encode()).hexdigest()[:16]
            result.append(action)
        else:
            first = grouped[location]
            first["packages"].extend(action["packages"])
            first["commands"].extend(c for c in action["commands"] if c not in first["commands"])
            first["advisories"] = sorted(set(first["advisories"] + action["advisories"]))
            first["instructions"].extend(action["instructions"])
    return result


def copy_project(root, stage):
    count, size = 0, 0
    copied = {}
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP]
        files = [name for name in files if name not in SKIP]
        for name in dirs + files:
            if (Path(base) / name).is_symlink():
                raise ValueError(
                    f"Project staging requires regular files; review symlink: {Path(base) / name}"
                )
        relative = Path(base).relative_to(root)
        destination = stage / relative
        destination.mkdir(parents=True, exist_ok=True)
        for name in files:
            path = Path(base) / name
            if str(relative / name) in {".yarn/install-state.gz", ".pnp.cjs", ".pnp.loader.mjs"}:
                continue
            if not path.is_file():
                raise ValueError(f"Project staging requires a regular file: {path}")
            count += 1
            size += path.stat().st_size
            if count > 20000 or size > 256 * 1024 * 1024:
                raise ValueError(
                    "Project staging exceeds 20,000 files or 256 MiB; use a smaller project root"
                )
            shutil.copy2(path, destination / name)
            copied[str(relative / name)] = digest(destination / name)
    return copied


def read_lock(path):
    warnings = []
    packages = (
        inventory.read_npm(path, warnings)
        if path.name in {"package-lock.json", "npm-shrinkwrap.json"}
        else projects.read(path, warnings)
    )
    if warnings:
        raise ValueError("Updated dependency graph requires review: " + "; ".join(warnings))
    return packages


def apply(action, state_dir, *, run=subprocess.run):
    run_id = str(uuid.uuid4())
    directory = Path(state_dir).resolve() / "runs" / run_id
    root = Path(action["working_directory"]).resolve()
    if directory.is_relative_to(root):
        raise ValueError("Set PATCHWATCH_STATE_DIR outside the project before updating it")
    directory.mkdir(parents=True, mode=0o700)
    stage = directory / "work"
    receipt = dict(id=run_id, created=datetime.now(UTC).isoformat(), action=action, status="preparing")

    def persist():
        temporary = directory / "receipt.tmp"
        temporary.write_text(json.dumps(receipt, indent=2) + "\n")
        temporary.replace(directory / "receipt.json")

    persist()
    try:
        if fingerprints(root, action["files"]) != action["before_hashes"]:
            raise ValueError("Project changed since planning; rescan")
        (directory / "files").mkdir()
        receipt["before"] = []
        for name, checksum in action["before_hashes"].items():
            item = {"name": name, "sha256": checksum}
            if checksum is not None:
                shutil.copy2(root / name, directory / "files" / name)
                if digest(directory / "files" / name) != checksum:
                    raise ValueError("Project changed while saving its snapshot; rescan")
                item["mode"] = (root / name).stat().st_mode & 0o777
            receipt["before"].append(item)
        persist()
        copied = copy_project(root, stage)
        if fingerprints(stage, action["files"]) != action["before_hashes"]:
            raise ValueError("Project changed during staging; rescan")
        env = dict(os.environ)
        env.pop("VIRTUAL_ENV", None)
        env.update(
            CI="true",
            GOTOOLCHAIN="local",
            npm_config_ignore_scripts="true",
            YARN_ENABLE_SCRIPTS="false",
            MIX_DEPS_PATH=str(stage / "deps"),
        )
        receipt["status"] = "resolving"
        persist()
        for index, command in enumerate(action["commands"]):
            result = run(command, cwd=stage, capture_output=True, text=True, timeout=600, env=env)
            (directory / f"command-{index}.log").write_text(result.stdout + result.stderr)
            if result.returncode:
                raise ValueError(f"Package manager exited {result.returncode}; see command-{index}.log")
        for name, checksum in copied.items():
            if name not in action["files"] and fingerprints(stage, [name])[name] != checksum:
                raise ValueError(
                    f"Package manager changed an additional project file: {name}; review this update manually"
                )
        lock = stage / Path(action["package"]["lockfile"]).name
        packages = read_lock(lock)
        if not packages:
            raise ValueError("Updated dependency graph is empty; review this update manually")
        report = scanner.scan(
            {"packages": packages, "warnings": [], "coverage": {}},
            {"advisories": action["catalog_rules"], "updated": "snapshot"},
            "snapshot",
            osv=action["online"],
        )
        if report["warnings"]:
            raise ValueError("Verification incomplete: " + "; ".join(report["warnings"]))
        target_names = {(p["ecosystem"], p["name"]) for p in action["packages"]}
        if any((f["package"]["ecosystem"], f["package"]["name"]) in target_names for f in report["findings"]):
            raise ValueError(
                "Selected dependencies still have advisories; adjust manifest constraints and retry"
            )
        new_findings = {key(f) for f in report["findings"]} - {tuple(k) for k in action["baseline"]}
        if new_findings:
            raise ValueError("Updated graph introduces advisory findings; review the dependency constraints")
        after = fingerprints(stage, action["files"])
        if after == action["before_hashes"]:
            raise ValueError("Package manager produced no dependency-file changes")
        if any(after[n] is None for n, checksum in action["before_hashes"].items() if checksum is not None):
            raise ValueError("Package manager removed an expected project file")
        if fingerprints(root, action["files"]) != action["before_hashes"]:
            raise ValueError("Project changed while resolving; original files preserved")
        receipt["after"] = after
        receipt["resolved_packages"] = [
            dict(name=p["name"], ecosystem=p["ecosystem"], version=p["version"])
            for p in packages
            if (p["ecosystem"], p["name"]) in target_names
        ]
        receipt["verification_scope"] = (
            "Resolved dependency files checked against the catalog and enabled OSV lookup. Install/sync dependencies and run project tests next."
        )
        receipt["status"] = "publishing"
        receipt["published"] = []
        persist()
        for name, checksum in after.items():
            if checksum == action["before_hashes"][name]:
                continue
            destination = root / name
            temp = root / (".patchwatch-" + run_id + "-" + name)
            shutil.copy2(stage / name, temp)
            os.replace(temp, destination)
            receipt["published"].append(name)
            persist()
        receipt["status"] = "verified-version"
    except Exception as exc:
        receipt.update(status="failed", error=str(exc))
    finally:
        persist()
        shutil.rmtree(stage, ignore_errors=True)
    return receipt


def rollback(receipt, directory):
    if receipt.get("status") == "rolled-back":
        raise ValueError("Already rolled back")
    root = Path(receipt["action"]["working_directory"])
    names = receipt["action"]["files"]
    before = {item["name"]: item for item in receipt["before"]}
    after = receipt.get("after")
    if not after:
        raise ValueError("Project files were not published")
    current = fingerprints(root, names)
    # A partially published transaction can contain either its before or after bytes.
    for name in names:
        if current[name] not in {before[name]["sha256"], after[name]}:
            raise ValueError(f"Project file changed since update: {root / name}")
        if (
            before[name]["sha256"] is not None
            and digest(directory / "files" / name) != before[name]["sha256"]
        ):
            raise ValueError("Backup integrity check failed")
    for name, item in before.items():
        if current[name] == item["sha256"]:
            continue
        if item["sha256"] is None:
            (root / name).unlink()
        else:
            temporary = root / (".patchwatch-restore-" + receipt["id"] + "-" + name)
            shutil.copy2(directory / "files" / name, temporary)
            os.replace(temporary, root / name)
    receipt.update(status="rolled-back", rolled_back_at=datetime.now(UTC).isoformat())
    (directory / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt
