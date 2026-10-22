"""Explicit package-manager actions with recoverable Python package snapshots."""

import configparser
import csv
import email.parser
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from .catalog import canonical, read_url, version
from .inventory import read_site
from .projects import update_guidance


def plan(report):
    groups = {}
    for finding in report["findings"]:
        groups.setdefault(finding["package"]["id"], []).append(finding)
    actions = []
    for pkg_id, findings in groups.items():
        p = findings[0]["package"]
        action = dict(
            id=pkg_id,
            package=p,
            advisories=[f["advisory"] for f in findings],
            supported=False,
            reason="No built-in remediation",
            commands=[],
            target_version=None,
        )
        targets = [f["target"] for f in findings if f["source"] == "catalog"]
        fixes = [t["fixed"] for t in targets if t.get("fixed")]
        for t in targets:
            if t.get("command"):
                action["commands"].append(t["command"])
        action["instructions"] = [f["target"].get("instructions", "") for f in findings]
        if any(f["source"] == "osv" for f in findings):
            action["reason"] = "OSV findings require review of release branches; add a curated catalog rule"
        elif fixes:
            fixed = max(fixes, key=Version)
            action["target_version"] = fixed
            all_targets = [
                t
                for advisory in report.get("catalog_rules", [])
                for t in advisory["affected"]
                if t["ecosystem"] == p["ecosystem"] and canonical(t["package"]) == canonical(p["name"])
            ] or targets
            if any(
                SpecifierSet(t["versions"]).contains(Version(fixed), prereleases=True) for t in all_targets
            ):
                action["reason"] = "No common fixed version across advisories"
            elif Version(fixed) <= version(p["version"], p["ecosystem"]):
                action["reason"] = "Fix must be newer than installed version"
            elif p["kind"] == "python" and p.get("venv") and p.get("python") and p["name"] != "conda":
                if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", p["name"]):
                    action["reason"] = "Invalid package name"
                elif not os.access(p["site"], os.W_OK):
                    action["reason"] = "Environment requires administrator access"
                elif (
                    Path(p["python"]).resolve() == Path(sys.executable).resolve()
                    and Path(p["site"]) in Path(__file__).resolve().parents
                ):
                    action["reason"] = "Do not mutate Patchwatch's own environment while it is running"
                else:
                    action.update(
                        supported=True, adapter="python", reason="Pinned update with package-file backup"
                    )
                    artifacts = [
                        t["artifact"] for t in targets if t.get("artifact") and t.get("fixed") == fixed
                    ]
                    if artifacts:
                        action["artifact"] = artifacts[0]
            elif p["kind"] == "homebrew" and not p.get("active", True):
                action["reason"] = "Retained Homebrew keg; update consumers before removing old runtime"
            elif p["kind"] == "homebrew" and re.fullmatch(r"[A-Za-z0-9@+_.-]+", p["name"]):
                action.update(
                    supported=True,
                    adapter="homebrew",
                    reason="Homebrew upgrade; prior kegs retained, no automatic rollback",
                )
            elif p["kind"] == "python-seed":
                action["reason"] = "Update the owning Python runtime to repair ensurepip seeds"
            elif p["kind"] == "python":
                action["reason"] = (
                    "Base Python installation: update through its owner; automatic writes limited to virtual environments"
                )
            elif p["kind"] == "tool":
                action["reason"] = "Use the owning package manager; standalone tools are report-only"
        if p.get("lockfile"):
            command, instruction = update_guidance(p)
            if command:
                action["commands"].append(command)
            action["instructions"].append(instruction)
            action["working_directory"] = p["project"]
        actions.append(action)
    return actions


def hash_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def distribution_files(dist, site, python, name):
    site, dist = Path(site).resolve(), Path(dist).resolve()
    bin_dir = Path(python).absolute().parent
    permitted_scripts = set()
    cfg = configparser.ConfigParser()
    if (dist / "entry_points.txt").exists():
        cfg.read(dist / "entry_points.txt")
        for section in ["console_scripts", "gui_scripts"]:
            if cfg.has_section(section):
                permitted_scripts.update(cfg[section])
    if name == "pip":
        permitted_scripts.update(
            p.name for p in bin_dir.glob("pip*") if re.fullmatch(r"pip(?:\d+(?:\.\d+)?)?", p.name)
        )
    files = []
    record = dist / "RECORD"
    if not record.is_file():
        raise ValueError("Missing RECORD: cannot take a reliable package snapshot")
    for row in csv.reader(record.read_text().splitlines()):
        if not row:
            continue
        lexical = Path(os.path.abspath(site / row[0]))
        resolved = lexical.resolve()
        if lexical.is_symlink() or lexical != resolved:
            raise ValueError(f"Refusing symlinked package file: {lexical}")
        allowed = resolved.is_relative_to(site) or (
            resolved.parent == bin_dir and resolved.name in permitted_scripts
        )
        if not allowed:
            raise ValueError(f"RECORD path outside package/site and declared scripts: {resolved}")
        if resolved.exists():
            if not resolved.is_file():
                raise ValueError(f"Not a regular package file: {resolved}")
            files.append(resolved)
    if record not in files:
        files.append(record)
    return sorted(set(files))


def save_snapshot(action, directory):
    p = action["package"]
    paths = distribution_files(p["location"], p["site"], p["python"], p["name"])
    snapshot = []
    (directory / "files").mkdir()
    for idx, path in enumerate(paths):
        dest = directory / "files" / str(idx)
        shutil.copy2(path, dest)
        snapshot.append(
            dict(path=str(path), backup=str(idx), sha256=hash_file(dest), mode=path.stat().st_mode & 0o777)
        )
    return snapshot


def clean_env():
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PIP_", "UV_", "PYTHON"))}
    env["UV_SYSTEM_CERTS"] = "true"
    env["HOMEBREW_NO_INSTALL_CLEANUP"] = "1"
    env["HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK"] = "1"
    return env


def validate_wheel(data, name, expected_version):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        metadata = [i for i in archive.infolist() if i.filename.endswith(".dist-info/METADATA")]
        if len(metadata) != 1 or metadata[0].file_size > 1024 * 1024:
            raise ValueError("Wheel must contain one bounded METADATA file")
        info = email.parser.Parser().parsestr(archive.read(metadata[0]).decode())
        if canonical(info.get("Name", "")) != canonical(name) or info.get("Version") != expected_version:
            raise ValueError("Artifact package/version does not match the planned update")


def apply(action, state_dir, *, run=subprocess.run):
    if not action["supported"]:
        raise ValueError(action["reason"])
    run_id = str(uuid.uuid4())
    directory = Path(state_dir) / "runs" / run_id
    directory.mkdir(parents=True, mode=0o700)
    receipt = dict(id=run_id, created=datetime.now(UTC).isoformat(), action=action, status="preparing")

    def persist():
        (directory / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")

    persist()
    p = action["package"]
    try:
        if action["adapter"] == "python":
            # Re-read local metadata immediately before mutation; stale plans are rejected.
            current = [x for x in read_site(Path(p["site"]), []) if x["name"] == p["name"]]
            if (
                len(current) != 1
                or current[0]["version"] != p["version"]
                or current[0]["location"] != p["location"]
            ):
                raise ValueError("Installation changed since scanning; rescan")
            if not Path(p["python"]).is_file():
                raise ValueError("Virtual environment interpreter is missing")
            receipt["before"] = save_snapshot(action, directory)
            persist()
            target = f"{p['name']}=={action['target_version']}"
            if action.get("artifact"):
                artifact = action["artifact"]
                data = read_url(artifact["url"], limit=64 * 1024 * 1024)
                if hashlib.sha256(data).hexdigest() != artifact["sha256"]:
                    raise ValueError("Artifact SHA-256 mismatch")
                validate_wheel(data, p["name"], action["target_version"])
                wheel = directory / artifact["filename"]
                wheel.write_bytes(data)
                target = str(wheel.absolute())
            uv = shutil.which("uv")
            if uv:
                command = [
                    uv,
                    "--no-config",
                    "pip",
                    "install",
                    "--python",
                    p["python"],
                    "--no-deps",
                    "--only-binary",
                    ":all:",
                    "--default-index",
                    "https://pypi.org/simple",
                    target,
                ]
            else:
                command = [
                    p["python"],
                    "-I",
                    "-m",
                    "pip",
                    "--isolated",
                    "install",
                    "--no-deps",
                    "--only-binary",
                    ":all:",
                    "--index-url",
                    "https://pypi.org/simple",
                    target,
                ]
        else:
            command = [shutil.which("brew") or "brew", "upgrade", p["name"]]
        receipt.update(status="running", command=command)
        persist()
        result = run(command, capture_output=True, text=True, timeout=600, env=clean_env())
        (directory / "command.log").write_text(result.stdout + result.stderr)
        receipt["returncode"] = result.returncode
        if action["adapter"] == "python":
            current = [x for x in read_site(Path(p["site"]), []) if x["name"] == p["name"]]
            if len(current) == 1:
                paths = distribution_files(current[0]["location"], p["site"], p["python"], p["name"])
                receipt["after"] = [dict(path=str(x), sha256=hash_file(x)) for x in paths]
                receipt["after_version"] = current[0]["version"]
                checker = (
                    [uv, "pip", "check", "--python", p["python"]]
                    if uv
                    else [p["python"], "-I", "-m", "pip", "check"]
                )
                check = run(checker, capture_output=True, text=True, timeout=60, env=clean_env())
                receipt["dependency_check"] = {
                    "returncode": check.returncode,
                    "output": check.stdout + check.stderr,
                }
                verified = (
                    Version(current[0]["version"]) == Version(action["target_version"])
                    and check.returncode == 0
                )
            else:
                verified = False
        else:
            info = run(
                [command[0], "info", "--json=v2", p["name"]], capture_output=True, text=True, timeout=60
            )
            formula = json.loads(info.stdout)["formulae"][0]
            versions = [i["version"] for i in formula["installed"]]
            receipt["after_versions"] = versions
            # Retained older kegs are intentionally still reported on later scans.
            verified = any(version(v, "Homebrew") >= Version(action["target_version"]) for v in versions)
        receipt["status"] = "verified-version" if result.returncode == 0 and verified else "failed"
        receipt["verification_scope"] = (
            "Installed version and (for Python) dependency consistency; application behavior and runtime exploitability not proven"
        )
    except Exception as exc:
        receipt.update(status="failed", error=str(exc))
    persist()
    return receipt


def rollback(run_id, state_dir):
    if not re.fullmatch(r"[0-9a-f-]{36}", run_id):
        raise ValueError("Invalid run ID")
    directory = Path(state_dir) / "runs" / run_id
    receipt = json.loads((directory / "receipt.json").read_text())
    if receipt["action"].get("adapter") != "python" or not receipt.get("after") or not receipt.get("before"):
        raise ValueError("No verified Python snapshot available for automatic rollback")
    if receipt.get("status") == "rolled-back":
        raise ValueError("Already rolled back")
    before = {x["path"]: x for x in receipt["before"]}
    after = {x["path"]: x for x in receipt["after"]}
    # Do all conflict checks before writing anything.
    for path, item in after.items():
        if not Path(path).is_file() or Path(path).is_symlink() or hash_file(Path(path)) != item["sha256"]:
            raise ValueError(f"Files changed since update; refusing rollback: {path}")
    for path, item in before.items():
        saved = directory / "files" / item["backup"]
        if hash_file(saved) != item["sha256"]:
            raise ValueError("Backup integrity check failed")
        if path not in after and Path(path).exists():
            raise ValueError(f"New file occupies original path: {path}")
    for path in after.keys() - before.keys():
        Path(path).unlink()
    for path in after.keys() - before.keys():
        parent = Path(path).parent
        site = Path(receipt["action"]["package"]["site"])
        while parent.is_relative_to(site) and parent != site:
            try:
                parent.rmdir()
            except OSError:
                break
            parent = parent.parent
    for path, item in before.items():
        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(directory / "files" / item["backup"], dest)
        dest.chmod(item["mode"])
    # Imports after the upgrade may create bytecode absent from RECORD. Same-size
    # source restored within one second can otherwise reuse the upgraded bytecode.
    for path in before.keys() | after.keys():
        source = Path(path)
        if source.suffix == ".py":
            for cached in (source.parent / "__pycache__").glob(source.stem + ".*.pyc"):
                if str(cached) not in before:
                    cached.unlink()
    receipt["status"] = "rolled-back"
    receipt["rolled_back_at"] = datetime.now(UTC).isoformat()
    (directory / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt
