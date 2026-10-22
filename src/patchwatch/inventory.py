"""Read installed metadata without importing packages or running discovered Python files."""

import email.parser
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from .catalog import canonical

PRUNE = {
    ".git",
    "node_modules",
    ".Trash",
    "Caches",
    "Cache",
    "cache",
    "caches",
    ".cache",
    "backups",
    "remediation-backups",
    "Containers",
    "Group Containers",
    "Mobile Documents",
    "Photos Library.photoslibrary",
    "DerivedData",
    ".next",
    "target",
}


def package_id(ecosystem, name, location):
    return hashlib.sha256(f"{ecosystem}\0{name}\0{location}".encode()).hexdigest()[:16]


def package(ecosystem, name, version, location, kind, **extra):
    location = str(location)
    return dict(
        id=package_id(ecosystem, name, location),
        ecosystem=ecosystem,
        name=name,
        version=version,
        location=location,
        kind=kind,
        **extra,
    )


def python_for(site):
    # Determine paths only. An explicit fix is required before running this interpreter.
    for parent in site.parents:
        if (parent / "pyvenv.cfg").is_file():
            return str(parent / ("Scripts/python.exe" if os.name == "nt" else "bin/python")), True
    match = re.search(r"python(\d+\.\d+)", str(site))
    if match:
        ver = match.group(1)
        for parent in site.parents:
            for candidate in [parent / "bin" / f"python{ver}", parent / f"python{ver}.exe"]:
                if candidate.is_file():
                    return str(candidate), False
    return None, False


def read_site(site, warnings):
    out = []
    python, venv = python_for(site)
    for dist in sorted(site.glob("*.dist-info")):
        try:
            meta_path = dist / "METADATA"
            if meta_path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError("oversized METADATA")
            meta = email.parser.Parser().parsestr(meta_path.read_text(errors="replace"))
            name, ver = meta.get("Name"), meta.get("Version")
            if not name or not ver:
                raise ValueError("missing name/version")
            out.append(
                package(
                    "PyPI",
                    canonical(name),
                    ver,
                    dist.resolve(),
                    "python",
                    site=str(site.resolve()),
                    python=python,
                    venv=venv,
                )
            )
        except (OSError, ValueError) as exc:
            warnings.append(f"{dist}: {exc}")
    return out


def read_npm(path, warnings):
    out = []
    try:
        if path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError("lockfile exceeds size limit")
        lock = json.loads(path.read_text())
        if lock.get("lockfileVersion", 0) < 2:
            warnings.append(f"{path}: npm lockfile v1 is not supported")
            return []
        for location, item in lock.get("packages", {}).items():
            if not location or not item.get("version") or item.get("link"):
                continue
            name = item.get("name") or location.rsplit("node_modules/", 1)[-1]
            out.append(package("npm", name, item["version"], f"{path.resolve()}#{location}", "lockfile"))
    except (OSError, ValueError, TypeError) as exc:
        warnings.append(f"{path}: {exc}")
    return out


def discover(roots, *, homebrew=True, tools=True, max_dirs=100000):
    out, warnings, sites, seeds, locks = [], [], set(), set(), set()
    visited = 0
    for root in roots:
        root = Path(root).expanduser().absolute()
        if not root.is_dir():
            warnings.append(f"Missing scan root: {root}")
            continue
        for base, dirs, names in os.walk(root, followlinks=False, onerror=lambda e: warnings.append(str(e))):
            visited += 1
            if visited > max_dirs:
                warnings.append(f"Directory budget {max_dirs} reached; inventory is incomplete")
                break
            dirs[:] = [d for d in dirs if d not in PRUNE and not Path(base, d).is_symlink()]
            p = Path(base)
            if p.name in {"site-packages", "dist-packages"}:
                sites.add(p.resolve())
                dirs[:] = []
            if p.name == "_bundled" and p.parent.name == "ensurepip":
                seeds.update(p / n for n in names if re.fullmatch(r"pip-[\d.]+-.*\.whl", n))
                dirs[:] = []
            if "package-lock.json" in names:
                locks.add(p / "package-lock.json")
        if visited > max_dirs:
            break
    for site in sorted(sites):
        out.extend(read_site(site, warnings))
    for seed in sorted(seeds):
        out.append(package("PyPI", "pip", seed.name.split("-")[1], seed, "python-seed"))
    for lock in sorted(locks):
        out.extend(read_npm(lock, warnings))
    if homebrew and shutil.which("brew"):
        try:
            cmd = [shutil.which("brew"), "info", "--json=v2", "--installed"]
            data = json.loads(
                subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=60).stdout
            )
            for formula in data["formulae"]:
                for installed in formula["installed"]:
                    out.append(
                        package(
                            "Homebrew",
                            formula["name"],
                            installed["version"],
                            f"brew:{formula['name']}:{installed['version']}",
                            "homebrew",
                            active=installed["version"]
                            == (formula.get("linked_keg") or formula.get("versions", {}).get("stable")),
                        )
                    )
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            warnings.append(f"Homebrew inventory failed: {exc}")
    if tools:
        for tool in ["uv", "bun", "node", "go", "pixi"]:
            exe = shutil.which(tool)
            if not exe:
                continue
            try:
                args = [exe, "version" if tool == "go" else "--version"]
                text = subprocess.run(args, check=True, capture_output=True, text=True, timeout=10).stdout
                found = re.search(r"\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?", text)
                if found:
                    out.append(package("Tool", tool, found.group(), exe, "tool", executable=exe))
                else:
                    warnings.append(f"Could not parse {tool} version")
            except (OSError, subprocess.SubprocessError) as exc:
                warnings.append(f"{tool} inventory failed: {exc}")
    if tools:
        for name, executable, arguments in [
            ("nginx", "nginx", ["-v"]),
            ("httpd", "httpd", ["-v"]),
            ("httpd", "apache2", ["-v"]),
            ("redis", "redis-server", ["--version"]),
            ("postgresql", "postgres", ["--version"]),
            ("mysql", "mysqld", ["--version"]),
        ]:
            exe = shutil.which(executable)
            if not exe:
                continue
            try:
                result = subprocess.run(
                    [exe, *arguments], check=True, capture_output=True, text=True, timeout=10
                )
                binary_output = result.stdout + result.stderr
                if executable == "mysqld" and "mariadb" in binary_output.lower():
                    name = "mariadb"
                found = re.search(r"\d+\.\d+(?:\.\d+)?", binary_output)
                if not found:
                    raise ValueError("Could not parse service binary version")
                out.append(
                    package(
                        "Service",
                        name,
                        found.group(),
                        exe,
                        "service",
                        executable=exe,
                        evidence="local binary version",
                    )
                )
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                warnings.append(f"{executable} inventory failed: {exc}")
    return {
        "packages": list({p["id"]: p for p in out}.values()),
        "warnings": warnings,
        "coverage": {
            "roots": [str(p) for p in roots],
            "directories": visited,
            "excluded_directory_names": sorted(PRUNE),
            "note": "Metadata inventory; does not prove runtime exploitability. App bundles, containers, remote hosts and unlisted roots are not covered.",
        },
    }


def default_roots():
    roots = [Path.home(), Path(sys.prefix)]
    for p in ["/opt/homebrew/lib", "/opt/homebrew/Cellar", "/usr/local/lib", "/Library/Frameworks"]:
        if Path(p).is_dir():
            roots.append(Path(p))
    return roots
