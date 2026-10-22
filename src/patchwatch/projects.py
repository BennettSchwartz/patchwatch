"""Extract resolved project dependencies as data, without invoking build tools."""

import json
import re
import tomllib
from pathlib import Path

import yaml
from packaging.requirements import Requirement

ECOSYSTEMS = {"PyPI", "npm", "Go", "crates.io", "RubyGems", "Packagist", "Maven", "NuGet", "Pub", "Hex"}
FILES = {
    "maven-dependencies.json",
    "uv.lock",
    "poetry.lock",
    "Pipfile.lock",
    "requirements.txt",
    "Cargo.lock",
    "go.mod",
    "composer.lock",
    "Gemfile.lock",
    "packages.lock.json",
    "pubspec.lock",
    "pnpm-lock.yaml",
    "yarn.lock",
    "gradle.lockfile",
    "buildscript-gradle.lockfile",
    "mix.lock",
}
MANIFESTS = {
    "pyproject.toml": {"uv.lock", "poetry.lock", "Pipfile.lock", "requirements.txt"},
    "package.json": {"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"},
    "Cargo.toml": {"Cargo.lock"},
    "composer.json": {"composer.lock"},
    "Gemfile": {"Gemfile.lock"},
    "pubspec.yaml": {"pubspec.lock"},
    "mix.exs": {"mix.lock"},
    "pom.xml": {"maven-dependencies.json"},
    "build.gradle": {"gradle.lockfile"},
    "build.gradle.kts": {"gradle.lockfile"},
}


def read(path, warnings):
    from .inventory import package

    out = []
    path = Path(path)

    def warn(message):
        warnings.append(f"{path}: {message}")

    def add(eco, name, ver, **extra):
        if not isinstance(name, str) or not isinstance(ver, str) or not re.fullmatch(r"v?\d[^\s]*", ver):
            raise ValueError("Dependency requires a resolved name and version")
        out.append(
            package(
                eco,
                name,
                ver,
                f"{path.resolve()}#{name}@{ver}",
                "lockfile",
                project=str(path.parent.resolve()),
                lockfile=str(path.resolve()),
                **extra,
            )
        )

    try:
        if path.is_symlink():
            raise ValueError("Symlinked dependency file requires an explicit scan of its owning project")
        if path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError("Dependency file exceeds size limit")
        text = path.read_text()
        name = path.name
        if name in {"uv.lock", "poetry.lock", "Cargo.lock"}:
            data = tomllib.loads(text)
            for p in data.get("package", []):
                source = p.get("source", {})
                if name == "Cargo.lock":
                    if source == "registry+https://github.com/rust-lang/crates.io-index":
                        add("crates.io", p["name"], p["version"])
                    elif source:
                        warn(f"Review external Cargo source for {p['name']}")
                elif (name == "uv.lock" and isinstance(source, dict) and "registry" in source) or (
                    name == "poetry.lock" and not source
                ):
                    add("PyPI", p["name"], p["version"])
                elif source and not (
                    isinstance(source, dict) and ("editable" in source or "virtual" in source)
                ):
                    warn(f"Review external Python source for {p['name']}")
        elif name == "Pipfile.lock":
            data = json.loads(text)
            for section in ("default", "develop"):
                for n, p in data.get(section, {}).items():
                    v = p.get("version", "")
                    if v.startswith("==") and "*" not in v:
                        add("PyPI", n, v[2:])
                    else:
                        warn(f"Unresolved dependency: {n}")
        elif name == "requirements.txt":
            for line in text.replace("\\\n", " ").splitlines():
                line = re.split(r"\s+#", line)[0].strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("-"):
                    warn("Requirements option or include requires review: " + line.split()[0])
                    continue
                req = Requirement(re.split(r"\s+--hash=", line)[0])
                specs = list(req.specifier)
                if len(specs) == 1 and specs[0].operator == "==" and "*" not in specs[0].version:
                    add("PyPI", req.name, specs[0].version)
                else:
                    warn(f"Pin a resolved version for {req.name}")
        elif name == "composer.lock":
            data = json.loads(text)
            for p in data.get("packages", []) + data.get("packages-dev", []):
                if re.fullmatch(r"v?\d[^\s]*", p["version"]):
                    add("Packagist", p["name"], p["version"].removeprefix("v"))
                else:
                    warn(f"Review development version for {p['name']}")
        elif name == "packages.lock.json":
            for deps in json.loads(text)["dependencies"].values():
                for n, p in deps.items():
                    if p.get("type", "").lower() != "project":
                        add("NuGet", n, p["resolved"])
        elif name == "pubspec.lock":
            for n, p in yaml.safe_load(text)["packages"].items():
                if p["source"] == "hosted":
                    add("Pub", n, p["version"])
                else:
                    warn(f"Review external Pub source for {n}")
        elif name == "pnpm-lock.yaml":
            data = yaml.safe_load(text)
            major = int(str(data["lockfileVersion"]).split(".")[0])
            if major not in {5, 6, 9}:
                raise ValueError("Supported pnpm lockfile versions: 5, 6, 9")
            for key in data.get("packages", {}):
                key = key.lstrip("/").split("(")[0]
                if major == 5:
                    n, v = key.rsplit("/", 1)
                else:
                    n, v = key.rsplit("@", 1)
                v = v.split("_")[0]
                add("npm", n, v)
        elif name == "yarn.lock":
            # Classic records use `version "..."`; Berry uses YAML and resolution identities.
            if "__metadata:" in text:
                for key, p in yaml.safe_load(text).items():
                    if key == "__metadata":
                        continue
                    resolution = p.get("resolution", "")
                    match = re.fullmatch(r"(.+)@(?:virtual:[^#]+#)?npm:(\d[^:]*)(?::.*)?", resolution)
                    if match:
                        add("npm", match[1], match[2])
                    else:
                        warn(f"Review Yarn resolution: {key}")
            else:
                selector = None
                for line in text.splitlines():
                    if line and not line[0].isspace() and not line.startswith("#"):
                        selector = line.split(", ")[0].strip('"').rstrip(":").strip('"')
                    elif selector and (m := re.match(r'  version "([^"]+)"', line)):
                        n, spec = selector.rsplit("@", 1)
                        if "@npm:" in n:
                            n = n.split("@npm:", 1)[1]
                        if spec.startswith(("http", "git", "file:", "link:")):
                            warn(f"Review external Yarn source for {n}")
                        else:
                            add("npm", n, m[1])
        elif name == "Gemfile.lock":
            section = ""
            for line in text.splitlines():
                if line and not line.startswith(" "):
                    section = line
                if m := re.fullmatch(r"    ([\w.-]+) \(([^)]+)\)", line):
                    if section == "GEM":
                        # Ruby platform suffix follows the gem release number.
                        add("RubyGems", m[1], re.split(r"-(?=java|ruby|x86|arm|aarch|universal)", m[2])[0])
                    else:
                        warn(f"Review external gem source for {m[1]}")
        elif name == "go.mod":
            required, replacements, section = {}, {}, ""
            for line in text.splitlines():
                line = line.split("//", 1)[0].strip()
                if not line:
                    continue
                if line == ")":
                    section = ""
                    continue
                if line in {"require (", "replace ("}:
                    section = line.split()[0]
                    continue
                parts = line.split()
                directive = section or parts.pop(0)
                if directive == "require" and len(parts) == 2:
                    required[(parts[0], parts[1])] = True
                elif directive == "replace" and "=>" in parts:
                    at = parts.index("=>")
                    replacements[tuple(parts[:at])] = parts[at + 1 :]
            for n, v in required:
                replacement = replacements.get((n, v), replacements.get((n,)))
                if replacement is not None:
                    if len(replacement) != 2:
                        warn(f"Review local Go replacement for {n}")
                        continue
                    n, v = replacement
                add("Go", n, v)
            if (path.parent / "go.work").exists():
                warn("Go workspace replacements require review against go.work")
        elif name.endswith("gradle.lockfile"):
            for line in text.splitlines():
                if line and not line.startswith(("#", "empty=")):
                    coordinate = line.split("=", 1)[0].split(":")
                    if len(coordinate) != 3:
                        raise ValueError("Invalid Gradle locked coordinate")
                    add("Maven", ":".join(coordinate[:2]), coordinate[2])
        elif name == "maven-dependencies.json":
            root = json.loads(text)
            if not all(k in root for k in ("groupId", "artifactId", "version")):
                raise ValueError("Expected a Maven dependency:tree JSON export")
            pending = list(root.get("children", []))
            while pending:
                node = pending.pop()
                add("Maven", node["groupId"] + ":" + node["artifactId"], node["version"])
                pending.extend(node.get("children", []))
        elif name == "mix.lock":
            for line in text.splitlines():
                if ":hex," in line:
                    m = re.search(r'\{:hex,\s*:(?:"([^"]+)"|([\w]+)),\s*"([^"]+)"', line)
                    if not m:
                        raise ValueError("Unsupported Hex lock entry")
                    add("Hex", m[1] or m[2], m[3])
                elif "=>" in line or ":git," in line:
                    warn("Review external Mix dependency")
        return list({p["id"]: p for p in out}.values())
    except (OSError, ValueError, TypeError, KeyError, AttributeError, yaml.YAMLError) as exc:
        warn(f"Dependency parsing failed: {exc}")
        return []


def summarize(packages, files):
    projects = {}
    for path in files:
        project = str(path.parent.resolve())
        projects.setdefault(project, {"path": project, "files": [], "ecosystems": set(), "packages": 0})[
            "files"
        ].append(str(path.resolve()))
    for p in packages:
        if p.get("project") in projects:
            entry = projects[p["project"]]
            entry["ecosystems"].add(p["ecosystem"])
            entry["packages"] += 1
    return [
        {**p, "files": sorted(set(p["files"])), "ecosystems": sorted(p["ecosystems"])}
        for p in sorted(projects.values(), key=lambda p: p["path"])
    ]


def update_guidance(pkg):
    """Return a manager command for operator review in the owning project."""
    filename = Path(pkg["lockfile"]).name
    name = pkg["name"]
    commands = {
        "uv.lock": ["uv", "lock", "--upgrade-package", name],
        "poetry.lock": ["poetry", "update", name],
        "Pipfile.lock": ["pipenv", "update", name],
        "package-lock.json": ["npm", "update", name, "--package-lock-only", "--ignore-scripts"],
        "npm-shrinkwrap.json": ["npm", "update", name, "--package-lock-only", "--ignore-scripts"],
        "pnpm-lock.yaml": ["pnpm", "update", name, "--lockfile-only", "--ignore-scripts"],
        "Cargo.lock": ["cargo", "update", "--package", name],
        "composer.lock": ["composer", "update", name, "--with-dependencies", "--no-scripts", "--no-plugins"],
        "Gemfile.lock": ["bundle", "update", name],
        "pubspec.lock": ["dart", "pub", "upgrade", name],
        "mix.lock": ["mix", "deps.update", name],
    }
    command = commands.get(filename)
    instruction = f"Run dependency updates in {pkg['project']}. Select an upstream fixed release, regenerate the dependency file, and rescan the project. Manifest constraints may need adjustment."
    return command, instruction
