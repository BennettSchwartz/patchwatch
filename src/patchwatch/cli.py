import argparse
import json
import os
import plistlib
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import __version__, catalog, importers, intelligence, inventory, remediation, scanner


def state_path():
    return Path(os.environ.get("PATCHWATCH_STATE_DIR", Path.home() / ".local/state/patchwatch"))


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2) + "\n")
    temp.chmod(0o600)
    os.replace(temp, path)


def clean(text):
    return "".join(c if c.isprintable() else " " for c in str(text))


def output(data, json_output):
    if json_output:
        print(json.dumps(data, indent=2))
        return
    if isinstance(data, dict) and "action" in data and "status" in data:
        data = [data]
    if isinstance(data, dict) and "findings" in data:
        print(
            f"{len(data['packages'])} packages; {len(data['findings'])} findings; {len(data['warnings'])} coverage warnings"
        )
        for project in data.get("projects", []):
            print(
                clean(
                    f"Project {project['path']}: {project['packages']} dependencies, {project['findings']} findings"
                )
            )
        for f in data["findings"]:
            p = f["package"]
            print(
                clean(
                    f"[{f['severity']}] {p['name']} {p['version']} -> {f['target'].get('fixed') or 'review'}  {f['advisory']}"
                )
            )
            print(clean(f"  {p['location']}"))
            signals = f.get("exploitation", {})
            if signals:
                kev = (
                    "CISA KEV listed"
                    if signals["kev_status"] == "listed"
                    else "CISA KEV: " + signals["kev_status"]
                )
                scores = signals.get("epss", {})
                suffix = "; ".join(
                    f"{c}: EPSS {v['probability']:.1%} ({v['date']})" for c, v in scores.items()
                )
                print("  " + clean(kev + ("; " + suffix if suffix else "")))
        for warning in data["warnings"]:
            print("WARNING: " + clean(warning))
    elif isinstance(data, list) and all("supported" in a for a in data):
        for a in data:
            p = a["package"]
            target = a["target_version"] or (
                "manager-resolved release" if a.get("adapter") == "project" else "review"
            )
            print(
                clean(
                    f"{a['id']}  {p['name']} {p['version']} -> {target}  {'READY' if a['supported'] else 'MANUAL'}"
                )
            )
            print("  " + clean(a["reason"]))
            print("  " + clean(p["location"]))
            if a.get("adapter") == "project":
                print(
                    "  "
                    + clean(
                        "Dependencies: " + ", ".join(p["name"] + " " + p["version"] for p in a["packages"])
                    )
                )
                print("  " + clean("Publish verified dependency files: " + ", ".join(a["files"])))
                print("  " + clean("Working directory: " + a["working_directory"]))
            for cmd in a["commands"]:
                print("  Suggested command: " + clean(shlex.join(cmd)))
            for instruction in a["instructions"]:
                if instruction:
                    print("  " + clean(instruction))
    elif isinstance(data, list) and all("status" in item for item in data):
        for receipt in data:
            action = receipt.get("action", {})
            name = action.get("package", {}).get("name", "update")
            print(clean(f"[{receipt['status']}] {name}"))
            if receipt.get("id"):
                print("  Receipt: " + receipt["id"])
            if receipt.get("error"):
                print("  " + clean(receipt["error"]))
            for package in receipt.get("resolved_packages", []):
                print("  " + clean(package["name"] + " -> " + package["version"]))
            if action.get("adapter") == "project" and receipt["status"] == "verified-version":
                print("  Dependency files updated. Sync the project environment and run its tests.")
            if receipt["status"] == "manual":
                print("  " + clean(action.get("reason", "Review this action")))
    else:
        print(json.dumps(data, indent=2))


def read_config(state):
    path = state / "config.json"
    return json.loads(path.read_text()) if path.exists() else {}


def get_catalog(args, state, *, refresh=False):
    if args.catalog:
        return catalog.load(args.catalog)
    config = read_config(state)
    cached = state / "catalog.json"
    if refresh and config.get("catalog_url"):
        catalog.sync(config["catalog_url"], cached, config.get("catalog_sha256"))
    return catalog.load(cached if cached.exists() else None)


def collect(args):
    if args.project and args.root:
        raise ValueError("Choose --project or --root for scan scope")
    roots = args.project or args.root or inventory.default_roots()
    result = inventory.discover(
        roots,
        homebrew=not (args.no_homebrew or args.project),
        tools=not (args.no_tools or args.project),
        max_dirs=args.max_dirs,
    )
    for value in args.tool:
        name, sep, version = value.partition("=")
        if not sep or not name or not version:
            raise ValueError("--tool requires NAME=VERSION")
        result["packages"].append(inventory.package("Tool", name, version, "declared:" + name, "declared"))
    for value in args.service:
        name, sep, observed_version = value.partition("=")
        if not sep or not name or not observed_version:
            raise ValueError("--service requires NAME=VERSION")
        result["packages"].append(
            inventory.package(
                "Service",
                name,
                observed_version,
                "declared:" + name,
                "declared-service",
                evidence="user-declared version",
            )
        )
    return result


def get_report(args, state, *, refresh=False):
    data, digest = get_catalog(args, state, refresh=refresh)
    report = scanner.scan(
        collect(args), data, digest, osv=(args.osv or bool(args.project)) and not args.offline
    )
    return intelligence.enrich(report) if args.intelligence and not args.offline else report


class RunLock:
    def __init__(self, state):
        self.path = state / "operation.lock"

    def __enter__(self):
        # OS-managed lock: automatically released on process exit, including crashes.
        import fcntl

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = self.path.open("a+")
        try:
            fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.file.close()
            raise ValueError("Another Patchwatch update/watch cycle is running") from None
        return self

    def __exit__(self, *args):
        self.file.close()


def fix_report(report, args, state):
    actions = remediation.plan(report)
    if args.only:
        requested = set(args.only)
        missing = requested - {a["id"] for a in actions}
        if missing:
            raise ValueError("Unknown action IDs: " + ", ".join(sorted(missing)))
        actions = [a for a in actions if a["id"] in requested]
    if not args.json or not args.apply:
        output(actions, args.json)
    if report["warnings"]:
        for warning in report["warnings"]:
            print("WARNING: " + clean(warning), file=sys.stderr)
        return 2
    apply_updates = args.apply
    ready = [a for a in actions if a["supported"]]
    if (
        not apply_updates
        and ready
        and args.command == "fix"
        and not args.json
        and sys.stdin.isatty()
        and sys.stdout.isatty()
    ):
        try:
            answer = input(f"Apply {len(ready)} update action(s)? [y/N] ").strip().lower()
        except EOFError:
            answer = ""
        apply_updates = answer in {"y", "yes"}
    if not apply_updates:
        return 1 if actions else 0
    receipts = []
    for action in actions:
        if action["supported"]:
            receipts.append(remediation.apply(action, state))
        else:
            receipts.append({"status": "manual", "action": action})
    output(receipts, args.json)
    return 1 if any(r["status"] != "verified-version" for r in receipts) else 0


def scan_arguments(parser):
    parser.add_argument(
        "--root",
        action="append",
        help="Directory to inspect; repeatable. Default: home and runtime locations",
    )
    parser.add_argument(
        "--project", action="append", metavar="PATH", help="Scan project dependencies with OSV; repeatable"
    )
    parser.add_argument("--offline", action="store_true", help="Use the local catalog for this scan")
    parser.add_argument("--catalog", type=Path, help="Explicit local catalog")
    parser.add_argument("--osv", action="store_true", help="Query OSV using package names and versions")
    parser.add_argument("--no-homebrew", action="store_true")
    parser.add_argument("--no-tools", action="store_true")
    parser.add_argument("--max-dirs", type=int, default=100000)
    parser.add_argument(
        "--tool", action="append", default=[], help="Declare an additional tool as NAME=VERSION"
    )
    parser.add_argument("--service", action="append", default=[], help="Declare a service as NAME=VERSION")
    parser.add_argument(
        "--intelligence", action="store_true", help="Prioritize findings with CISA KEV and FIRST EPSS"
    )
    parser.add_argument("--json", action="store_true")


def parser():
    p = argparse.ArgumentParser(
        prog="patchwatch", description="Find vulnerable installed packages and apply reviewed fixes"
    )
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)
    for name in ["inventory", "scan", "plan", "fix", "watch"]:
        c = sub.add_parser(name)
        scan_arguments(c)
        if name in {"fix", "watch"}:
            c.add_argument(
                "--apply",
                "--yes",
                "-y",
                dest="apply",
                action="store_true",
                help="Approve supported updates for unattended execution",
            )
            c.add_argument("--only", action="append", default=[], help="Restrict fixes to action IDs")
        if name == "scan":
            c.add_argument("--output", type=Path)
        if name == "watch":
            c.add_argument("--interval", type=int, default=86400)
            c.add_argument("--once", action="store_true")
            c.add_argument("--max-runs", type=int, default=0)
    c = sub.add_parser("catalog")
    cs = c.add_subparsers(dest="catalog_command", required=True)
    v = cs.add_parser("validate")
    v.add_argument("path", type=Path)
    s = cs.add_parser("sync")
    s.add_argument("--url", required=True, help="HTTPS URL; immutable GitHub raw commit URL recommended")
    s.add_argument("--sha256", help="Optional independently verified catalog checksum")
    e = cs.add_parser("export")
    e.add_argument("path", type=Path)
    imp = cs.add_parser("import")
    source = imp.add_mutually_exclusive_group(required=True)
    source.add_argument("--github", help="GitHub Advisory Database GHSA identifier")
    source.add_argument("--cve", help="CVE List identifier with an explicit product/version mapping")
    imp.add_argument("--output", type=Path, required=True, help="Catalog file to create or extend")
    imp.add_argument("--ecosystem", choices=["PyPI", "npm", "Homebrew", "Tool", "Service"])
    imp.add_argument("--package")
    imp.add_argument("--versions")
    imp.add_argument("--fixed")
    imp.add_argument("--instructions")
    r = sub.add_parser("rollback")
    r.add_argument("run_id")
    r.add_argument("--apply", action="store_true", required=True)
    sub.add_parser("status")
    s = sub.add_parser("schedule")
    s.add_argument("action", choices=["install", "remove", "show"])
    s.add_argument("--interval", type=int, default=86400)
    s.add_argument("--root", action="append", default=[])
    s.add_argument("--project", action="append", default=[])
    s.add_argument("--offline", action="store_true")
    s.add_argument("--osv", action="store_true")
    s.add_argument("--intelligence", action="store_true")
    s.add_argument("--apply", action="store_true", help="Enable automatic supported fixes in scheduled runs")
    return p


def schedule(args, state):
    if sys.platform != "darwin":
        raise ValueError(
            "Built-in scheduling currently supports macOS; use watch --once with cron/systemd elsewhere"
        )
    path = Path.home() / "Library/LaunchAgents/com.patchwatch.agent.plist"
    domain = f"gui/{os.getuid()}"
    if args.action == "show":
        print(path.read_text() if path.exists() else "No schedule installed")
        return 0
    if args.action == "remove":
        if path.exists():
            subprocess.run(["launchctl", "bootout", domain, str(path)], capture_output=True)
            path.unlink()
        print("Schedule removed")
        return 0
    if args.interval < 60:
        raise ValueError("Schedule interval must be at least 60 seconds")
    if path.exists():
        raise ValueError("Schedule exists; remove it before replacing")
    exe = shutil.which("patchwatch")
    if not exe:
        raise ValueError("Install patchwatch on PATH before scheduling")
    command = [exe, "watch", "--once"]
    for root in args.root:
        command += ["--root", str(Path(root).expanduser().absolute())]
    if args.project and args.root:
        raise ValueError("Choose --project or --root for scan scope")
    for project in args.project:
        command += ["--project", str(Path(project).expanduser().absolute())]
    if args.offline:
        command.append("--offline")
    if args.osv:
        command.append("--osv")
    if args.intelligence:
        command.append("--intelligence")
    if args.apply:
        command.append("--apply")
    content = dict(
        Label="com.patchwatch.agent",
        ProgramArguments=command,
        StartInterval=args.interval,
        RunAtLoad=True,
        StandardOutPath=str(state / "schedule.log"),
        StandardErrorPath=str(state / "schedule-error.log"),
        EnvironmentVariables={
            "PATCHWATCH_STATE_DIR": str(state),
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        },
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(content))
    result = subprocess.run(["launchctl", "bootstrap", domain, str(path)], capture_output=True, text=True)
    if result.returncode:
        path.unlink()
        raise ValueError("launchctl bootstrap failed: " + result.stderr)
    print(
        f"Installed: every {args.interval} seconds; automatic fixes {'enabled' if args.apply else 'disabled'}"
    )
    return 0


def main(argv=None):
    args = parser().parse_args(argv)
    state = state_path().expanduser().absolute()
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        if args.command == "catalog":
            if args.catalog_command == "validate":
                data, digest = catalog.load(args.path)
                print(f"Valid: {len(data['advisories'])} advisories; SHA-256 {digest}")
            elif args.catalog_command == "export":
                data, _ = catalog.load()
                write_json(args.path, data)
                print(args.path)
            elif args.catalog_command == "import":
                advisory = (
                    importers.from_github(args.github)
                    if args.github
                    else importers.from_cve(
                        args.cve,
                        ecosystem=args.ecosystem,
                        package=args.package,
                        versions=args.versions,
                        fixed=args.fixed,
                        instructions=args.instructions,
                    )
                )
                with RunLock(state):
                    data = (
                        catalog.load(args.output)[0]
                        if args.output.exists()
                        else {"schema_version": 1, "updated": "2026-01-01T00:00:00Z", "advisories": []}
                    )
                    write_json(args.output, importers.merge(data, advisory))
                print(f"Imported {advisory['id']} into {args.output}; review the entry before distribution")
            else:
                with RunLock(state):
                    digest = catalog.sync(args.url, state / "catalog.json", args.sha256)
                    write_json(state / "config.json", dict(catalog_url=args.url, catalog_sha256=args.sha256))
                print(f"Catalog synchronized: {digest}")
            return 0
        if args.command == "status":
            report = state / "last-report.json"
            output(
                json.loads(report.read_text()) if report.exists() else {"status": "No monitoring run yet"},
                False,
            )
            return 0
        if args.command == "schedule":
            return schedule(args, state)
        if args.command == "rollback":
            with RunLock(state):
                output(remediation.rollback(args.run_id, state), False)
            return 0
        if args.max_dirs < 1:
            raise ValueError("--max-dirs must be positive")
        if args.command == "inventory":
            output(collect(args), args.json)
            return 0
        if args.command == "watch":
            if args.interval < 60 or args.max_runs < 0:
                raise ValueError("Watch interval must be >=60 seconds and max-runs >=0")
            count = 0
            while True:
                with RunLock(state):
                    report = get_report(args, state, refresh=True)
                    write_json(state / "last-report.json", report)
                    output(report, args.json)
                    result = 2 if report["warnings"] else 1 if report["findings"] else 0
                    if args.apply:
                        if report["warnings"]:
                            raise ValueError("Incomplete scan; automatic updates skipped")
                        result = fix_report(report, args, state)
                        write_json(state / "last-report.json", get_report(args, state))
                count += 1
                if args.once or (args.max_runs and count >= args.max_runs):
                    return result
                time.sleep(args.interval)
        if args.command == "fix":
            with RunLock(state):
                report = get_report(args, state)
                if args.apply and report["warnings"]:
                    raise ValueError(
                        "Incomplete scan; narrow --root or resolve coverage warnings before applying"
                    )
                return fix_report(report, args, state)
        report = get_report(args, state)
        if args.command == "plan":
            output(remediation.plan(report), args.json)
        else:
            output(report, args.json)
            if args.output:
                write_json(args.output, report)
        return 2 if report["warnings"] else 1 if report["findings"] else 0
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print("patchwatch: " + clean(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        # Schema/network errors are operational failures, never clean scans.
        print("patchwatch: " + clean(exc), file=sys.stderr)
        return 2
