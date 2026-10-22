import json

import pytest

from patchwatch import cli, inventory, projects, scanner


@pytest.mark.parametrize(
    ("filename", "content", "eco", "name", "version"),
    [
        (
            "uv.lock",
            '[[package]]\nname="requests"\nversion="2.31.0"\nsource={registry="https://pypi.org/simple"}',
            "PyPI",
            "requests",
            "2.31.0",
        ),
        ("poetry.lock", '[[package]]\nname="requests"\nversion="2.31.0"', "PyPI", "requests", "2.31.0"),
        ("Pipfile.lock", '{"default":{"requests":{"version":"==2.31.0"}}}', "PyPI", "requests", "2.31.0"),
        ("requirements.txt", 'requests==2.31.0 ; python_version >= "3.8"\n', "PyPI", "requests", "2.31.0"),
        (
            "Cargo.lock",
            '[[package]]\nname="regex"\nversion="1.5.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"',
            "crates.io",
            "regex",
            "1.5.0",
        ),
        (
            "go.mod",
            "module example.com/app\nrequire (\n golang.org/x/text v0.3.0 // indirect\n)",
            "Go",
            "golang.org/x/text",
            "v0.3.0",
        ),
        (
            "composer.lock",
            '{"packages":[{"name":"symfony/http-foundation","version":"v5.0.0"}]}',
            "Packagist",
            "symfony/http-foundation",
            "5.0.0",
        ),
        (
            "Gemfile.lock",
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.10.0-x86_64-linux)\n      racc (~> 1.4)\n",
            "RubyGems",
            "nokogiri",
            "1.10.0",
        ),
        (
            "packages.lock.json",
            '{"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"12.0.1"}}}}',
            "NuGet",
            "Newtonsoft.Json",
            "12.0.1",
        ),
        (
            "pubspec.lock",
            'packages:\n  http:\n    source: hosted\n    version: "0.13.0"\n',
            "Pub",
            "http",
            "0.13.0",
        ),
        (
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\npackages:\n  '@scope/pkg@1.2.3': {}\n",
            "npm",
            "@scope/pkg",
            "1.2.3",
        ),
        (
            "pnpm-lock.yaml",
            "lockfileVersion: 5.4\npackages:\n  /@scope/pkg/1.2.3: {}\n",
            "npm",
            "@scope/pkg",
            "1.2.3",
        ),
        ("yarn.lock", '"@scope/pkg@^1.0.0":\n  version "1.2.3"\n', "npm", "@scope/pkg", "1.2.3"),
        (
            "yarn.lock",
            '__metadata:\n  version: 8\n"@scope/pkg@npm:^1.0.0":\n  version: 1.2.3\n  resolution: "@scope/pkg@npm:1.2.3"\n',
            "npm",
            "@scope/pkg",
            "1.2.3",
        ),
        (
            "gradle.lockfile",
            "# generated\norg.apache.logging.log4j:log4j-core:2.14.1=runtimeClasspath\nempty=\n",
            "Maven",
            "org.apache.logging.log4j:log4j-core",
            "2.14.1",
        ),
        (
            "mix.lock",
            '%{\n  "decimal": {:hex, :decimal, "2.0.0", "hash", [:mix], [], "hexpm", "hash"},\n}',
            "Hex",
            "decimal",
            "2.0.0",
        ),
    ],
)
def test_lockfiles(tmp_path, filename, content, eco, name, version):
    (tmp_path / filename).write_text(content)
    result = inventory.discover([tmp_path], homebrew=False, tools=False)
    assert not result["warnings"]
    assert [(p["ecosystem"], p["name"], p["version"]) for p in result["packages"]] == [(eco, name, version)]
    assert result["packages"][0]["project"] == str(tmp_path)
    assert result["projects"][0]["ecosystems"] == [eco]


def test_go_replacements_and_local_source(tmp_path):
    p = tmp_path / "go.mod"
    p.write_text(
        "require example.com/old v1.0.0\nrequire example.com/local v1.0.0\nreplace example.com/old => example.com/fork v2.0.0\nreplace example.com/local => ../local\n"
    )
    warnings = []
    found = projects.read(p, warnings)
    assert [(p["name"], p["version"]) for p in found] == [("example.com/fork", "v2.0.0")]
    assert any("local Go replacement" in w for w in warnings)


def test_unpinned_requirements_and_include_are_gaps(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests>=2.0\n-r ../other.txt\nflask==2.0.0\n")
    found = inventory.discover([tmp_path], homebrew=False, tools=False)
    assert len(found["warnings"]) == 2
    assert [p["name"] for p in found["packages"]] == ["flask"]


def test_manifest_without_lock_is_visible(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    found = inventory.discover([tmp_path], homebrew=False, tools=False)
    assert found["warnings"]
    assert found["projects"][0]["packages"] == 0


def test_malformed_lock_and_symlink_are_gaps(tmp_path):
    (tmp_path / "uv.lock").write_text("[[invalid")
    (tmp_path / "poetry.lock").symlink_to(tmp_path / "uv.lock")
    found = inventory.discover([tmp_path], homebrew=False, tools=False)
    assert len(found["warnings"]) == 2
    assert not found["packages"]


def test_monorepo_retains_locations_deduplicates_network(tmp_path, monkeypatch):
    for name in ["a", "b"]:
        directory = tmp_path / name
        directory.mkdir()
        (directory / "requirements.txt").write_text("demo==1.0.0")
    inv = inventory.discover([tmp_path], homebrew=False, tools=False)
    calls = []

    def query(*args):
        calls.append(args)
        return [{"id": "DEMO-1"}]

    monkeypatch.setattr(scanner, "osv_query", query)
    result = scanner.scan(inv, {"advisories": [], "updated": "today"}, "hash", osv=True)
    assert len(calls) == 1
    assert [p["findings"] for p in result["projects"]] == [1, 1]
    assert len(result["findings"]) == 2


def test_all_ecosystems_sent_to_osv(monkeypatch):
    calls = []
    monkeypatch.setattr(scanner, "osv_query", lambda *args: calls.append(args) or [])
    scanner.scan_osv([inventory.package(e, "demo", "1.0.0", e, "lockfile") for e in projects.ECOSYSTEMS])
    assert {c[0] for c in calls} == projects.ECOSYSTEMS


def test_project_mode_scopes_inventory_and_enables_osv(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PATCHWATCH_STATE_DIR", str(tmp_path / "state"))
    (tmp_path / "requirements.txt").write_text("example==1.0.0")

    def fail(*a, **k):
        pytest.fail("Project scan invoked a system command")

    monkeypatch.setattr(inventory.subprocess, "run", fail)
    calls = []
    monkeypatch.setattr(scanner, "osv_query", lambda *args: calls.append(args) or [])
    assert cli.main(["scan", "--project", str(tmp_path), "--json"]) == 0
    assert len(calls) == 1
    assert len(json.loads(capsys.readouterr().out)["projects"]) == 1
    calls.clear()
    assert cli.main(["scan", "--project", str(tmp_path), "--offline"]) == 0
    assert not calls


def test_npm_v1_nested_dependencies(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 1,
                "dependencies": {"a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}},
            }
        )
    )
    found = inventory.discover([tmp_path], homebrew=False, tools=False)
    assert {p["name"] for p in found["packages"]} == {"a", "b"}
    assert not found["warnings"]


def test_yarn_alias_uses_actual_package_identity(tmp_path):
    (tmp_path / "yarn.lock").write_text('"alias@npm:real-package@^1":\n  version "1.2.3"\n')
    found = inventory.discover([tmp_path], homebrew=False, tools=False)
    assert found["packages"][0]["name"] == "real-package"


def test_workspace_manifest_uses_ancestor_lock(tmp_path):
    (tmp_path / "uv.lock").write_text("version=1\npackage=[]")
    child = tmp_path / "member"
    child.mkdir()
    (child / "pyproject.toml").write_text('[project]\nname="member"')
    assert not inventory.discover([tmp_path], homebrew=False, tools=False)["warnings"]
    assert inventory.discover([child], homebrew=False, tools=False)["warnings"]


def test_project_remediation_has_directory_and_command(tmp_path):
    from patchwatch import catalog, remediation

    (tmp_path / "requirements.txt").write_text("requests==2.31.0")
    inv = inventory.discover([tmp_path], homebrew=False, tools=False)
    data, digest = catalog.load()
    actions = remediation.plan(scanner.scan(inv, data, digest))
    assert actions and all(a["working_directory"] == str(tmp_path) for a in actions)
    assert all(not a["supported"] for a in actions)


def test_osv_pagination_retains_all_results(monkeypatch):
    import io

    payloads = []

    def response(req, **kwargs):
        payloads.append(json.loads(req.data))
        data = (
            {"vulns": [{"id": "TWO"}]}
            if len(payloads) == 2
            else {"vulns": [{"id": "ONE"}], "next_page_token": "next"}
        )
        return io.BytesIO(json.dumps(data).encode())

    monkeypatch.setattr(scanner.urllib.request, "urlopen", response)
    assert [r["id"] for r in scanner.osv_query("Maven", "group:artifact", "1.0")] == ["ONE", "TWO"]
    assert payloads[1]["page_token"] == "next"


def test_maven_export_includes_transitive_dependencies(tmp_path):
    root = {
        "groupId": "app",
        "artifactId": "app",
        "version": "1.0",
        "children": [
            {
                "groupId": "org.example",
                "artifactId": "direct",
                "version": "2.0",
                "children": [{"groupId": "org.example", "artifactId": "transitive", "version": "3.0"}],
            }
        ],
    }
    (tmp_path / "maven-dependencies.json").write_text(json.dumps(root))
    (tmp_path / "pom.xml").write_text("<project/>")
    found = inventory.discover([tmp_path], homebrew=False, tools=False)
    assert not found["warnings"]
    assert {p["name"] for p in found["packages"]} == {"org.example:direct", "org.example:transitive"}


def test_scan_root_symlink_preserves_manifest_association(tmp_path):
    root = tmp_path / "real"
    root.mkdir()
    (root / "uv.lock").write_text("version=1\npackage=[]")
    (root / "pyproject.toml").write_text('[project]\nname="demo"')
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    assert not inventory.discover([alias], homebrew=False, tools=False)["warnings"]


def test_yarn_workspace_identity_is_project_source(tmp_path):
    (tmp_path / "yarn.lock").write_text(
        '__metadata:\n  version: 8\n"app@workspace:.":\n  version: 0.0.0-use.local\n  resolution: "app@workspace:."\n"lodash@npm:^4.17.20":\n  version: 4.17.20\n  resolution: "lodash@npm:4.17.20"\n'
    )
    found = inventory.discover([tmp_path], homebrew=False, tools=False)
    assert not found["warnings"]
    assert [p["name"] for p in found["packages"]] == ["lodash"]
