"""Real uv install + rollback, using local wheels and an isolated temporary venv."""

import base64
import csv
import hashlib
import io
import shutil
import subprocess
import zipfile

import pytest

from patchwatch import inventory, remediation, scanner


def wheel(version):
    name = "patchwatch_test_fixture"
    dist = f"{name}-{version}.dist-info"
    content = {
        f"{name}/__init__.py": f'VERSION = "{version}"\n'.encode(),
        f"{dist}/METADATA": f"Metadata-Version: 2.1\nName: patchwatch-test-fixture\nVersion: {version}\n".encode(),
        f"{dist}/WHEEL": b"Wheel-Version: 1.0\nGenerator: patchwatch-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    record = io.StringIO()
    writer = csv.writer(record)
    for path, data in content.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow([path, "sha256=" + digest, len(data)])
    writer.writerow([f"{dist}/RECORD", "", ""])
    content[f"{dist}/RECORD"] = record.getvalue().encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for path, data in content.items():
            archive.writestr(path, data)
    return output.getvalue()


def test_real_install_and_rollback(tmp_path, tiny_catalog, monkeypatch):
    uv = shutil.which("uv")
    if not uv:
        pytest.skip("uv required for real installer integration")
    root = tmp_path / "env"
    subprocess.run([uv, "venv", str(root)], check=True, capture_output=True)
    old = tmp_path / "patchwatch_test_fixture-1.0-py3-none-any.whl"
    old.write_bytes(wheel("1.0"))
    subprocess.run(
        [uv, "pip", "install", "--python", str(root / "bin/python"), str(old)],
        check=True,
        capture_output=True,
    )
    new = wheel("2.0")
    t = tiny_catalog["advisories"][0]["affected"][0]
    t["package"] = "patchwatch-test-fixture"
    t["artifact"] = {
        "url": "https://example.com/fixture.whl",
        "filename": "patchwatch_test_fixture-2.0-py3-none-any.whl",
        "sha256": hashlib.sha256(new).hexdigest(),
    }
    monkeypatch.setattr(remediation, "read_url", lambda *a, **k: new)
    inv = inventory.discover([root], homebrew=False, tools=False)
    action = remediation.plan(scanner.scan(inv, tiny_catalog, "digest"))[0]
    receipt = remediation.apply(action, tmp_path / "state")
    assert receipt["status"] == "verified-version", receipt
    command = [str(root / "bin/python"), "-I", "-c", "import patchwatch_test_fixture as p; print(p.VERSION)"]
    assert subprocess.check_output(command, text=True).strip() == "2.0"
    remediation.rollback(receipt["id"], tmp_path / "state")
    assert subprocess.check_output(command, text=True).strip() == "1.0"


def test_wheel_identity_mismatch_rejected():
    with pytest.raises(ValueError, match="does not match"):
        remediation.validate_wheel(wheel("2.0"), "another-package", "2.0")
