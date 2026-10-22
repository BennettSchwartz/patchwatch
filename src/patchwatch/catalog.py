"""Validated catalogs. Remote data never becomes executable shell text."""

import hashlib
import json
import os
import re
import urllib.request
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlsplit

import jsonschema
from packaging.specifiers import SpecifierSet
from packaging.version import Version

MAX_BYTES = 8 * 1024 * 1024


def read_url(url, *, limit=MAX_BYTES):
    if urlsplit(url).scheme != "https":
        raise ValueError("Only HTTPS catalog/artifact URLs are accepted")
    req = urllib.request.Request(url, headers={"User-Agent": "patchwatch/0.1"})
    with urllib.request.urlopen(req, timeout=30) as response:
        if urlsplit(response.url).scheme != "https":
            raise ValueError("Refusing HTTPS downgrade")
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Download exceeds size limit")
    return data


def validate(data):
    schema = json.loads(files("patchwatch").joinpath("data/schema.json").read_text())
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(data)
    ids = set()
    for advisory in data["advisories"]:
        if advisory["id"] in ids:
            raise ValueError(f"Duplicate advisory ID: {advisory['id']}")
        ids.add(advisory["id"])
        for target in advisory["affected"]:
            spec = SpecifierSet(target["versions"])
            if not target["versions"].strip():
                raise ValueError("Affected version range cannot be empty")
            fixed = target.get("fixed")
            if fixed and Version(fixed) in spec:
                raise ValueError(f"Fixed version {fixed} is still in the affected range")
            if target.get("artifact") and not fixed:
                raise ValueError("Artifacts require a fixed version")
            if target.get("artifact") and not target["artifact"]["filename"].endswith(".whl"):
                raise ValueError("Only wheel artifacts are supported")
    return data


def load(path=None):
    if path is None:
        raw = files("patchwatch").joinpath("data/catalog.json").read_bytes()
    else:
        raw = Path(path).read_bytes()
    if len(raw) > MAX_BYTES:
        raise ValueError("Catalog exceeds size limit")
    return validate(json.loads(raw)), hashlib.sha256(raw).hexdigest()


def sync(url, destination, expected_sha256=None):
    data = read_url(url)
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 and digest != expected_sha256.lower():
        raise ValueError("Catalog SHA-256 mismatch; cached catalog unchanged")
    validate(json.loads(data))
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)
    return digest


def canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def version(value, ecosystem):
    # Homebrew uses _N for formula revisions; compare those as post releases.
    if ecosystem == "Homebrew":
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:_\d+)?", value):
            value = value.replace("-", ".")
        value = value.replace("_", ".post")
    return Version(value)
