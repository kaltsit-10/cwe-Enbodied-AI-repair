#!/usr/bin/env python3
"""Validate a clean public cwe-repair repository clone."""
import hashlib
import importlib.util
import json
import py_compile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / ".dsh" / "skills" / "cwe-repair"
SCRIPTS = SKILL / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def load(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_manifest():
    manifest = ROOT / "SHA256SUMS"
    if not manifest.is_file():
        raise SystemExit("SHA256SUMS missing")
    entries = {}
    for line in manifest.read_text(encoding="utf-8-sig").splitlines():
        if not line.strip():
            continue
        digest, relative = line.split("  ", 1)
        entries[relative] = digest
    for relative, expected in entries.items():
        path = ROOT / relative
        if not path.is_file() or sha256(path) != expected:
            raise SystemExit("SHA256SUMS mismatch: " + relative)


def main():
    required = (ROOT / "README.md", ROOT / "LICENSE", ROOT / "NOTICE", ROOT / "SECURITY.md", ROOT / "CONTRIBUTING.md", ROOT / "SHA256SUMS", SKILL / "SKILL.md")
    missing = [str(path.relative_to(ROOT)) for path in required if not path.is_file()]
    if missing:
        raise SystemExit("required files missing: " + ", ".join(missing))
    for path in SCRIPTS.glob("*.py"):
        py_compile.compile(str(path), doraise=True)
    for path in SKILL.rglob("*.json"):
        json.loads(path.read_text(encoding="utf-8-sig"))
    audit = load(SCRIPTS / "release_audit.py")
    report = audit.audit(audit.DEFAULT_BASELINE)
    if report["verdict"] != "PASS":
        raise SystemExit("release audit failed: " + ", ".join(report["errors"]))
    verify_manifest()
    print("public release validation: PASS")


if __name__ == "__main__":
    main()
