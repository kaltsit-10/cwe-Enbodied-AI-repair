#!/usr/bin/env python3
"""Validate paired base/head target-build evidence without promoting runtime status.

A paired build proves that the selected target was configured and compiled at both
pinned revisions under a comparable toolchain. It is deliberately weaker than a
runtime or semantic verdict.
"""
import argparse
import json
import re
import sys
from pathlib import Path

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_TOOLCHAIN_FIELDS = ("cmake", "compiler", "generator")


def _status(entry, key):
    value = entry.get(key)
    return value.get("status") if isinstance(value, dict) else None


def validate_evidence(record):
    """Return validation details for a base/head target-build evidence record."""
    errors = []
    case_id = record.get("case_id")
    target = record.get("target")
    base = record.get("base")
    head = record.get("head")

    if not isinstance(case_id, str) or not case_id:
        errors.append("case-id-missing")
    if not isinstance(target, str) or not target:
        errors.append("target-missing")
    if not isinstance(base, dict) or not isinstance(head, dict):
        errors.append("base-or-head-missing")
        return _result(record, errors)

    base_sha = base.get("sha")
    head_sha = head.get("sha")
    if not isinstance(base_sha, str) or len(base_sha) != 40:
        errors.append("base-sha-invalid")
    if not isinstance(head_sha, str) or len(head_sha) != 40:
        errors.append("head-sha-invalid")
    if base_sha == head_sha:
        errors.append("revisions-not-distinct")

    for label, entry in (("base", base), ("head", head)):
        if _status(entry, "configure") != "PASS":
            errors.append(f"{label}-configure-not-pass")
        build = entry.get("build")
        if not isinstance(build, dict):
            errors.append(f"{label}-build-missing")
            continue
        if build.get("status") != "PASS":
            errors.append(f"{label}-build-not-pass")
        if build.get("target") != target:
            errors.append(f"{label}-target-mismatch")
        if build.get("target_includes_contract_test") is not True:
            errors.append(f"{label}-contract-test-not-in-target")
        manifest = build.get("target_source_manifest")
        if not isinstance(manifest, str) or not manifest:
            errors.append(f"{label}-contract-test-manifest-missing")
        contract_test_source = build.get("contract_test_source")
        if not isinstance(contract_test_source, str) or not contract_test_source.endswith("rnn_op_test.cc"):
            errors.append(f"{label}-contract-test-source-missing")
        digest = build.get("binary_sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest.lower()):
            errors.append(f"{label}-binary-sha256-invalid")

    toolchain = record.get("toolchain")
    if not isinstance(toolchain, dict):
        errors.append("toolchain-missing")
    else:
        for field in REQUIRED_TOOLCHAIN_FIELDS:
            if not isinstance(toolchain.get(field), str) or not toolchain[field]:
                errors.append(f"toolchain-{field}-missing")

    runtime = record.get("runtime")
    if not isinstance(runtime, dict):
        errors.append("runtime-status-missing")
    else:
        for label in ("base", "head"):
            if runtime.get(label) not in {"NOT_RUN", "PASS", "REVIEW"}:
                errors.append(f"runtime-{label}-invalid")

    return _result(record, errors)


def _result(record, errors):
    valid = not errors
    return {
        "schema_version": 1,
        "case_id": record.get("case_id"),
        "target": record.get("target"),
        "valid": valid,
        "verdict": "PAIRED_BUILD_VERIFIED" if valid else "REVIEW",
        "errors": errors,
        "formal_proof": False,
        "proof_scope": "pinned base/head configure and selected target build only; runtime remains separate",
    }


def main():
    parser = argparse.ArgumentParser(description="Validate paired base/head target-build evidence")
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    record = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
    result = validate_evidence(record)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"verdict={result['verdict']}")
        for error in result["errors"]:
            print(f"  {error}")
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
