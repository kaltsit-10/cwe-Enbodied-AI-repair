#!/usr/bin/env python3
"""Validate paired local GoogleTest runtime evidence without semantic uplift.

The validator checks artifact binding (revision, binary hash, target) and the
recorded finite test counts. A successful result means the evidence records are
consistent; it is not a proof over untested inputs, providers, or configurations.
"""
import argparse
import json
import re
import sys
from pathlib import Path

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _load_relative(root, name, errors, label):
    if not isinstance(name, str) or not name:
        errors.append(f"{label}-evidence-name-missing")
        return None
    path = root / name
    if not path.is_file():
        errors.append(f"{label}-evidence-missing")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        errors.append(f"{label}-evidence-invalid-json")
        return None


def _single_suite_counts(evidence):
    cases = evidence.get("cases") if isinstance(evidence, dict) else None
    if not isinstance(cases, list) or len(cases) != 1 or not isinstance(cases[0], dict):
        return None
    case = cases[0]
    return {
        "expected": case.get("expected_test_count"),
        "run": case.get("tests_run"),
        "passed": case.get("tests_passed"),
        "failed": case.get("tests_failed"),
        "skipped": case.get("tests_skipped"),
    }


def _validate_side(label, side, root, target, errors):
    if not isinstance(side, dict):
        errors.append(f"{label}-missing")
        return
    sha = side.get("sha")
    digest = side.get("binary_sha256")
    if not isinstance(sha, str) or not SHA1_RE.fullmatch(sha.lower()):
        errors.append(f"{label}-sha-invalid")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest.lower()):
        errors.append(f"{label}-binary-sha256-invalid")

    focused = _load_relative(root, side.get("evidence"), errors, f"{label}-focused")
    suite = _load_relative(root, side.get("full_active_suite_evidence"), errors, f"{label}-suite")
    expected_filter_cases = side.get("focused_filter_case_count")
    expected_suite_tests = side.get("active_suite_expected_tests")

    if not isinstance(expected_filter_cases, int) or expected_filter_cases <= 0:
        errors.append(f"{label}-focused-count-invalid")
    if not isinstance(expected_suite_tests, int) or expected_suite_tests <= 0:
        errors.append(f"{label}-suite-count-invalid")

    for kind, evidence in (("focused", focused), ("suite", suite)):
        if evidence is None:
            continue
        if evidence.get("status") != "PASS":
            errors.append(f"{label}-{kind}-not-pass")
        if evidence.get("source_revision") != sha:
            errors.append(f"{label}-{kind}-revision-mismatch")
        if evidence.get("binary_sha256") != digest:
            errors.append(f"{label}-{kind}-binary-mismatch")
        if evidence.get("target") != target:
            errors.append(f"{label}-{kind}-target-mismatch")

    if focused is not None:
        cases = focused.get("cases")
        if not isinstance(cases, list) or len(cases) != expected_filter_cases:
            errors.append(f"{label}-focused-case-count-mismatch")
        elif any(item.get("status") != "PASS" for item in cases if isinstance(item, dict)):
            errors.append(f"{label}-focused-case-not-pass")

    if suite is not None:
        counts = _single_suite_counts(suite)
        if counts is None:
            errors.append(f"{label}-suite-shape-invalid")
        elif counts != {
            "expected": expected_suite_tests,
            "run": expected_suite_tests,
            "passed": expected_suite_tests,
            "failed": 0,
            "skipped": 0,
        }:
            errors.append(f"{label}-suite-count-mismatch")


def validate_evidence(record, root=None):
    """Return a no-uplift validation result for a paired runtime artifact."""
    errors = []
    if root is None:
        root = Path.cwd()
    else:
        root = Path(root)
    target = record.get("target")
    if not isinstance(record.get("case_id"), str) or not record.get("case_id"):
        errors.append("case-id-missing")
    if not isinstance(target, str) or not target:
        errors.append("target-missing")
    _validate_side("base", record.get("base"), root, target, errors)
    _validate_side("head", record.get("head"), root, target, errors)

    comparison = record.get("comparison")
    if not isinstance(comparison, dict) or comparison.get("shared_control_symmetry") != "PASS":
        errors.append("shared-control-symmetry-not-pass")
    if not isinstance(comparison, dict) or comparison.get("head_direct_regression_runtime") != "PASS":
        errors.append("head-direct-runtime-not-pass")

    return {
        "schema_version": 1,
        "case_id": record.get("case_id"),
        "target": target,
        "valid": not errors,
        "verdict": "PAIRED_RUNTIME_EVIDENCE_VERIFIED" if not errors else "REVIEW",
        "errors": errors,
        "formal_proof": False,
        "proof_scope": "pinned local GoogleTest evidence records only; untested contract dimensions remain outside scope",
    }


def main():
    parser = argparse.ArgumentParser(description="Validate paired local GoogleTest runtime evidence")
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    evidence_path = Path(args.evidence)
    record = json.loads(evidence_path.read_text(encoding="utf-8"))
    result = validate_evidence(record, evidence_path.parent)
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
