#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Evaluate paired-entry safety contracts for defensive repair evidence.

The matrix is deliberately explicit: a path is covered only when its source,
postimage patterns, guard markers, and full runtime verdict are all present. A
separate scoped_runtime record can describe bounded evidence, but it never
satisfies the full runtime gate. An operator_runtime record may report a real
full-target execution for selected subcases, but is display-only until the full
contract runtime gate passes. This is not formal verification; it is a
conservative path-coverage gate.
"""
import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent


def load_detector():
    spec = importlib.util.spec_from_file_location("cwe_detect_matrix", SCRIPT_DIR / "cwe_detect.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def marker_present(text, marker):
    try:
        return re.search(marker, text, re.MULTILINE) is not None
    except re.error:
        return marker in text


def _ratio_pass(value):
    if not isinstance(value, str) or "/" not in value:
        return False
    left, right = value.split("/", 1)
    try:
        return int(left.strip()) > 0 and int(left.strip()) == int(right.strip())
    except ValueError:
        return False


def scoped_runtime_summary(runtime, scoped_runtime=None):
    runtime_note = str(runtime.get("note", "")).lower() if isinstance(runtime, dict) else ""
    runtime_is_scoped = any(marker in runtime_note for marker in ("reduced", "scoped", "bounded"))
    if isinstance(runtime, dict) and runtime.get("verdict") == "PASS" and not runtime_is_scoped:
        return {"scope": "full", "verdict": "PASS"}
    candidate = scoped_runtime if isinstance(scoped_runtime, dict) else runtime
    if not isinstance(candidate, dict):
        return {"scope": "none", "verdict": None}
    note = str(candidate.get("note", "")).lower()
    reduced = runtime_is_scoped or any(marker in note for marker in ("reduced", "scoped", "bounded"))
    if candidate.get("verdict") == "PASS" and scoped_runtime is not None:
        reduced = True
    if reduced and _ratio_pass(candidate.get("malicious_rejected")) and _ratio_pass(candidate.get("benign_passed")) and candidate.get("infrastructure_failures", 1) == 0:
        return {"scope": "scoped", "verdict": "PASS"}
    return {"scope": "none", "verdict": None}


def operator_runtime_summary(operator_runtime):
    """Describe actual target execution without allowing a contract-gate uplift."""
    if not isinstance(operator_runtime, dict) or operator_runtime.get("verdict") != "PASS":
        return {"scope": "none", "verdict": None}
    scope = operator_runtime.get("scope", "local-full-target-partial-contract")
    if not isinstance(scope, str) or not scope:
        scope = "local-full-target-partial-contract"
    return {"scope": scope, "verdict": "PASS"}


def evaluate_matrix(spec):
    detector = load_detector()
    errors = []
    paths = spec.get("paths")
    if not isinstance(paths, list) or not paths:
        return {"status": "REVIEW", "reason": "paths-missing", "paths": [], "errors": ["paths must be non-empty"]}

    results = []
    for path_spec in paths:
        path_id = path_spec.get("id", "unknown")
        source = path_spec.get("source", "")
        cwe = path_spec.get("cwe")
        pattern = path_spec.get("residual_pattern")
        required_markers = path_spec.get("required_markers", [])
        runtime = path_spec.get("runtime", {})
        scoped_runtime = path_spec.get("scoped_runtime")
        operator_runtime = path_spec.get("operator_runtime")
        allowed_residual_lines = {int(line) for line in path_spec.get("allowed_residual_lines", [])}
        row_errors = []
        exists = bool(source) and os.path.isfile(source)
        if not exists:
            row_errors.append("source-missing")
        if not isinstance(cwe, int) or not pattern:
            row_errors.append("detector-contract-missing")
        findings = detector.detect_in_file(source, {cwe}, component=spec.get("component", "ncnn")) if exists and isinstance(cwe, int) else []
        residual = [item for item in findings if item.get("pattern") == pattern]
        scoped_residual = [item for item in residual if item.get("line") not in allowed_residual_lines]
        marker_results = []
        if exists:
            text = Path(source).read_text(encoding="utf-8", errors="replace")
            marker_results = [{"marker": marker, "present": marker_present(text, marker)} for marker in required_markers]
            if any(not item["present"] for item in marker_results):
                row_errors.append("guard-marker-missing")
        else:
            marker_results = [{"marker": marker, "present": False} for marker in required_markers]
        runtime_status = runtime.get("verdict") if isinstance(runtime, dict) else None
        runtime_scope = scoped_runtime_summary(runtime, scoped_runtime)
        operator_scope = operator_runtime_summary(operator_runtime)
        if runtime_status != "PASS":
            row_errors.append("runtime-not-pass")
        if scoped_residual:
            row_errors.append("postimage-residual")
        results.append({
            "id": path_id,
            "source": source,
            "source_exists": exists,
            "residual_pattern": pattern,
            "residual_count": len(scoped_residual),
            "residual_total": len(residual),
            "allowed_residual_lines": sorted(allowed_residual_lines),
            "residual_lines": [item.get("line") for item in residual],
            "scoped_residual_lines": [item.get("line") for item in scoped_residual],
            "required_markers": marker_results,
            "runtime": runtime,
            "scoped_runtime": scoped_runtime,
            "operator_runtime": operator_runtime,
            "runtime_scope": runtime_scope["scope"],
            "scoped_runtime_verdict": runtime_scope["verdict"],
            "operator_runtime_scope": operator_scope["scope"],
            "operator_runtime_verdict": operator_scope["verdict"],
            "status": "PASS" if not row_errors else "REVIEW",
            "errors": row_errors,
        })

    expected_ids = spec.get("required_path_ids", [item.get("id") for item in paths])
    actual_ids = [item.get("id") for item in paths]
    missing_ids = [path_id for path_id in expected_ids if path_id not in actual_ids]
    if missing_ids:
        errors.append("required-path-missing:" + ",".join(missing_ids))
    if len({item.get("contract") for item in paths}) > 1:
        errors.append("paths-use-different-contract-labels")
    if errors or any(item["status"] != "PASS" for item in results):
        status = "REVIEW"
        reason = "paired-path-contract-incomplete"
    else:
        status = "MATRIX_VERIFIED"
        reason = "all declared paired paths satisfy the named contract"
    return {
        "schema_version": 1,
        "status": status,
        "reason": reason,
        "contract": spec.get("contract", "unnamed"),
        "path_count": len(results),
        "paths": results,
        "errors": errors,
        "formal_proof": False,
        "proof_scope": "declared-paired-paths-only",
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate a paired-entry defensive contract matrix")
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    spec = json.loads(Path(args.matrix).read_text(encoding="utf-8"))
    result = evaluate_matrix(spec)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"status={result['status']}")
        print(f"reason={result['reason']}")
        for item in result["paths"]:
            print(f"  {item['id']}: {item['status']} residual={item['residual_count']} errors={item['errors']}")
    return 0 if result["status"] == "MATRIX_VERIFIED" else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
