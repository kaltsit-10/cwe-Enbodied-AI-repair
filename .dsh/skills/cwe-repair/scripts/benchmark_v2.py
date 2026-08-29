#!/usr/bin/env python3
"""Benchmark v2 for provenance-aware historical repair-pair evaluation.

This is intentionally separate from cwe_leaderboard.py. It evaluates fixed
before/after anchors and reports independent dimensions instead of folding
runtime or postimage evidence into the legacy strict numerator.
"""
import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
WORKSPACE = SCRIPT_DIR.parents[3]
DEFAULT_DATA = SCRIPT_DIR.parent / "examples" / "ncnn_history_benchmark_v2.json"
REQUIRED_CASE_FIELDS = {
    "id", "project", "pr_url", "pr_number", "base_sha", "head_sha",
    "before_source", "after_source", "contract", "cwe", "expected_pattern",
    "provenance_status", "upstream_state", "strict_eligible", "runtime_artifact",
    "postimage_markers", "runtime",
}
VALID_RUNTIME_STATUS = {"PASS", "REVIEW", "NOT_APPLICABLE"}


def load_detector():
    spec = importlib.util.spec_from_file_location("cwe_detect_v2", SCRIPT_DIR / "cwe_detect.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_json(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def validate_data(data):
    errors = []
    if data.get("schema_version") != 2:
        errors.append({"schema_version": data.get("schema_version")})
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        errors.append({"cases": "non-empty list required"})
        return errors
    ids = set()
    for case in cases:
        case_id = case.get("id") if isinstance(case, dict) else None
        if case_id in ids:
            errors.append({"case": case_id, "duplicate_id": True})
        ids.add(case_id)
        if not isinstance(case, dict):
            errors.append({"case": case_id, "not_object": True})
            continue
        missing = sorted(REQUIRED_CASE_FIELDS - case.keys())
        if missing:
            errors.append({"case": case_id, "missing": missing})
        for field in ("pr_url", "base_sha", "head_sha", "before_source", "after_source", "contract", "expected_pattern"):
            if field in case and not isinstance(case[field], str):
                errors.append({"case": case_id, "not_string": field})
        if not isinstance(case.get("pr_number"), int) or isinstance(case.get("pr_number"), bool):
            errors.append({"case": case_id, "invalid_pr_number": True})
        if case.get("provenance_status") not in {"official-local-materialized", "official-local-materialized-upstream-open", "external-reference", "local-only"}:
            errors.append({"case": case_id, "invalid_provenance_status": case.get("provenance_status")})
        if case.get("upstream_state") not in {"merged", "open", "unknown"}:
            errors.append({"case": case_id, "invalid_upstream_state": case.get("upstream_state")})
        if not isinstance(case.get("strict_eligible"), bool):
            errors.append({"case": case_id, "strict_eligible_not_bool": True})
        if case.get("upstream_state") == "open" and case.get("strict_eligible"):
            errors.append({"case": case_id, "open_pr_strict_eligible": True})
        artifact = case.get("runtime_artifact")
        if not isinstance(artifact, str) or not artifact:
            errors.append({"case": case_id, "runtime_artifact_invalid": True})
        elif "external-reference" in artifact:
            errors.append({"case": case_id, "runtime_artifact_external": True})
        elif not (WORKSPACE / artifact.replace("/", os.sep)).is_file():
            errors.append({"case": case_id, "runtime_artifact_missing": artifact})
        markers = case.get("postimage_markers")
        if not isinstance(markers, list) or not markers or any(not isinstance(item, str) for item in markers):
            errors.append({"case": case_id, "invalid_postimage_markers": True})
        allowed_residual = case.get("allowed_postimage_residual_patterns", [])
        if not isinstance(allowed_residual, list) or any(not isinstance(item, str) for item in allowed_residual):
            errors.append({"case": case_id, "invalid_allowed_postimage_residual_patterns": True})
        if allowed_residual and not case.get("evaluation_scope"):
            errors.append({"case": case_id, "scoped_residual_without_scope": True})
        runtime = case.get("runtime")
        if not isinstance(runtime, dict):
            errors.append({"case": case_id, "runtime_not_object": True})
        else:
            for field in ("rejection", "benign"):
                value = runtime.get(field)
                if value not in VALID_RUNTIME_STATUS:
                    errors.append({"case": case_id, "invalid_runtime": field})
            if runtime.get("infrastructure_failures") is not None:
                value = runtime["infrastructure_failures"]
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    errors.append({"case": case_id, "invalid_infrastructure_failures": True})
            if runtime.get("rejection") == "PASS" and runtime.get("infrastructure_failures", 0) != 0:
                errors.append({"case": case_id, "runtime_pass_with_infra_failure": True})
    return errors


def marker_present(text, marker):
    try:
        return re.search(marker, text, re.MULTILINE) is not None
    except re.error:
        return marker in text


def evaluate_case(case, detector):
    result = {
        "id": case["id"], "contract": case["contract"], "cwe": case["cwe"],
        "upstream_state": case["upstream_state"],
        "strict_eligible": case["strict_eligible"],
        "runtime_artifact": case["runtime_artifact"],
    }
    before_path = case["before_source"]
    after_path = case["after_source"]
    before_exists = os.path.isfile(before_path)
    after_exists = os.path.isfile(after_path)
    result["source_available"] = {"before": before_exists, "after": after_exists}
    if before_exists:
        before = detector.detect_in_file(before_path, {int(case["cwe"])}, component="ncnn")
        before_matches = [x for x in before if x.get("pattern") == case["expected_pattern"]]
    else:
        before_matches = []
    if after_exists:
        after = detector.detect_in_file(after_path, {int(case["cwe"])}, component="ncnn")
        after_matches = [x for x in after if x.get("pattern") == case["expected_pattern"]]
    else:
        after_matches = []
    result["preimage_detection"] = {
        "status": "HIT" if before_matches else ("REVIEW" if not before_exists else "MISS"),
        "matches": [{"line": x.get("line"), "evidence": x.get("evidence", "")} for x in before_matches],
    }
    allowed_residual = set(case.get("allowed_postimage_residual_patterns", []))
    scoped_residual = after_matches and allowed_residual and all(
        x.get("pattern") in allowed_residual for x in after_matches
    )
    if not after_exists:
        postimage_status = "REVIEW"
    elif not after_matches:
        postimage_status = "GUARDED"
    elif scoped_residual:
        postimage_status = "GUARDED_SCOPED"
    else:
        postimage_status = "MISS"
    result["postimage_guard"] = {
        "status": postimage_status,
        "evaluation_scope": case.get("evaluation_scope", "whole-file"),
        "residual_matches": [{"line": x.get("line"), "pattern": x.get("pattern"),
                              "evidence": x.get("evidence", "")} for x in after_matches],
        "residual_note": case.get("allowed_postimage_residual_note", "") if scoped_residual else "",
    }
    marker_results = []
    if after_exists:
        with open(after_path, encoding="utf-8", errors="replace") as stream:
            text = stream.read()
        marker_results = [{"marker": marker, "present": marker_present(text, marker)}
                          for marker in case["postimage_markers"]]
    result["postimage_markers"] = marker_results
    result["runtime"] = case["runtime"]
    result["provenance"] = {
        "status": case["provenance_status"],
        "upstream_state": case["upstream_state"],
        "complete": case["provenance_status"] in {"official-local-materialized", "official-local-materialized-upstream-open", "local-only"} and before_exists and after_exists and bool(case.get("runtime_artifact")), 
        "pr_url": case["pr_url"],
        "base_sha": case["base_sha"],
        "head_sha": case["head_sha"],
    }
    return result


def summarize(results):
    def count(field, value):
        return sum(1 for item in results if item.get(field, {}).get("status") == value)
    return {
        "cases": len(results),
        "preimage_detection": {"HIT": count("preimage_detection", "HIT"), "total": len(results)},
        "postimage_guard": {
            "GUARDED": count("postimage_guard", "GUARDED"),
            "GUARDED_SCOPED": count("postimage_guard", "GUARDED_SCOPED"),
            "MISS": count("postimage_guard", "MISS"),
            "REVIEW": count("postimage_guard", "REVIEW"),
            "total": len(results),
        },
        "runtime_rejection_pass": sum(1 for item in results if item["runtime"].get("rejection") == "PASS"),
        "runtime_benign_pass": sum(1 for item in results if item["runtime"].get("benign") == "PASS"),
        "runtime_infrastructure_failures": sum(item["runtime"].get("infrastructure_failures", 0) for item in results),
        "provenance_complete": sum(1 for item in results if item["provenance"].get("complete")),
        "strict_eligible_cases": sum(1 for item in results if item.get("strict_eligible")),
        "strict_eligible_preimage_hits": sum(1 for item in results
                                              if item.get("strict_eligible") and item["preimage_detection"].get("status") == "HIT"),
        "legacy_benchmark_untouched": True,
    }


def main():
    parser = argparse.ArgumentParser(description="Run provenance-aware benchmark v2")
    parser.add_argument("--data", default=str(DEFAULT_DATA))
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    data = read_json(args.data)
    errors = validate_data(data)
    if errors:
        output = {"valid": False, "errors": errors}
        print(json.dumps(output, ensure_ascii=False, indent=1))
        raise SystemExit(1)
    if args.validate_only:
        print(json.dumps({"valid": True, "cases": len(data["cases"])}, ensure_ascii=False, indent=1))
        return
    detector = load_detector()
    results = [evaluate_case(case, detector) for case in data["cases"]]
    output = {"valid": True, "schema_version": 2, "summary": summarize(results), "results": results}
    print(json.dumps(output, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
