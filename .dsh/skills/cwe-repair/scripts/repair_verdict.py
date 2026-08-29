#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Evidence-gated verdict for a defensive repair candidate.

SEMANTIC_VERIFIED means the named local contract passed every configured
obligation. It is not a mathematical proof of arbitrary program behavior.
"""
import argparse
import importlib.util
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPT_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def runtime_gate(runtime):
    if not isinstance(runtime, dict):
        return False, "runtime-report-missing"
    if isinstance(runtime.get("runtime"), dict):
        runtime = runtime["runtime"]
    summary = runtime.get("summary", runtime)
    malicious = str(summary.get("malicious_rejected", ""))
    benign = str(summary.get("benign_passed", ""))
    infra = summary.get("infrastructure_failures", 0)
    if not malicious or "/" not in malicious or malicious.split("/", 1)[0] != malicious.split("/", 1)[1]:
        return False, "malicious-rejection-incomplete"
    if not benign or "/" not in benign or benign.split("/", 1)[0] != benign.split("/", 1)[1]:
        return False, "benign-regression-incomplete"
    if infra != 0:
        return False, "runtime-infrastructure-failure"
    if summary.get("verdict") not in (None, "PASS"):
        return False, "runtime-verdict-not-pass"
    return True, "malicious-and-benign-runtime-gates-pass"


def evaluate(before_source, after_source, cwe, pattern, runtime, provenance, symmetry_result=None, matrix_result=None):
    detector = load("cwe_detect")
    before = detector.detect_in_file(str(before_source), {cwe}, component="ncnn")
    after = detector.detect_in_file(str(after_source), {cwe}, component="ncnn")
    before_matches = [item for item in before if item.get("pattern") == pattern]
    after_matches = [item for item in after if item.get("pattern") == pattern]
    static_ok = bool(before_matches) and not after_matches

    if symmetry_result is None:
        symmetry_ok = True
        symmetry_reason = "not-configured"
    else:
        symmetry_ok = bool(symmetry_result.get("symmetric")) and not symmetry_result.get("findings")
        symmetry_reason = "symmetric" if symmetry_ok else "symmetry-findings-present"

    runtime_ok, runtime_reason = runtime_gate(runtime)
    provenance_ok = isinstance(provenance, dict) and all(provenance.get(key) for key in ("base_sha", "head_sha"))
    if matrix_result is None:
        matrix_ok = True
        matrix_reason = "not-configured"
    else:
        matrix_ok = matrix_result.get("status") == "MATRIX_VERIFIED"
        matrix_reason = matrix_result.get("reason", "matrix-review")
    gates = {
        "static_before_hit": bool(before_matches),
        "static_after_clear": not after_matches,
        "symmetry": symmetry_ok,
        "paired_path_matrix": matrix_ok,
        "runtime": runtime_ok,
        "provenance": provenance_ok,
    }
    if all(gates.values()):
        status = "SEMANTIC_VERIFIED"
        reason = "all configured local contract gates pass"
    elif not bool(before_matches):
        status = "REFUSE"
        reason = "before-image target pattern was not observed"
    else:
        status = "REVIEW"
        failed = [key for key, value in gates.items() if not value]
        reason = "failed gates: " + ", ".join(failed)
    return {
        "schema_version": 1,
        "status": status,
        "reason": reason,
        "proof_scope": "named-local-contract-path",
        "formal_proof": False,
        "gates": gates,
        "gate_reasons": {"runtime": runtime_reason, "symmetry": symmetry_reason, "paired_path_matrix": matrix_reason},
        "matrix": matrix_result,
        "static": {
            "before_count": len(before_matches),
            "after_count": len(after_matches),
            "before_lines": [item.get("line") for item in before_matches],
            "after_lines": [item.get("line") for item in after_matches],
        },
        "provenance": provenance or {},
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate evidence gates for a defensive repair")
    parser.add_argument("--before-source", required=True)
    parser.add_argument("--after-source", required=True)
    parser.add_argument("--cwe", required=True, type=int)
    parser.add_argument("--pattern", required=True)
    parser.add_argument("--runtime-json", required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--symmetry-json")
    parser.add_argument("--matrix-json")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    runtime = load_json(args.runtime_json)
    symmetry_result = load_json(args.symmetry_json) if args.symmetry_json else None
    matrix_result = None
    if args.matrix_json:
        matrix_module = load("contract_matrix")
        matrix_result = matrix_module.evaluate_matrix(load_json(args.matrix_json))
    result = evaluate(
        args.before_source,
        args.after_source,
        args.cwe,
        args.pattern,
        runtime,
        {"base_sha": args.base_sha, "head_sha": args.head_sha},
        symmetry_result,
        matrix_result,
    )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"status={result['status']}")
        print(f"reason={result['reason']}")
        print(f"gates={result['gates']}")
    return 0 if result["status"] == "SEMANTIC_VERIFIED" else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
