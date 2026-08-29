#!/usr/bin/env python3
"""Validate and summarize the reproducible evaluation plan without fabricating baselines."""
import argparse
import json
from pathlib import Path

REQUIRED_METRICS = {
    "precision", "recall", "f1", "guarded_false_positive_rate", "repair_plan_coverage",
    "symmetry_detection_rate", "malicious_rejection_rate", "benign_preservation_rate",
    "contract_completion_rate", "runtime_cost",
}


def validate(manifest, base_dir):
    errors = []
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        return {"valid": False, "errors": ["manifest-schema-invalid"]}
    boundary = manifest.get("claim_boundary", {})
    if boundary.get("universal_claim") is not False or boundary.get("formal_proof") is not False or boundary.get("real_robot_execution") is not False:
        errors.append("manifest-claim-boundary-invalid")
    corpus = manifest.get("corpus", {})
    for key in ("legacy_benchmark", "registry", "readiness_queue"):
        value = corpus.get(key)
        if not isinstance(value, str) or not (base_dir / value).is_file():
            errors.append("manifest-corpus-file-invalid:" + key)
    if set(manifest.get("metrics", [])) != REQUIRED_METRICS:
        errors.append("manifest-metrics-invalid")
    environment_file = manifest.get("environment_evidence")
    environment = None
    if not isinstance(environment_file, str) or not (base_dir / environment_file).is_file():
        errors.append("manifest-environment-evidence-invalid")
    else:
        try:
            environment = json.loads((base_dir / environment_file).read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            errors.append("manifest-environment-evidence-json-invalid")
    methods = manifest.get("methods", [])
    ids = {method.get("id") for method in methods if isinstance(method, dict)}
    if not {"cwe-repair", "cppcheck", "semgrep", "codeql"}.issubset(ids):
        errors.append("manifest-methods-incomplete")
    for method in methods:
        if not isinstance(method, dict) or method.get("status") not in {"measured-local", "pending-environment"}:
            errors.append("manifest-method-status-invalid")
            continue
        if method["status"] == "pending-environment" and not isinstance(method.get("reason"), str):
            errors.append("manifest-pending-method-reason-missing:" + str(method.get("id")))
        if environment is not None and method.get("id") in {"cppcheck", "semgrep", "codeql"}:
            available = environment.get("tools", {}).get(method["id"], {}).get("available")
            if method["status"] == "measured-local" and available is not True:
                errors.append("manifest-measured-baseline-unavailable:" + method["id"])
    for simulation in manifest.get("scoped_simulations", []):
        if not isinstance(simulation, dict) or simulation.get("status") != "measured-local-reduced":
            errors.append("manifest-simulation-status-invalid")
            continue
        evidence = simulation.get("evidence")
        if not isinstance(evidence, str) or not (base_dir / evidence).is_file():
            errors.append("manifest-simulation-evidence-invalid")
        if simulation.get("included_in_production_runtime_metrics") is not False or simulation.get("included_in_asset_scope_complete_metrics") is not False:
            errors.append("manifest-simulation-boundary-invalid")
    return {"valid": not errors, "errors": errors}


def summarize(manifest):
    methods = manifest["methods"]
    return {
        "methods": {method["id"]: method["status"] for method in methods},
        "measured_methods": [method["id"] for method in methods if method["status"] == "measured-local"],
        "pending_methods": [method["id"] for method in methods if method["status"] == "pending-environment"],
        "reduced_simulations": [item.get("id") for item in manifest.get("scoped_simulations", [])],
        "metrics": manifest["metrics"],
        "comparative_claim": "NOT_AVAILABLE until external baselines use normalized commands and mappings",
    }


def main():
    parser = argparse.ArgumentParser(description="Validate cwe-repair evaluation manifest")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        result = {"valid": False, "errors": ["manifest-read-invalid"]}
    else:
        result = validate(manifest, args.manifest.parent)
        if result["valid"]:
            result["summary"] = summarize(manifest)
    print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else "valid=" + str(result["valid"]).lower())
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
