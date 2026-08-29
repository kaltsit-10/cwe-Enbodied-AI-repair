#!/usr/bin/env python3
"""Produce a conservative, machine-readable cwe-repair release audit."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
EXAMPLES = SKILL_DIR / "examples"
DEFAULT_BASELINE = EXAMPLES / "release_baseline.json"
DEFAULT_REPORT = EXAMPLES / "release_audit_report.json"
CONTRACTS = (
    "ncnn_pr6383_asset_semantic_contract.json",
    "ncnn_pr6383_two_text_failure_asset_contract.json",
    "ncnn_pr6383_four_parser_paths_asset_contract.json",
    "ort_pr28003_safeint_helper_asset_contract.json",
    "ort_pr28003_rnn_narrowing_scoped_contract.json",
    "ort_pr28003_asset_semantic_contract.json",
)
SENSITIVE_NAMES = (".credentials.yaml", ".env", "id_rsa", "id_ed25519")
EXPECTED_VERDICTS = {
    "ncnn_pr6383_asset_semantic_contract.json": "ASSET_SCOPE_COMPLETE",
    "ncnn_pr6383_two_text_failure_asset_contract.json": "ASSET_SCOPE_COMPLETE",
    "ncnn_pr6383_four_parser_paths_asset_contract.json": "ASSET_SCOPE_COMPLETE",
    "ort_pr28003_safeint_helper_asset_contract.json": "ASSET_SCOPE_COMPLETE",
    "ort_pr28003_rnn_narrowing_scoped_contract.json": "REVIEW",
    "ort_pr28003_asset_semantic_contract.json": "REVIEW",
}
PROFILE = EXAMPLES / "embodied_ai_profile.json"
REGISTRY = EXAMPLES / "embodied_ai_pr_case_registry.json"
READINESS_QUEUE = EXAMPLES / "embodied_ai_pr_readiness_queue.json"
EVALUATION_MANIFEST = EXAMPLES / "evaluation_manifest.json"
SOURCE_SLICE_PLAN = EXAMPLES / "agibot_jointcmd_source_slice_plan.json"


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_validator():
    spec = importlib.util.spec_from_file_location("asset_semantic_contract", SCRIPT_DIR / "asset_semantic_contract.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def audit(baseline_path):
    validator = load_validator()
    errors = []
    discovered_contracts = tuple(sorted(
        path.name for path in EXAMPLES.glob("*.json")
        if path.name.endswith(("_asset_contract.json", "_semantic_contract.json", "_scoped_contract.json"))
    ))
    inventory_result = {
        "status": "PASS" if set(discovered_contracts) == set(CONTRACTS) else "MISMATCH",
        "discovered": list(discovered_contracts),
        "declared": list(CONTRACTS),
    }
    if inventory_result["status"] != "PASS":
        errors.append("formal-contract-inventory-mismatch")
    contracts = []
    for name in CONTRACTS:
        path = EXAMPLES / name
        if not path.is_file():
            errors.append("contract-missing:" + name)
            continue
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            errors.append("contract-json-invalid:" + name)
            continue
        result = validator.validate_asset_record(record, base_dir=EXAMPLES)
        contracts.append({"file": name, "sha256": digest(path), "result": result})
        if not result["valid"]:
            errors.append("contract-artifact-invalid:" + name)
        if result["verdict"] != EXPECTED_VERDICTS[name]:
            errors.append("contract-verdict-unexpected:" + name)

    profile_result = {"status": "MISSING"}
    if PROFILE.is_file():
        try:
            profile = json.loads(PROFILE.read_text(encoding="utf-8"))
            profile_contracts = profile.get("contracts", {})
            required_fields = {"input_source", "runtime_stage", "hardware_dependency", "failure_mode", "control_impact", "risk_labels", "real_robot_execution"}
            missing_profiles = [name for name in CONTRACTS if name not in profile_contracts]
            invalid_profiles = []
            for name, entry in profile_contracts.items():
                if name not in CONTRACTS:
                    continue
                if not isinstance(entry, dict) or not required_fields.issubset(entry):
                    invalid_profiles.append(name)
                    continue
                if entry["real_robot_execution"] is not False or not isinstance(entry["risk_labels"], list) or not entry["risk_labels"]:
                    invalid_profiles.append(name)
            profile_result = {
                "status": "PASS" if not missing_profiles and not invalid_profiles else "INCOMPLETE",
                "missing": missing_profiles,
                "invalid": invalid_profiles,
            }
            if missing_profiles:
                errors.append("embodied-profile-incomplete")
            if invalid_profiles:
                errors.append("embodied-profile-entry-invalid")
            profile_spec = importlib.util.spec_from_file_location("embodied_profile_validate", SCRIPT_DIR / "embodied_profile_validate.py")
            profile_validator = importlib.util.module_from_spec(profile_spec)
            profile_spec.loader.exec_module(profile_validator)
            core_profile = profile_validator.validate_profile(profile, CONTRACTS)
            profile_result["core_errors"] = core_profile["errors"]
            if not core_profile["valid"]:
                errors.append("embodied-profile-core-invalid")
        except json.JSONDecodeError:
            profile_result = {"status": "INVALID"}
            errors.append("embodied-profile-json-invalid")
    else:
        errors.append("embodied-profile-missing")

    queue_result = {"status": "MISSING"}
    if REGISTRY.is_file() and READINESS_QUEUE.is_file():
        try:
            readiness_spec = importlib.util.spec_from_file_location("pr_case_readiness", SCRIPT_DIR / "pr_case_readiness.py")
            readiness = importlib.util.module_from_spec(readiness_spec)
            readiness_spec.loader.exec_module(readiness)
            snapshot = readiness.validate_queue_snapshot(
                json.loads(REGISTRY.read_text(encoding="utf-8")),
                json.loads(READINESS_QUEUE.read_text(encoding="utf-8")),
            )
            queue_result = {"status": "PASS" if snapshot["valid"] else "DRIFT", "errors": snapshot["errors"]}
            if not snapshot["valid"]:
                errors.append("readiness-queue-drift")
        except json.JSONDecodeError:
            queue_result = {"status": "INVALID"}
            errors.append("readiness-queue-json-invalid")
    else:
        errors.append("readiness-queue-or-registry-missing")

    source_slice_result = {"status": "MISSING"}
    if SOURCE_SLICE_PLAN.is_file():
        try:
            slice_spec = importlib.util.spec_from_file_location("source_slice_plan_validate", SCRIPT_DIR / "source_slice_plan_validate.py")
            slice_validator = importlib.util.module_from_spec(slice_spec)
            slice_spec.loader.exec_module(slice_validator)
            slice_check = slice_validator.validate(
                json.loads(SOURCE_SLICE_PLAN.read_text(encoding="utf-8")), SKILL_DIR.parent.parent.parent, allow_unavailable_source=True
            )
            source_slice_result = {
                "status": "PASS" if slice_check["valid"] else "INVALID",
                "plan_status": slice_check.get("status"),
                "source_anchors": slice_check.get("source_anchors"),
                "errors": slice_check["errors"],
            }
            if not slice_check["valid"]:
                errors.append("source-slice-plan-invalid")
        except json.JSONDecodeError:
            source_slice_result = {"status": "INVALID", "errors": ["plan-json-invalid"]}
            errors.append("source-slice-plan-json-invalid")
    else:
        errors.append("source-slice-plan-missing")

    evaluation_result = {"status": "MISSING"}
    if EVALUATION_MANIFEST.is_file():
        try:
            evaluation_spec = importlib.util.spec_from_file_location("evaluation_summary", SCRIPT_DIR / "evaluation_summary.py")
            evaluation = importlib.util.module_from_spec(evaluation_spec)
            evaluation_spec.loader.exec_module(evaluation)
            evaluation_check = evaluation.validate(json.loads(EVALUATION_MANIFEST.read_text(encoding="utf-8")), EXAMPLES)
            evaluation_result = {"status": "PASS" if evaluation_check["valid"] else "INVALID", "errors": evaluation_check["errors"]}
            if not evaluation_check["valid"]:
                errors.append("evaluation-manifest-invalid")
        except json.JSONDecodeError:
            evaluation_result = {"status": "INVALID", "errors": ["manifest-json-invalid"]}
            errors.append("evaluation-manifest-json-invalid")
    else:
        errors.append("evaluation-manifest-missing")

    baseline_result = {"status": "MISSING"}
    if baseline_path.is_file():
        try:
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            expected = baseline.get("protected_files", {})
            mismatches = []
            for name, expected_sha in expected.items():
                path = EXAMPLES / name
                if not path.is_file() or digest(path) != expected_sha:
                    mismatches.append(name)
            baseline_result = {"status": "PASS" if not mismatches else "MISMATCH", "mismatches": mismatches}
            if mismatches:
                errors.append("protected-artifact-hash-mismatch")
        except json.JSONDecodeError:
            baseline_result = {"status": "INVALID"}
            errors.append("baseline-json-invalid")
    else:
        errors.append("baseline-missing")

    sensitive = []
    for needle in SENSITIVE_NAMES:
        sensitive.extend(str(path.relative_to(SKILL_DIR)) for path in SKILL_DIR.rglob(needle))
    if sensitive:
        errors.append("sensitive-file-present")

    for item in contracts:
        record = item["result"]
        if record["universal_claim"] or record["formal_proof"]:
            errors.append("claim-boundary-invalid:" + item["file"])

    return {
        "schema_version": 1,
        "tool": "cwe-repair-release-audit",
        "scope": "artifact-backed embodied-AI runtime release only",
        "contracts": contracts,
        "formal_contract_inventory": inventory_result,
        "protected_artifacts": baseline_result,
        "embodied_profile": profile_result,
        "readiness_queue": queue_result,
        "evaluation_manifest": evaluation_result,
        "source_slice_plan": source_slice_result,
        "sensitive_files": sensitive,
        "errors": errors,
        "verdict": "PASS" if not errors else "REVIEW",
        "release_boundary": {
            "real_robot_execution": False,
            "network_target_execution": False,
            "universal_claim": False,
            "formal_proof": False,
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Audit cwe-repair release artifacts")
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--out", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = audit(args.baseline)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else "verdict=" + result["verdict"])
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
