#!/usr/bin/env python3
"""Validate portable embodied-AI deployment profile metadata."""
import argparse
import json
from pathlib import Path

REQUIRED_ENTRY_FIELDS = {
    "input_source", "runtime_stage", "hardware_dependency", "failure_mode",
    "control_impact", "risk_labels", "real_robot_execution",
}
ALLOWED_INPUTS = {"model_file", "tensor_shape", "sensor_message", "pointcloud", "image", "joint_command"}
ALLOWED_STAGES = {"ingest", "preprocess", "inference", "postprocess", "control_boundary"}
ALLOWED_IMPACTS = {"none", "indirect", "direct"}


def validate_profile(profile, contract_names=None):
    errors = []
    if not isinstance(profile, dict):
        return {"valid": False, "errors": ["profile-not-object"]}
    if profile.get("schema_version") != 1:
        errors.append("profile-schema-version-invalid")
    if profile.get("profile") != "embodied-ai-runtime-safety":
        errors.append("profile-name-invalid")
    if profile.get("universal_claim") is not False or profile.get("formal_proof") is not False:
        errors.append("profile-claim-boundary-invalid")
    labels = profile.get("risk_labels")
    if not isinstance(labels, list) or not labels or not all(isinstance(item, str) and item for item in labels):
        errors.append("profile-risk-labels-invalid")
    entries = profile.get("contracts")
    if not isinstance(entries, dict) or not entries:
        errors.append("profile-contracts-invalid")
        entries = {}
    if contract_names is not None:
        for name in contract_names:
            if name not in entries:
                errors.append("profile-contract-missing:" + name)
    for name, entry in entries.items():
        if not isinstance(entry, dict):
            errors.append("profile-entry-not-object:" + name)
            continue
        missing = REQUIRED_ENTRY_FIELDS - set(entry)
        if missing:
            errors.append("profile-entry-missing:" + name + ":" + ",".join(sorted(missing)))
            continue
        if entry["input_source"] not in ALLOWED_INPUTS:
            errors.append("profile-entry-input-invalid:" + name)
        if entry["runtime_stage"] not in ALLOWED_STAGES:
            errors.append("profile-entry-stage-invalid:" + name)
        if entry["control_impact"] not in ALLOWED_IMPACTS:
            errors.append("profile-entry-impact-invalid:" + name)
        if entry["real_robot_execution"] is not False:
            errors.append("profile-entry-real-robot-not-false:" + name)
        if not isinstance(entry["hardware_dependency"], list) or not entry["hardware_dependency"]:
            errors.append("profile-entry-hardware-invalid:" + name)
        if not isinstance(entry["risk_labels"], list) or not entry["risk_labels"]:
            errors.append("profile-entry-risk-labels-invalid:" + name)
        elif not set(entry["risk_labels"]).issubset(set(labels)):
            errors.append("profile-entry-unknown-risk-label:" + name)
    return {"valid": not errors, "errors": errors}


def main():
    parser = argparse.ArgumentParser(description="Validate an embodied-AI deployment profile")
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--contracts", nargs="*", default=[])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        profile = json.loads(args.profile.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        result = {"valid": False, "errors": ["profile-read-invalid"]}
    else:
        result = validate_profile(profile, args.contracts or None)
    print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else "valid=" + str(result["valid"]).lower())
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
