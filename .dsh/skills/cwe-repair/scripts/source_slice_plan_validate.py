#!/usr/bin/env python3
"""Validate source-bound local fake-sink materialization plans."""
import argparse
import hashlib
import json
from pathlib import Path

REQUIRED_SAFETY = ("no_network_target_execution", "no_real_robot_execution", "no_real_actuator_execution", "no_can_or_serial_execution", "no_oom_or_huge_allocation", "no_exploit_chain")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(plan, workspace, allow_unavailable_source=False):
    errors = []
    if not isinstance(plan, dict) or plan.get("schema_version") != 1:
        return {"valid": False, "errors": ["plan-schema-invalid"]}
    if plan.get("status") not in {"REVIEW", "READY_TO_BUILD", "MATERIALIZED"}:
        errors.append("plan-status-invalid")
    if plan.get("universal_claim") is not False or plan.get("formal_proof") is not False:
        errors.append("plan-claim-boundary-invalid")
    root = workspace / plan.get("source_root", "")
    source_available = root.is_dir()
    if not source_available and not allow_unavailable_source:
        errors.append("source-root-missing")
    anchors = plan.get("source_anchors")
    anchor_errors = []
    if not isinstance(anchors, list) or not anchors:
        anchor_errors.append("source-anchors-invalid")
    else:
        for index, anchor in enumerate(anchors):
            if not isinstance(anchor, dict) or not isinstance(anchor.get("path"), str) or not isinstance(anchor.get("sha256"), str):
                anchor_errors.append("source-anchor-invalid:" + str(index))
                continue
            if source_available:
                path = root / anchor["path"]
                if not path.is_file():
                    anchor_errors.append("source-anchor-missing:" + anchor["path"])
                elif digest(path) != anchor["sha256"]:
                    anchor_errors.append("source-anchor-hash-mismatch:" + anchor["path"])
    errors.extend(anchor_errors)
    safety = plan.get("safety", {})
    if not isinstance(safety, dict) or any(safety.get(key) is not True for key in REQUIRED_SAFETY):
        errors.append("plan-safety-incomplete")
    for key in ("slice_interfaces", "required_runtime_evidence", "environment_prerequisites", "current_blockers", "completion_boundary"):
        if key not in plan:
            errors.append("plan-field-missing:" + key)
    return {
        "valid": not errors,
        "errors": errors,
        "status": plan.get("status"),
        "source_anchors": "VERIFIED" if source_available and not anchor_errors else "UNAVAILABLE" if not source_available else "INVALID",
    }


def main():
    parser = argparse.ArgumentParser(description="Validate a source-slice materialization plan")
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--workspace", default=".", type=Path)
    parser.add_argument("--allow-unavailable-source", action="store_true", help="validate plan structure when external source is intentionally absent")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = validate(json.loads(args.plan.read_text(encoding="utf-8")), args.workspace, args.allow_unavailable_source)
    except (OSError, json.JSONDecodeError):
        result = {"valid": False, "errors": ["plan-read-invalid"]}
    print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else "valid=" + str(result["valid"]).lower())
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
