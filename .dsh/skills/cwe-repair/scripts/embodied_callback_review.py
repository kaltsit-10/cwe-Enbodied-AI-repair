#!/usr/bin/env python3
"""Source-bound review for bounded joint-command callback semantics.

This is a static embodied-AI profile rule. It does not execute ROS, AimRT,
network transports, controllers, or actuators, and it never claims runtime
control-chain validation.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

COMMAND_FIELDS = ("effort", "velocity", "position", "stiffness", "damping")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def review(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    errors = []
    for marker in ("JointCmdCallback", "msg->name.size()", "xyber_ctrl_->SetMitCmd"):
        if marker not in text:
            errors.append("source-marker-missing:" + marker)
    indexed = [field for field in COMMAND_FIELDS if re.search(r"msg->" + field + r"\s*\[\s*i\s*\]", text)]
    missing_indexed = [field for field in COMMAND_FIELDS if field not in indexed]
    if missing_indexed:
        errors.append("command-field-indexing-incomplete:" + ",".join(missing_indexed))
    length_guards = []
    for field in COMMAND_FIELDS:
        pattern = r"msg->" + field + r"\.size\s*\(\s*\)\s*([!=<>]=?)\s*msg->name\.size\s*\(\s*\)"
        if re.search(pattern, text):
            length_guards.append(field)
    missing_guards = [field for field in COMMAND_FIELDS if field not in length_guards]
    finding = bool(indexed and missing_guards)
    return {
        "schema_version": 1,
        "profile": "embodied-ai-callback-parallel-array",
        "source": str(path),
        "source_sha256": sha256(path),
        "entrypoint": "DcuDriverModule::JointCmdCallback",
        "input_source": "joint_command",
        "runtime_stage": "control_boundary",
        "control_boundary": "xyber_ctrl_->SetMitCmd",
        "real_robot_execution": False,
        "network_target_execution": False,
        "static_finding": {
            "id": "joint_command_parallel_array_contract",
            "cwe": [125, 787],
            "indexed_fields": indexed,
            "missing_length_guards": missing_guards,
            "reachable_control_boundary": "static-source-only",
            "verdict": "REVIEW" if finding else "NO_UNGUARDED_PATTERN",
        },
        "repair_constraints": {
            "required": [
                "reject before any command-state mutation when every command vector is not name.size()",
                "skip TransformJointToActuator and SetMitCmd after rejection",
                "preserve benign matching-vector command semantics",
            ],
            "forbidden": ["silent truncation", "partial command state update", "real actuator execution"],
        },
        "evidence_level": "STATIC_ONLY",
        "runtime_verification": "NOT_RUN: source-bound static review only; no fake-sink or real actuator runtime claim",
        "errors": errors,
        "universal_claim": False,
        "formal_proof": False,
    }


def main():
    parser = argparse.ArgumentParser(description="Review a joint-command callback control boundary")
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if not args.source.is_file():
        result = {"valid": False, "errors": ["source-missing"]}
    else:
        result = review(args.source)
        result["valid"] = not result["errors"]
    if args.out:
        args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else "verdict=" + result.get("static_finding", {}).get("verdict", "REVIEW"))
    return 0 if result.get("valid") else 1


if __name__ == "__main__":
    raise SystemExit(main())
