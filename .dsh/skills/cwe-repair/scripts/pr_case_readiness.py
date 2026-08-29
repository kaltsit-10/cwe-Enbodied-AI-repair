#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Score evidence readiness and produce a defensive PR materialization queue."""
import argparse
import json
import sys
from pathlib import Path

try:
    from . import evidence_lattice
except ImportError:
    import evidence_lattice

GATES = (
    "official_source",
    "base_head",
    "source_pair",
    "detect",
    "repair_plan",
    "symmetry",
    "runtime",
    "provenance",
)
NEGATIVE_MARKERS = (
    "not locally",
    "not executed",
    "not locally available",
    "requires local",
    "external pr reference only",
    "official pr title/reference collected",
    "unconfirmed",
    "unknown",
    "pending",
    "unavailable",
    "not-applicable",
    "not-run",
    "not_run",
    "contract-mismatch",
    "mismatch",
)


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def meaningful(value, field=None):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    if not text:
        return False
    if field in {"symmetry", "runtime"} and "review" in text:
        return False
    return not any(marker in text for marker in NEGATIVE_MARKERS)


def recorded_path(value):
    """Check registry provenance without requiring a third-party worktree in this host."""
    return isinstance(value, str) and bool(value.strip())


def assess_case(case):
    evidence = case.get("evidence", {})
    base_head = bool(evidence.get("base_sha")) and bool(evidence.get("head_sha"))
    # The queue is a checked-in provenance snapshot. Runtime/build validators, not
    # this inventory score, decide whether a referenced local worktree is available.
    source_pair = recorded_path(evidence.get("before_source")) and recorded_path(evidence.get("after_source"))
    gates = {
        "official_source": evidence.get("official_source") is True,
        "base_head": base_head,
        "source_pair": source_pair,
        "detect": meaningful(evidence.get("detect"), "detect"),
        "repair_plan": meaningful(evidence.get("repair_plan"), "repair_plan"),
        "symmetry": meaningful(evidence.get("symmetry"), "symmetry"),
        "runtime": meaningful(evidence.get("runtime"), "runtime"),
        "provenance": meaningful(evidence.get("provenance"), "provenance") and base_head,
    }
    gaps = [gate for gate in GATES if not gates[gate]]
    actions = {
        "base_head": "materialize immutable base/head revisions",
        "source_pair": "checkout source files and record exact paths",
        "detect": "run local detector and save before/after JSON",
        "repair_plan": "run contract-gated repair_plan and archive patch decision",
        "symmetry": "run symmetry or paired-path contract matrix",
        "runtime": "build local harness and run defensive malicious/benign verification",
        "provenance": "bind source, patch, binary and runtime hashes to the case",
        "official_source": "verify official PR/commit URL",
    }
    if all(gates.values()):
        priority = "ready-for-semantic-verification"
    elif case.get("materialization") == "external-reference":
        priority = "materialize-external-reference"
    elif gates["official_source"] and gates["base_head"] and gates["source_pair"]:
        priority = "complete-missing-gates"
    elif gates["official_source"] and gates["base_head"]:
        priority = "materialize-source-pair"
    else:
        priority = "source-review"
    score = sum(1 for value in gates.values() if value)
    lattice = evidence_lattice.classify_case(case, source_pair=source_pair)
    return {
        "id": case.get("id"),
        "project": case.get("project"),
        "materialization": case.get("materialization"),
        "upstream_state": case.get("upstream_state"),
        "strict_eligible": case.get("strict_eligible"),
        "readiness_score": f"{score}/{len(GATES)}",
        "gates": gates,
        "gate_status": lattice["gate_status"],
        "required_gates": lattice["required_gates"],
        "evidence_level": lattice["evidence_level"],
        "full_gate_ready": lattice["full_gate_ready"],
        "formal_proof": lattice["formal_proof"],
        "gaps": gaps,
        "recommended_actions": [actions[gap] for gap in gaps],
        "priority": priority,
    }


def validate_queue_snapshot(data, snapshot):
    """Verify that a checked-in readiness snapshot matches its registry input."""
    expected = build_queue(data)
    if not isinstance(snapshot, dict):
        return {"valid": False, "errors": ["queue-not-object"], "expected": expected}
    errors = []
    for key in ("schema_version", "case_count", "gate_count", "priority_counts", "evidence_level_counts", "assessments", "strict_rule"):
        if snapshot.get(key) != expected.get(key):
            errors.append(f"queue-drift-{key}")
    return {"valid": not errors, "errors": errors, "expected": expected}


def build_queue(data):
    assessments = [assess_case(case) for case in data.get("cases", [])]
    priority_rank = {
        "ready-for-semantic-verification": 0,
        "complete-missing-gates": 1,
        "materialize-source-pair": 2,
        "materialize-external-reference": 3,
        "source-review": 4,
    }
    assessments.sort(key=lambda item: (priority_rank.get(item["priority"], 9), -int(item["readiness_score"].split("/", 1)[0]), item["id"] or ""))
    counts = {}
    evidence_levels = {}
    for item in assessments:
        counts[item["priority"]] = counts.get(item["priority"], 0) + 1
        level = item["evidence_level"]
        evidence_levels[level] = evidence_levels.get(level, 0) + 1
    return {
        "schema_version": 1,
        "case_count": len(assessments),
        "gate_count": len(GATES),
        "priority_counts": counts,
        "evidence_level_counts": evidence_levels,
        "assessments": assessments,
        "strict_rule": "readiness does not grant strict eligibility; all semantic gates and upstream policy still apply",
    }


def main():
    parser = argparse.ArgumentParser(description="Score PR evidence readiness")
    parser.add_argument("--data", required=True)
    parser.add_argument("--out")
    parser.add_argument("--validate-queue", help="validate a checked-in readiness queue against --data")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    data = load(args.data)
    if args.validate_queue:
        snapshot_result = validate_queue_snapshot(data, load(args.validate_queue))
        result = {
            "valid": snapshot_result["valid"],
            "errors": snapshot_result["errors"],
            "case_count": snapshot_result["expected"]["case_count"],
            "priority_counts": snapshot_result["expected"]["priority_counts"],
            "evidence_level_counts": snapshot_result["expected"]["evidence_level_counts"],
        }
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(f"valid={result['valid']}")
            for error in result["errors"]:
                print(error)
        return 0 if result["valid"] else 1
    result = build_queue(data)
    if args.out:
        Path(args.out).write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"cases={result['case_count']}")
        print(json.dumps(result["priority_counts"], ensure_ascii=False))
        for item in result["assessments"]:
            print(f"{item['id']}: {item['readiness_score']} {item['priority']} gaps={','.join(item['gaps'])}")
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
