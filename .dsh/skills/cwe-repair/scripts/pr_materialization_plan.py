#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate a defensive PR materialization plan against the case registry."""
import argparse
import json
import sys
from pathlib import Path

REQUIRED_SAFETY = {
    "local/offline source and fixtures only",
    "no exploit chain or real executor",
    "no network target execution",
    "no OOM, huge allocation, or resource-exhaustion sample",
    "a local crash is evidence of a preimage defect, never a successful rejection",
    "missing proof obligations force REVIEW",
}


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate(plan, registry):
    errors = []
    if plan.get("schema_version") != 1:
        errors.append("invalid-schema-version")
    cases = plan.get("cases")
    if not isinstance(cases, list) or not cases:
        errors.append("cases-must-be-nonempty")
        return errors
    max_cases = plan.get("selection_policy", {}).get("max_cases")
    if not isinstance(max_cases, int) or len(cases) > max_cases:
        errors.append("selection-exceeds-max-cases")
    registry_by_id = {item.get("id"): item for item in registry.get("cases", [])}
    seen = set()
    for item in cases:
        case_id = item.get("id")
        if case_id in seen:
            errors.append(f"duplicate-plan-case:{case_id}")
        seen.add(case_id)
        source = registry_by_id.get(case_id)
        if source is None:
            errors.append(f"case-not-in-registry:{case_id}")
            continue
        if source.get("materialization") not in {"external-reference", "official-local-materialized"}:
            errors.append(f"case-not-materializable-reference:{case_id}")
        if source.get("strict_eligible") is not False:
            errors.append(f"case-strict-eligible:{case_id}")
        if item.get("source_url") != source.get("source_url"):
            errors.append(f"source-url-mismatch:{case_id}")
        if item.get("expected_initial_status") != "REVIEW":
            errors.append(f"initial-status-not-review:{case_id}")
        if not isinstance(item.get("materialization_steps"), list) or not item["materialization_steps"]:
            errors.append(f"materialization-steps-missing:{case_id}")
        if not isinstance(item.get("blocking_evidence"), list) or not item["blocking_evidence"]:
            errors.append(f"blocking-evidence-missing:{case_id}")
    safety = set(plan.get("safety_constraints", []))
    errors.extend(f"safety-constraint-missing:{item}" for item in sorted(REQUIRED_SAFETY - safety))
    return errors


def main():
    parser = argparse.ArgumentParser(description="Validate a PR materialization plan")
    parser.add_argument("--plan", required=True)
    parser.add_argument("--registry", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    plan = load(args.plan)
    registry = load(args.registry)
    errors = validate(plan, registry)
    result = {"valid": not errors, "errors": errors, "planned_cases": len(plan.get("cases", []))}
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"valid={result['valid']} planned_cases={result['planned_cases']}")
        for error in errors:
            print(error)
    return 0 if not errors else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
