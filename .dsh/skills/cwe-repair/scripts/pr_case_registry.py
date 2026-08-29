#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate and summarize the provenance-aware PR case registry.

The registry is separate from the legacy finding dataset. A PR reference is not
counted as a verified repair pair unless its stated evidence gates are complete.
"""
import argparse
import json
import sys
from pathlib import Path

VALID_MATERIALIZATION = {
    "official-local-materialized",
    "official-local-materialized-upstream-open",
    "external-reference",
    "local-only",
}
VALID_UPSTREAM = {"merged", "open", "closed-unmerged", "unknown"}
VALID_REVIEW_STATUS = {"candidate", "accepted", "rejected", "unconfirmed"}
REQUIRED_CASE_FIELDS = {
    "id", "project", "component_role", "source_url", "source_platform",
    "pr_number", "upstream_state", "materialization", "contract_family",
    "evidence", "strict_eligible", "review_status",
}
EVIDENCE_FIELDS = {
    "official_source", "base_sha", "head_sha", "before_source", "after_source",
    "detect", "repair_plan", "symmetry", "runtime", "provenance",
}


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate(data):
    errors = []
    if data.get("schema_version") != 1:
        errors.append({"schema_version": data.get("schema_version")})
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        return errors + [{"cases": "non-empty list required"}]
    ids = set()
    for case in cases:
        case_id = case.get("id") if isinstance(case, dict) else None
        if not isinstance(case, dict):
            errors.append({"case": case_id, "not_object": True})
            continue
        if case_id in ids:
            errors.append({"case": case_id, "duplicate_id": True})
        ids.add(case_id)
        missing = sorted(REQUIRED_CASE_FIELDS - set(case))
        if missing:
            errors.append({"case": case_id, "missing": missing})
        if not isinstance(case.get("pr_number"), int) or isinstance(case.get("pr_number"), bool):
            errors.append({"case": case_id, "invalid_pr_number": True})
        if case.get("materialization") not in VALID_MATERIALIZATION:
            errors.append({"case": case_id, "invalid_materialization": case.get("materialization")})
        if case.get("upstream_state") not in VALID_UPSTREAM:
            errors.append({"case": case_id, "invalid_upstream_state": case.get("upstream_state")})
        if case.get("review_status") not in VALID_REVIEW_STATUS:
            errors.append({"case": case_id, "invalid_review_status": case.get("review_status")})
        if not isinstance(case.get("strict_eligible"), bool):
            errors.append({"case": case_id, "strict_eligible_not_bool": True})
        if case.get("materialization") in {"external-reference", "local-only"} and case.get("strict_eligible"):
            errors.append({"case": case_id, "unverifiable_material_strict_eligible": True})
        if case.get("upstream_state") == "open" and case.get("strict_eligible"):
            errors.append({"case": case_id, "open_pr_strict_eligible": True})
        if not isinstance(case.get("evidence"), dict):
            errors.append({"case": case_id, "evidence_not_object": True})
        else:
            unknown = sorted(set(case["evidence"]) - EVIDENCE_FIELDS)
            if unknown:
                errors.append({"case": case_id, "unknown_evidence_fields": unknown})
            for field in ("official_source", "base_sha", "head_sha"):
                if field not in case["evidence"]:
                    errors.append({"case": case_id, "evidence_missing": field})
        if case.get("review_status") == "accepted" and case.get("materialization") == "external-reference":
            errors.append({"case": case_id, "external_reference_cannot_be_accepted": True})
    return errors


def summarize(data):
    cases = data.get("cases", [])
    by_materialization = {}
    by_project = {}
    verified_candidates = 0
    for case in cases:
        materialization = case.get("materialization", "unknown")
        project = case.get("project", "unknown")
        by_materialization[materialization] = by_materialization.get(materialization, 0) + 1
        by_project[project] = by_project.get(project, 0) + 1
        evidence = case.get("evidence", {})
        complete = all(evidence.get(field) for field in ("official_source", "base_sha", "head_sha"))
        complete = complete and case.get("materialization") in {
            "official-local-materialized", "official-local-materialized-upstream-open", "local-only"
        }
        if complete and case.get("review_status") == "accepted":
            verified_candidates += 1
    return {
        "cases": len(cases),
        "by_materialization": by_materialization,
        "by_project": by_project,
        "accepted_with_local_provenance": verified_candidates,
        "legacy_dataset_impact": "none",
    }


def main():
    parser = argparse.ArgumentParser(description="Validate the provenance-aware PR case registry")
    parser.add_argument("--data", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    data = load(args.data)
    errors = validate(data)
    result = {"valid": not errors, "errors": errors, "summary": summarize(data)}
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"valid={result['valid']}")
        print(json.dumps(result["summary"], ensure_ascii=False))
        for error in errors:
            print(error)
    return 0 if not errors else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
