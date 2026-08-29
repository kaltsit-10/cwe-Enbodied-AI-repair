#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Normalize provenance and verification evidence into explicit levels.

This module separates full-gate evidence from scoped/reduced evidence. It does
not grant strict eligibility and never treats a reduced runtime as full proof.
"""

import argparse
import json
import os
import sys
from pathlib import Path

STATUS_VERIFIED = "verified"
STATUS_SCOPED = "scoped"
STATUS_MISSING = "missing"
STATUS_NOT_APPLICABLE = "not_applicable"
STATUS_BLOCKED = "blocked"


def _text(value):
    return str(value or "").strip().lower()


def _has_any(text, *parts):
    return any(part in text for part in parts)


def _positive(value):
    text = _text(value)
    if not text:
        return False
    return not _has_any(
        text,
        "not executed",
        "not run",
        "not-run",
        "not_run",
        "not locally",
        "not applicable",
        "not-applicable",
        "contract-mismatch",
        "mismatch",
        "unavailable",
        "unconfirmed",
        "pending",
        "unknown",
    )


def _scoped(text):
    return _has_any(text, "scoped", "reduced", "bounded harness")


def _full_pass(text):
    return _has_any(text, "matrix_verified", "matrix verified", "semantic_verified") or (
        "pass" in text and "review" not in text and not _scoped(text)
    )


def classify_case(case, source_pair=None):
    evidence = case.get("evidence", {})
    gate_status = {}

    gate_status["official_source"] = STATUS_VERIFIED if evidence.get("official_source") is True else STATUS_MISSING
    has_revisions = bool(evidence.get("base_sha")) and bool(evidence.get("head_sha"))
    gate_status["base_head"] = STATUS_VERIFIED if has_revisions else STATUS_MISSING

    before = evidence.get("before_source")
    after = evidence.get("after_source")
    # Readiness supplies the filesystem-aware result; direct callers still get
    # a useful declaration-only result when no override is provided.
    declared_source_pair = bool(before and after)
    gate_status["source_pair"] = STATUS_VERIFIED if (declared_source_pair if source_pair is None else source_pair) else STATUS_MISSING

    for name in ("detect", "repair_plan", "provenance"):
        text = _text(evidence.get(name))
        if not _positive(text):
            gate_status[name] = STATUS_MISSING
        elif _scoped(text):
            gate_status[name] = STATUS_SCOPED
        else:
            gate_status[name] = STATUS_VERIFIED

    symmetry_text = _text(evidence.get("symmetry"))
    if _has_any(symmetry_text, "not applicable", "not-applicable"):
        gate_status["symmetry"] = STATUS_NOT_APPLICABLE
    elif _scoped(symmetry_text) and _has_any(symmetry_text, "pass", "passed", "verified"):
        # A scoped matrix may pass its declared target while a wider sibling
        # matrix remains REVIEW; retain that distinction explicitly.
        gate_status["symmetry"] = STATUS_SCOPED
    elif _full_pass(symmetry_text):
        gate_status["symmetry"] = STATUS_VERIFIED
    elif "review" in symmetry_text:
        gate_status["symmetry"] = STATUS_MISSING
    elif _positive(symmetry_text):
        gate_status["symmetry"] = STATUS_VERIFIED
    else:
        gate_status["symmetry"] = STATUS_MISSING

    runtime_text = _text(evidence.get("runtime"))
    if _has_any(runtime_text, "not executed", "not run", "unavailable"):
        gate_status["runtime"] = STATUS_MISSING
    elif _scoped(runtime_text) and _has_any(runtime_text, "pass", "passed"):
        gate_status["runtime"] = STATUS_SCOPED
    elif _full_pass(runtime_text) or (_positive(runtime_text) and "review" not in runtime_text):
        gate_status["runtime"] = STATUS_VERIFIED
    else:
        gate_status["runtime"] = STATUS_MISSING

    required = {name: True for name in gate_status}
    # A declared single-path case can explicitly opt out of sibling symmetry.
    if case.get("path_scope") == "single-path" or "single-path" in symmetry_text or "single-kernel" in symmetry_text or "single-session" in symmetry_text:
        required["symmetry"] = False

    required_statuses = [status for name, status in gate_status.items() if required[name]]
    all_verified = all(status == STATUS_VERIFIED for status in required_statuses)
    any_scoped = any(status == STATUS_SCOPED for status in required_statuses)
    has_local = gate_status["base_head"] == STATUS_VERIFIED and gate_status["source_pair"] == STATUS_VERIFIED
    if all_verified:
        level = "FULL_GATED_LOCAL"
    elif any_scoped and has_local:
        level = "SCOPED_RUNTIME"
    elif has_local:
        level = "LOCAL_STATIC"
    elif gate_status["official_source"] == STATUS_VERIFIED:
        level = "MATERIALIZED_REFERENCE"
    else:
        level = "REFERENCE_ONLY"

    return {
        "evidence_level": level,
        "gate_status": gate_status,
        "required_gates": required,
        "full_gate_ready": all_verified,
        "formal_proof": False,
    }


def classify_registry(data):
    assessments = []
    counts = {}
    anomalies = []
    for case in data.get("cases", []):
        evidence = case.get("evidence", {})
        source_pair = bool(
            isinstance(evidence.get("before_source"), str)
            and isinstance(evidence.get("after_source"), str)
            and os.path.isfile(evidence.get("before_source"))
            and os.path.isfile(evidence.get("after_source"))
        )
        result = classify_case(case, source_pair=source_pair)
        item = {
            "id": case.get("id"),
            "project": case.get("project"),
            "materialization": case.get("materialization"),
            "strict_eligible": case.get("strict_eligible"),
            **result,
        }
        assessments.append(item)
        level = result["evidence_level"]
        counts[level] = counts.get(level, 0) + 1
        if case.get("strict_eligible") is True and level != "FULL_GATED_LOCAL":
            anomalies.append({"id": case.get("id"), "type": "strict-without-full-gates", "level": level})
        if case.get("materialization") in {
            "official-local-materialized",
            "official-local-materialized-upstream-open",
        } and not (result["gate_status"]["base_head"] == STATUS_VERIFIED and source_pair):
            anomalies.append({"id": case.get("id"), "type": "materialized-without-local-source-pair"})
        if result.get("formal_proof") is True:
            anomalies.append({"id": case.get("id"), "type": "formal-proof-claim-not-supported"})
    return {
        "schema_version": 1,
        "case_count": len(assessments),
        "evidence_level_counts": counts,
        "anomalies": anomalies,
        "assessments": assessments,
        "strict_rule": "evidence level is descriptive; it never grants strict eligibility",
    }


def main():
    parser = argparse.ArgumentParser(description="Classify PR registry evidence levels")
    parser.add_argument("--data", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    data = json.loads(Path(args.data).read_text(encoding="utf-8"))
    result = classify_registry(data)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"cases={result['case_count']}")
        print(json.dumps(result["evidence_level_counts"], ensure_ascii=False))
        for item in result["assessments"]:
            print(f"{item['id']}: {item['evidence_level']} full_gate_ready={item['full_gate_ready']}")
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
