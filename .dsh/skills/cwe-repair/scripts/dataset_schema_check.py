#!/usr/bin/env python3
"""Validate defensive dataset evidence fields without changing finding counts."""
import argparse
import json
import os
import sys

REQUIRED_FINDING_FIELDS = {"id", "cwe", "title", "loc", "evidence"}
PAIR_FIELDS = {
    "id", "component", "sample_role", "before", "after", "contract_type",
    "evidence_status", "repair_status", "verification_status", "runtime_verdict",
}
PATCH_APPLICATION_FIELDS = {
    "source", "patch", "target_path", "forward_applicable", "reverse_applicable",
}
LOCAL_PATCH_EVIDENCE_FIELDS = {"patch", "source_proof"}
RUNTIME_PREFLIGHT_FIELDS = {
    "launcher_preflight_attempted", "actual_harness_executed", "verdict",
    "infrastructure_failures", "infrastructure_reasons",
}
RUNTIME_VERIFICATION_FIELDS = {
    "artifact", "source_commit", "actual_harness_executed", "infrastructure_failures", "scope_verdict",
}


def validate_dataset(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    errors = []
    findings = []
    workspace = os.path.dirname(os.path.dirname(os.path.abspath(path)))
    for component in data.get("components", []):
        for finding in component.get("findings", []):
            missing = sorted(REQUIRED_FINDING_FIELDS - finding.keys())
            if missing:
                errors.append({"id": finding.get("id"), "missing": missing})
            findings.append(finding)
    pairs = data.get("repair_pairs", [])
    for pair in pairs:
        missing = sorted(PAIR_FIELDS - pair.keys())
        if missing:
            errors.append({"repair_pair": pair.get("id"), "missing": missing})
        if pair.get("evidence_status") in {"source-confirmed", "local-reduced-fixture"}:
            for field in ("before", "after"):
                artifact = pair.get(field, "")
                if " preimage" in artifact or "external-reference" in artifact:
                    continue
                resolved = os.path.abspath(os.path.join(workspace, artifact.replace("/", os.sep)))
                if not os.path.isfile(resolved):
                    errors.append({
                        "repair_pair": pair.get("id"),
                        "artifact": field,
                        "missing_path": artifact,
                    })
        patch_application = pair.get("patch_application_evidence")
        if patch_application:
            missing = sorted(PATCH_APPLICATION_FIELDS - patch_application.keys())
            if missing:
                errors.append({"repair_pair": pair.get("id"), "patch_application_missing": missing})
            for field in ("source", "patch"):
                artifact = patch_application.get(field, "")
                if artifact and "external-reference" not in artifact:
                    resolved = os.path.abspath(os.path.join(workspace, artifact.replace("/", os.sep)))
                    if not os.path.isfile(resolved):
                        errors.append({
                            "repair_pair": pair.get("id"),
                            "patch_application_artifact": field,
                            "missing_path": artifact,
                        })
            for field in ("forward_applicable", "reverse_applicable", "direct_artifact_path_applicable"):
                if field in patch_application and not isinstance(patch_application[field], bool):
                    errors.append({"repair_pair": pair.get("id"), "patch_application_not_bool": field})
            for fragment_name, fragment in patch_application.items():
                if not fragment_name.endswith("_fragment"):
                    continue
                if not isinstance(fragment, dict):
                    errors.append({"repair_pair": pair.get("id"), "patch_fragment_not_object": fragment_name})
                    continue
                fragment_patch = fragment.get("patch", "")
                resolved = os.path.abspath(os.path.join(workspace, fragment_patch.replace("/", os.sep)))
                if not fragment_patch or not os.path.isfile(resolved):
                    errors.append({
                        "repair_pair": pair.get("id"),
                        "patch_fragment": fragment_name,
                        "patch_fragment_missing_path": fragment_patch,
                    })
                for field in ("forward_applicable", "reverse_applicable"):
                    if field not in fragment or not isinstance(fragment[field], bool):
                        errors.append({
                            "repair_pair": pair.get("id"),
                            "patch_fragment": fragment_name,
                            "patch_fragment_not_bool": field,
                        })
        local_patch = pair.get("local_patch_evidence")
        if local_patch:
            missing = sorted(LOCAL_PATCH_EVIDENCE_FIELDS - local_patch.keys())
            if missing:
                errors.append({"repair_pair": pair.get("id"), "local_patch_missing": missing})
            artifact = local_patch.get("patch", "")
            if artifact and "external-reference" not in artifact:
                resolved = os.path.abspath(os.path.join(workspace, artifact.replace("/", os.sep)))
                if not os.path.isfile(resolved):
                    errors.append({
                        "repair_pair": pair.get("id"),
                        "local_patch_missing_path": artifact,
                    })
            if "source_proof" in local_patch and not isinstance(local_patch["source_proof"], bool):
                errors.append({"repair_pair": pair.get("id"), "local_patch_source_proof_not_bool": True})
            if "added_lines" in local_patch and (
                    not isinstance(local_patch["added_lines"], int) or isinstance(local_patch["added_lines"], bool)
                    or local_patch["added_lines"] < 0):
                errors.append({"repair_pair": pair.get("id"), "local_patch_added_lines_invalid": True})
        preflight = pair.get("runtime_preflight_evidence")
        if preflight:
            missing = sorted(RUNTIME_PREFLIGHT_FIELDS - preflight.keys())
            if missing:
                errors.append({"repair_pair": pair.get("id"), "runtime_preflight_missing": missing})
            for field in ("launcher_preflight_attempted", "actual_harness_executed"):
                if field in preflight and not isinstance(preflight[field], bool):
                    errors.append({"repair_pair": pair.get("id"), "runtime_preflight_not_bool": field})
            if preflight.get("verdict") not in {"PASS", "REVIEW"}:
                errors.append({"repair_pair": pair.get("id"), "runtime_preflight_invalid_verdict": preflight.get("verdict")})
            failures = preflight.get("infrastructure_failures")
            if (not isinstance(failures, int) or isinstance(failures, bool) or failures < 0):
                errors.append({"repair_pair": pair.get("id"), "runtime_preflight_invalid_failures": failures})
            reasons = preflight.get("infrastructure_reasons")
            if not isinstance(reasons, dict) or any(
                    not isinstance(reason, str) or not isinstance(count, int)
                    or isinstance(count, bool) or count < 0
                    for reason, count in (reasons.items() if isinstance(reasons, dict) else ())):
                errors.append({"repair_pair": pair.get("id"), "runtime_preflight_invalid_reasons": True})
            if preflight.get("actual_harness_executed") is False and preflight.get("verdict") == "PASS":
                errors.append({"repair_pair": pair.get("id"), "runtime_preflight_unexecuted_pass": True})
        runtime = pair.get("runtime_verification_evidence")
        if runtime:
            missing = sorted(RUNTIME_VERIFICATION_FIELDS - runtime.keys())
            if missing:
                errors.append({"repair_pair": pair.get("id"), "runtime_verification_missing": missing})
            artifact = runtime.get("artifact", "")
            if not artifact or "external-reference" in artifact:
                errors.append({"repair_pair": pair.get("id"), "runtime_verification_invalid_artifact": artifact})
            else:
                resolved = os.path.abspath(os.path.join(workspace, artifact.replace("/", os.sep)))
                if not os.path.isfile(resolved):
                    errors.append({"repair_pair": pair.get("id"), "runtime_verification_missing_artifact": artifact})
            if not isinstance(runtime.get("source_commit"), str) or not runtime.get("source_commit"):
                errors.append({"repair_pair": pair.get("id"), "runtime_verification_invalid_commit": True})
            if not isinstance(runtime.get("actual_harness_executed"), bool):
                errors.append({"repair_pair": pair.get("id"), "runtime_verification_not_bool": "actual_harness_executed"})
            failures = runtime.get("infrastructure_failures")
            if not isinstance(failures, int) or isinstance(failures, bool) or failures < 0:
                errors.append({"repair_pair": pair.get("id"), "runtime_verification_invalid_failures": failures})
            scope_verdict = runtime.get("scope_verdict")
            if not isinstance(scope_verdict, str) or not scope_verdict.startswith(("PASS", "REVIEW")):
                errors.append({"repair_pair": pair.get("id"), "runtime_verification_invalid_scope_verdict": scope_verdict})
            if runtime.get("actual_harness_executed") is False and isinstance(scope_verdict, str) and scope_verdict.startswith("PASS"):
                errors.append({"repair_pair": pair.get("id"), "runtime_verification_unexecuted_pass": True})
            for scope_name in ("bin_scope", "text_count_scope", "text_blob_index_scope"):
                scope = runtime.get(scope_name)
                if scope is not None and (not isinstance(scope, dict) or scope.get("verdict") not in {"PASS", "REVIEW"}):
                    errors.append({"repair_pair": pair.get("id"), "runtime_verification_invalid_scope": scope_name})
    return {
        "findings": len(findings),
        "repair_pairs": len(pairs),
        "errors": errors,
        "valid": not errors,
    }


def main():
    ap = argparse.ArgumentParser(description="Validate defensive dataset evidence schema")
    ap.add_argument("dataset")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    result = validate_dataset(args.dataset)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=1))
    else:
        print(f"findings={result['findings']} repair_pairs={result['repair_pairs']} valid={result['valid']}")
        for error in result["errors"]:
            print(error)
    raise SystemExit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
