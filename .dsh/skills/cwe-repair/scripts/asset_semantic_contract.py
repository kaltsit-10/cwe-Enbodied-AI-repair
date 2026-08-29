#!/usr/bin/env python3
"""Validate one asset's declared semantic-verification scope.

This is a conservative aggregation gate for a pinned, explicitly bounded asset.
It verifies evidence-file hashes, case identity, assertions, declared paths,
dimensions, and runtime gate metrics. ``ASSET_SCOPE_COMPLETE`` only means that
all gates in the declared local asset scope passed. It never means universal or
formal verification over all inputs, providers, or configurations.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RATIO_RE = re.compile(r"^(\d+)\s*/\s*(\d+)$")
GATE_STATUSES = {"PASS", "REVIEW", "SCOPED", "NOT_RUN", "MISSING"}
DEFAULT_ASSET_GATES = (
    "official_provenance",
    "source_scope",
    "inventory_completeness",
    "reproducibility",
    "safety",
)
DEFAULT_PATH_GATES = (
    "static_contract",
    "symmetry",
    "detect",
    "repair_plan",
    "paired_build",
    "preimage_witness",
    "runtime_head",
    "negative_rejection",
    "benign_preservation",
)
SAFETY_KEYS = (
    "no_external_inputs",
    "no_network_target_execution",
    "no_oom_or_huge_allocation",
    "no_exploit_chain",
)
SCOPE_LIST_KEYS = ("providers", "targets", "configurations", "input_domains")


def _result(record, errors, missing):
    artifact_integrity = not errors
    scope_complete = artifact_integrity and not missing
    return {
        "schema_version": 1,
        "asset_id": record.get("asset_id") if isinstance(record, dict) else None,
        "case_id": record.get("case_id") if isinstance(record, dict) else None,
        "artifact_integrity": artifact_integrity,
        "scope_complete": scope_complete,
        "valid": artifact_integrity,
        "verdict": "ASSET_SCOPE_COMPLETE" if scope_complete else "REVIEW",
        "missing_gates": sorted(set(missing)),
        "errors": errors,
        "universal_claim": False,
        "formal_proof": False,
        "proof_scope": "one pinned asset and explicitly declared paths/dimensions only; not all inputs/providers/configurations and not a formal proof",
    }


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_ref_path(path_value, base_dir):
    if not isinstance(path_value, str) or not path_value.strip():
        return None
    normalized = path_value.strip()
    if normalized.startswith(("http://", "https://", "file://")):
        return None
    path = Path(normalized)
    return path if path.is_absolute() else base_dir / path


def _get_json_path(document, path):
    current = document
    segments = path.split(".")
    index = 0
    while index < len(segments):
        if isinstance(current, list) and segments[index].isdigit() and int(segments[index]) < len(current):
            current = current[int(segments[index])]
            index += 1
            continue
        if not isinstance(current, dict):
            return False, None
        if segments[index] in current:
            current = current[segments[index]]
            index += 1
            continue
        matched = None
        for end in range(len(segments), index + 1, -1):
            candidate = ".".join(segments[index:end])
            if candidate in current:
                matched = (end, current[candidate])
                break
        if matched is None:
            return False, None
        index, current = matched
    return True, current


def _valid_string_list(value):
    return isinstance(value, list) and bool(value) and all(isinstance(item, str) and item.strip() for item in value)


def _valid_string_list_or_empty(value):
    return isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value)


def _verify_reference(reference, base_dir, label, expected_case_id, errors):
    if not isinstance(reference, dict):
        errors.append(f"{label}-reference-not-object")
        return None
    path = _resolve_ref_path(reference.get("path"), base_dir)
    if path is None:
        errors.append(f"{label}-reference-path-invalid")
        return None
    if not path.is_file():
        errors.append(f"{label}-reference-file-missing")
        return None
    digest = reference.get("sha256")
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest.lower()) is None:
        errors.append(f"{label}-reference-sha256-invalid")
        return None
    try:
        actual_digest = _sha256(path)
    except OSError:
        errors.append(f"{label}-reference-file-unreadable")
        return None
    if actual_digest != digest.lower():
        errors.append(f"{label}-reference-sha256-mismatch")
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        errors.append(f"{label}-reference-json-invalid")
        return None
    if not isinstance(document, dict):
        errors.append(f"{label}-reference-json-root-not-object")
        return None
    if document.get("case_id") != expected_case_id:
        errors.append(f"{label}-reference-case-id-mismatch")
    if document.get("formal_proof") is True:
        errors.append(f"{label}-reference-formal-proof-claim")

    evidence_role = reference.get("evidence_role")
    if evidence_role is not None and not isinstance(evidence_role, str):
        errors.append(f"{label}-evidence-role-invalid")
    assertions = reference.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        errors.append(f"{label}-assertions-missing")
    else:
        for index, assertion in enumerate(assertions):
            if not isinstance(assertion, dict) or not isinstance(assertion.get("path"), str) or not assertion["path"] or "equals" not in assertion:
                errors.append(f"{label}-assertion-{index}-invalid")
                continue
            found, actual = _get_json_path(document, assertion["path"])
            if not found or actual != assertion["equals"]:
                errors.append(f"{label}-assertion-{index}-failed")
    return document


def _verify_references(value, base_dir, label, expected_case_id, errors):
    if not isinstance(value, list) or not value:
        errors.append(f"{label}-evidence-missing")
        return []
    documents = []
    for index, reference in enumerate(value):
        document = _verify_reference(reference, base_dir, f"{label}-{index}", expected_case_id, errors)
        if document is not None:
            documents.append(document)
    return documents


def _valid_sha(value, pattern):
    return isinstance(value, str) and pattern.fullmatch(value.lower()) is not None


def _valid_status_gate(gate, base_dir, label, expected_case_id, errors, required_role=None):
    if not isinstance(gate, dict):
        errors.append(f"{label}-missing")
        return "MISSING"
    status = gate.get("status")
    if status not in GATE_STATUSES:
        errors.append(f"{label}-status-invalid")
        status = "MISSING"
    references = gate.get("evidence")
    _verify_references(references, base_dir, label, expected_case_id, errors)
    if required_role is not None and isinstance(references, list):
        for index, reference in enumerate(references):
            if reference.get("evidence_role") != required_role:
                errors.append(f"{label}-{index}-evidence-role-mismatch")
    return status


def _valid_ratio(value):
    if not isinstance(value, str):
        return False
    match = RATIO_RE.fullmatch(value.strip())
    if not match:
        return False
    passed, total = (int(item) for item in match.groups())
    return total > 0 and passed == total


def _validate_runtime_gate(gate, base_dir, label, expected_case_id, errors):
    status = _valid_status_gate(gate, base_dir, label, expected_case_id, errors)
    if status != "PASS" or not isinstance(gate, dict):
        return status
    metrics = gate.get("metrics")
    if not isinstance(metrics, dict):
        errors.append(f"{label}-metrics-missing")
        return status
    metric_name = "malicious_rejected" if label.endswith("negative_rejection") else "benign_passed"
    if not _valid_ratio(metrics.get(metric_name)):
        errors.append(f"{label}-ratio-not-complete")
    if metrics.get("infrastructure_failures") != 0:
        errors.append(f"{label}-infrastructure-failures")
    return status


def _validate_preimage_witness(gate, base_dir, label, expected_case_id, errors):
    """Require a reproduced preimage violation, not a passing base binary."""
    status = _valid_status_gate(gate, base_dir, label, expected_case_id, errors)
    if status != "PASS" or not isinstance(gate, dict):
        return status
    metrics = gate.get("metrics")
    if not isinstance(metrics, dict):
        errors.append(f"{label}-metrics-missing")
        return status
    if metrics.get("unsafe_behavior_observed") is not True:
        errors.append(f"{label}-unsafe-behavior-not-observed")
    rejected = metrics.get("malicious_rejected")
    match = RATIO_RE.fullmatch(rejected.strip()) if isinstance(rejected, str) else None
    if match is None:
        errors.append(f"{label}-malicious-rejection-ratio-invalid")
    else:
        passed, total = (int(item) for item in match.groups())
        if total <= 0 or passed >= total:
            errors.append(f"{label}-does-not-demonstrate-preimage-violation")
    if metrics.get("infrastructure_failures") != 0:
        errors.append(f"{label}-infrastructure-failures")
    return status


def _validate_gate_map(gates, required, base_dir, label, expected_case_id, errors, missing, runtime=False):
    if not isinstance(gates, dict):
        for gate_name in required:
            missing.append(f"{label}.{gate_name}")
        return
    for gate_name in required:
        full_label = f"{label}.{gate_name}"
        gate = gates.get(gate_name)
        if runtime and gate_name in {"negative_rejection", "benign_preservation"}:
            status = _validate_runtime_gate(gate, base_dir, full_label, expected_case_id, errors)
            if gate_name in {"detect", "repair_plan"} and isinstance(gate, dict):
                role = "detector" if gate_name == "detect" else "repair_plan"
                if gate.get("evidence_role") != role:
                    errors.append(f"{full_label}-evidence-role-mismatch")
        elif runtime and gate_name == "preimage_witness":
            status = _validate_preimage_witness(gate, base_dir, full_label, expected_case_id, errors)
        else:
            status = _valid_status_gate(gate, base_dir, full_label, expected_case_id, errors)
        if gate_name in {"detect", "repair_plan"} and isinstance(gate, dict):
            role = "detector" if gate_name == "detect" else "repair_plan"
            if gate.get("evidence_role") != role:
                errors.append(f"{full_label}-evidence-role-mismatch")
        if status != "PASS":
            missing.append(full_label)


def _validate_scope(scope, errors):
    if not isinstance(scope, dict):
        errors.append("declared-scope-missing")
        return
    for key in SCOPE_LIST_KEYS:
        if not _valid_string_list(scope.get(key)):
            errors.append(f"declared-scope-{key}-invalid")


def validate_asset_record(record, base_dir=None):
    """Validate a normalized single-asset semantic contract record."""
    if not isinstance(record, dict):
        return _result({}, ["record-root-not-object"], [])
    base_dir = Path(base_dir or Path.cwd()).resolve()
    errors = []
    missing = []

    for key in ("asset_id", "case_id", "asset_kind", "scope_type"):
        if not isinstance(record.get(key), str) or not record[key].strip():
            errors.append(f"{key}-missing")
    case_id = record.get("case_id") if isinstance(record.get("case_id"), str) else ""
    if record.get("scope_type") != "single-asset-declared-contract":
        errors.append("scope-type-invalid")
    if record.get("universal_claim") is not False:
        errors.append("universal-claim-must-be-false")
    if record.get("formal_proof") is not False:
        errors.append("formal-proof-must-be-false")
    official_source = record.get("official_source")
    if not isinstance(official_source, str) or not official_source.startswith(("https://", "http://")):
        errors.append("official-source-invalid")
    _validate_scope(record.get("declared_scope"), errors)

    revisions = record.get("revisions")
    if not isinstance(revisions, dict) or not _valid_sha(revisions.get("base"), SHA1_RE) or not _valid_sha(revisions.get("head"), SHA1_RE):
        errors.append("revisions-invalid")
    elif revisions["base"].lower() == revisions["head"].lower():
        errors.append("revisions-not-distinct")

    contract = record.get("contract")
    if not isinstance(contract, dict):
        errors.append("contract-missing")
        required_asset_gates = list(DEFAULT_ASSET_GATES)
        required_path_gates = list(DEFAULT_PATH_GATES)
        required_dimensions = []
    else:
        required_asset_gates = contract.get("required_asset_gates", list(DEFAULT_ASSET_GATES))
        required_path_gates = contract.get("required_path_gates", list(DEFAULT_PATH_GATES))
        required_dimensions = contract.get("required_dimensions", [])
        if not _valid_string_list(required_asset_gates):
            errors.append("required-asset-gates-invalid")
            required_asset_gates = list(DEFAULT_ASSET_GATES)
        if not _valid_string_list(required_path_gates):
            errors.append("required-path-gates-invalid")
            required_path_gates = list(DEFAULT_PATH_GATES)
        if not _valid_string_list(required_dimensions):
            errors.append("required-dimensions-invalid")
            required_dimensions = []
        if len(set(required_asset_gates)) != len(required_asset_gates) or len(set(required_path_gates)) != len(required_path_gates) or len(set(required_dimensions)) != len(required_dimensions):
            errors.append("contract-gate-or-dimension-duplicates")
        missing_baseline_gates = [gate for gate in DEFAULT_ASSET_GATES if gate not in required_asset_gates]
        for gate in missing_baseline_gates:
            errors.append(f"required-asset-gate-not-declared-{gate}")
            required_asset_gates.append(gate)
        for gate in ("detect", "repair_plan"):
            if gate not in required_path_gates:
                errors.append(f"required-path-gate-not-declared-{gate}")
                required_path_gates.append(gate)

    safety = record.get("safety")
    if not isinstance(safety, dict) or any(safety.get(key) is not True for key in SAFETY_KEYS):
        errors.append("safety-declaration-incomplete")
    _validate_gate_map(record.get("asset_coverage"), required_asset_gates, base_dir, "asset", case_id, errors, missing)

    paths = record.get("paths")
    path_ids = []
    path_dimensions = {}
    if not isinstance(paths, list) or not paths:
        errors.append("paths-missing")
    else:
        for index, path in enumerate(paths):
            if not isinstance(path, dict) or not isinstance(path.get("id"), str) or not path["id"]:
                errors.append(f"path-{index}-invalid")
                continue
            path_id = path["id"]
            if path_id in path_ids:
                errors.append(f"path-{path_id}-duplicate")
            path_ids.append(path_id)
            if not isinstance(path.get("source"), str) or not path["source"]:
                errors.append(f"path-{path_id}-source-missing")
            if not isinstance(path.get("entrypoint"), str) or not path["entrypoint"]:
                errors.append(f"path-{path_id}-entrypoint-missing")
            if not _valid_string_list(path.get("call_path")):
                errors.append(f"path-{path_id}-call-path-invalid")
            dimensions = path.get("required_dimensions")
            if not _valid_string_list(dimensions):
                errors.append(f"path-{path_id}-dimensions-invalid")
                dimensions = []
            elif len(set(dimensions)) != len(dimensions):
                errors.append(f"path-{path_id}-dimension-duplicates")
            path_dimensions[path_id] = dimensions
            for dimension in dimensions:
                if dimension not in required_dimensions:
                    errors.append(f"path-{path_id}-dimension-not-declared-{dimension}")
        assigned_dimensions = {dimension for dimensions in path_dimensions.values() for dimension in dimensions}
        for dimension in required_dimensions:
            if dimension not in assigned_dimensions:
                errors.append(f"contract-dimension-unassigned-{dimension}")

    inventory = record.get("inventory")
    if not isinstance(inventory, dict):
        errors.append("inventory-missing")
        missing.append("asset.inventory_completeness")
    else:
        for key in ("enumeration_method", "source_basis"):
            if not isinstance(inventory.get(key), str) or not inventory[key].strip():
                errors.append(f"inventory-{key}-missing")
        for key in ("external_boundaries", "reachable_sinks", "declared_path_ids", "unverified"):
            if not _valid_string_list_or_empty(inventory.get(key)):
                errors.append(f"inventory-{key}-invalid")
        if _valid_string_list_or_empty(inventory.get("declared_path_ids")) and path_ids:
            if inventory["declared_path_ids"] != path_ids:
                errors.append("inventory-path-ids-do-not-match-paths")
        inventory_gate = record.get("asset_coverage", {}).get("inventory_completeness", {})
        if isinstance(inventory_gate, dict) and inventory_gate.get("status") == "PASS" and inventory.get("unverified"):
            errors.append("inventory-pass-with-unverified-items")

    path_coverage = record.get("path_coverage")
    if isinstance(path_coverage, dict):
        for path_id in set(path_coverage) - set(path_ids):
            errors.append(f"path-coverage-unknown-path-{path_id}")
    _validate_gate_map(path_coverage, [], base_dir, "path", case_id, errors, missing)
    for path_id in path_ids:
        _validate_gate_map(
            path_coverage.get(path_id) if isinstance(path_coverage, dict) else None,
            required_path_gates,
            base_dir,
            f"path.{path_id}",
            case_id,
            errors,
            missing,
            runtime=True,
        )

    dimension_coverage = record.get("path_dimension_coverage")
    if isinstance(dimension_coverage, dict):
        for path_id in set(dimension_coverage) - set(path_ids):
            errors.append(f"dimension-coverage-unknown-path-{path_id}")
    for path_id, dimensions in path_dimensions.items():
        coverage = dimension_coverage.get(path_id) if isinstance(dimension_coverage, dict) else None
        if isinstance(coverage, dict):
            for dimension in set(coverage) - set(dimensions):
                errors.append(f"path-{path_id}-dimension-coverage-unknown-{dimension}")
        for dimension in dimensions:
            full_label = f"path.{path_id}.dimension.{dimension}"
            status = _valid_status_gate(
                coverage.get(dimension) if isinstance(coverage, dict) else None,
                base_dir,
                full_label,
                case_id,
                errors,
            )
            if status != "PASS":
                missing.append(full_label)

    exclusions = record.get("exclusions", [])
    if not isinstance(exclusions, list):
        errors.append("exclusions-invalid")
    else:
        for index, exclusion in enumerate(exclusions):
            if not isinstance(exclusion, dict) or not isinstance(exclusion.get("dimension"), str) or not exclusion["dimension"] or not isinstance(exclusion.get("reason"), str) or not exclusion["reason"].strip():
                errors.append(f"exclusion-{index}-invalid")
            elif exclusion["dimension"] in required_dimensions:
                errors.append(f"required-dimension-explicitly-excluded-{exclusion['dimension']}")

    return _result(record, errors, missing)


def main():
    parser = argparse.ArgumentParser(description="Validate one asset's declared semantic verification scope")
    parser.add_argument("--contract", required=True)
    parser.add_argument("--base-dir")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    path = Path(args.contract)
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result = _result({}, [f"contract-read-failed:{exc.__class__.__name__}"], [])
    else:
        result = validate_asset_record(record, base_dir=Path(args.base_dir) if args.base_dir else path.parent)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"verdict={result['verdict']}")
        print(f"artifact_integrity={result['artifact_integrity']} scope_complete={result['scope_complete']}")
        for item in result["missing_gates"]:
            print(f"  missing: {item}")
        for item in result["errors"]:
            print(f"  error: {item}")
    return 0 if result["scope_complete"] else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
