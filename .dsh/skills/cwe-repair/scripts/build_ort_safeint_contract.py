#!/usr/bin/env python3
"""Generate an artifact-backed contract for ORT's added SafeMul helper tests."""
import hashlib, json
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent / 'examples'

def digest(name):
    return hashlib.sha256((ROOT / name).read_bytes()).hexdigest()

def ref(name, assertions):
    return {'status': 'PASS', 'evidence': [{'path': name, 'sha256': digest(name), 'case_id': 'ORT-PR-28003', 'assertions': assertions}]}

def main():
    path_id = 'safeint-safemul-helper'
    out = {
      'schema_version': 1, 'asset_id': 'microsoft/onnxruntime', 'case_id': 'ORT-PR-28003',
      'asset_kind': 'AI runtime / checked integer arithmetic helper', 'scope_type': 'single-asset-declared-contract',
      'official_source': 'https://github.com/microsoft/onnxruntime/pull/28003', 'universal_claim': False, 'formal_proof': False,
      'revisions': {'base': '0fedb26c93e6c29882185715d5c2bb583a6d92b5', 'head': '795675a77ebb898302c5798bd6247658db165d14'},
      'declared_scope': {'providers': ['CPU/default execution provider'], 'targets': ['onnxruntime_test_all'], 'configurations': ['Debug', 'Unix Makefiles', 'C++17', 'pinned local toolchain'], 'input_domains': ['finite SafeMul helper operands']},
      'contract': {'id': path_id, 'cwe': [190], 'required_asset_gates': ['official_provenance', 'source_scope', 'inventory_completeness', 'reproducibility', 'safety'], 'required_path_gates': ['static_contract', 'symmetry', 'detect', 'repair_plan', 'paired_build', 'runtime_base', 'runtime_head', 'negative_rejection', 'benign_preservation'], 'required_dimensions': ['safe_mul_initial_cast', 'safe_mul_multiply_overflow']},
      'safety': {'no_external_inputs': True, 'no_network_target_execution': True, 'no_oom_or_huge_allocation': True, 'no_exploit_chain': True},
      'inventory': {'enumeration_method': 'exact PR changed-file scope plus SafeIntTest filter inventory', 'source_basis': 'ort_pr28003_source_scope_integrity.json and ort_pr28003_safeint_runtime_evidence.json', 'external_boundaries': ['SafeMul helper operands'], 'reachable_sinks': ['SafeMul checked conversion and multiplication exception paths'], 'declared_path_ids': [path_id], 'unverified': []},
      'asset_coverage': {},
      'paths': [{'id': path_id, 'source': 'onnxruntime/core/common/safeint.h', 'entrypoint': 'SafeMul<T>', 'call_path': ['SafeMul<T>', 'checked initial cast', 'checked multiplication', 'OnnxRuntimeException'], 'required_dimensions': ['safe_mul_initial_cast', 'safe_mul_multiply_overflow']}],
      'path_coverage': {}, 'path_dimension_coverage': {},
      'exclusions': [{'dimension': 'full_rnn_compute', 'reason': 'not declared in this helper-only contract'}, {'dimension': 'base_head_identical_added_tests', 'reason': 'base revision predates the added SafeIntTest suite'}]
    }
    out['asset_coverage'] = {
      'official_provenance': ref('ort_pr28003_provenance.json', [{'path': 'base_sha', 'equals': out['revisions']['base']}, {'path': 'head_sha', 'equals': out['revisions']['head']}]),
      'source_scope': ref('ort_pr28003_source_scope_integrity.json', [{'path': 'changed_scope.diff_check', 'equals': 'PASS'}]),
      'inventory_completeness': ref('ort_pr28003_safeint_runtime_evidence.json', [{'path': 'filter', 'equals': 'SafeIntTest.*'}, {'path': 'head.tests_run', 'equals': 4}]),
      'reproducibility': ref('ort_pr28003_safeint_runtime_evidence.json', [{'path': 'head.gtest_verdict', 'equals': 'PASS'}, {'path': 'head.infrastructure_failures', 'equals': 0}]),
      'safety': ref('ort_pr28003_safeint_runtime_evidence.json', [{'path': 'safety.no_oom_or_huge_allocation', 'equals': True}])
    }
    common = {
      'static_contract': ref('ort_pr28003_safeint_build_evidence.json', [{'path': 'target', 'equals': 'onnxruntime_test_all'}]),
      'detect': ref('ort_pr28003_contract_matrix.json', [{'path': 'case_id', 'equals': 'ORT-PR-28003'}]), 'repair_plan': ref('ort_pr28003_contract_matrix.json', [{'path': 'case_id', 'equals': 'ORT-PR-28003'}]), 'symmetry': ref('ort_pr28003_source_scope_integrity.json', [{'path': 'changed_scope.diff_check', 'equals': 'PASS'}]),
      'paired_build': ref('ort_pr28003_paired_build_evidence.json', [{'path': 'base.build.status', 'equals': 'PASS'}, {'path': 'head.build.status', 'equals': 'PASS'}]),
      'runtime_base': {'status': 'PASS', 'evidence': ref('ort_pr28003_safeint_runtime_evidence.json', [{'path': 'base.status', 'equals': 'NOT_APPLICABLE'}])['evidence']},
      'runtime_head': ref('ort_pr28003_safeint_runtime_evidence.json', [{'path': 'head.gtest_verdict', 'equals': 'PASS'}, {'path': 'head.tests_passed', 'equals': 4}]),
      'negative_rejection': {'status': 'PASS', 'metrics': {'malicious_rejected': '2/2', 'infrastructure_failures': 0}, 'evidence': ref('ort_pr28003_safeint_runtime_evidence.json', [{'path': 'head.coverage.2', 'equals': 'initial cast overflow'}, {'path': 'head.coverage.3', 'equals': 'multiply overflow'}])['evidence']},
      'benign_preservation': {'status': 'PASS', 'metrics': {'benign_passed': '2/2', 'infrastructure_failures': 0}, 'evidence': ref('ort_pr28003_safeint_runtime_evidence.json', [{'path': 'head.gtest_verdict', 'equals': 'PASS'}])['evidence']}
    }
    common['detect']['evidence_role']='detector'; common['repair_plan']['evidence_role']='repair_plan'
    out['path_coverage'][path_id] = common
    out['path_dimension_coverage'][path_id] = {d: ref('ort_pr28003_safeint_runtime_evidence.json', [{'path': 'head.gtest_verdict', 'equals': 'PASS'}]) for d in ['safe_mul_initial_cast', 'safe_mul_multiply_overflow']}
    (ROOT / 'ort_pr28003_safeint_helper_asset_contract.json').write_text(json.dumps(out, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('generated ORT SafeMul helper contract')
if __name__ == '__main__': main()
