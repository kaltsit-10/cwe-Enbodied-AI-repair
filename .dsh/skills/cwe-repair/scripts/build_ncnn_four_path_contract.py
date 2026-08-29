#!/usr/bin/env python3
"""Generate the four ordinary NCNN #6383 parser-path contract."""
import copy, json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / 'examples'

def ref(path, sha, assertions):
    return {'status': 'PASS', 'evidence': [{'path': path, 'sha256': sha, 'case_id': 'NCNN-PR-6383', 'assertions': assertions}]}

def runtime_gates(evidence_path, evidence_sha):
    return {
        'paired_build': ref(evidence_path, evidence_sha, [{'path': 'runtime.base.executed', 'equals': True}]),
        'preimage_witness': {'status': 'PASS', 'metrics': {'unsafe_behavior_observed': True, 'malicious_rejected': '0/1', 'infrastructure_failures': 0}, 'evidence': [{'path': evidence_path, 'sha256': evidence_sha, 'case_id': 'NCNN-PR-6383', 'assertions': [{'path': 'runtime.base.unsafe_behavior_observed', 'equals': True}]}]},
        'runtime_head': ref(evidence_path, evidence_sha, [{'path': 'runtime.head.verdict', 'equals': 'PASS'}]),
        'negative_rejection': {'status': 'PASS', 'metrics': {'malicious_rejected': '1/1', 'infrastructure_failures': 0}, 'evidence': [{'path': evidence_path, 'sha256': evidence_sha, 'case_id': 'NCNN-PR-6383', 'assertions': [{'path': 'runtime.head.malicious_rejected', 'equals': '1/1'}]}]},
        'benign_preservation': {'status': 'PASS', 'metrics': {'benign_passed': '1/1', 'infrastructure_failures': 0}, 'evidence': [{'path': evidence_path, 'sha256': evidence_sha, 'case_id': 'NCNN-PR-6383', 'assertions': [{'path': 'runtime.head.benign_passed', 'equals': '1/1'}]}]},
    }

def main():
    out = {
      'schema_version': 1, 'asset_id': 'Tencent/ncnn', 'case_id': 'NCNN-PR-6383', 'asset_kind': 'embodied-ai-inference-runtime', 'scope_type': 'single-asset-declared-contract', 'official_source': 'https://github.com/Tencent/ncnn/pull/6383', 'universal_claim': False, 'formal_proof': False,
      'revisions': {'base': '5154f22a4c146959beda380dc7522de53704d940', 'head': '1d6c7f55d11aee7d9808802ff913f8482f8e2ac7'},
      'declared_scope': {'providers': ['cpu'], 'targets': ['pr6383_error_path', 'pr6383_bin_error_path'], 'configurations': ['release', 'Unix Makefiles', 'NCNN_VULKAN=OFF', 'NCNN_OPENMP=OFF', 'NCNN_ASAN=OFF'], 'input_domains': ['finite local TEXT parser fixtures', 'finite local BIN parser fixtures']},
      'contract': {'required_asset_gates': ['official_provenance', 'source_scope', 'inventory_completeness', 'reproducibility', 'safety'], 'required_path_gates': ['static_contract', 'symmetry', 'detect', 'repair_plan', 'paired_build', 'preimage_witness', 'runtime_head', 'negative_rejection', 'benign_preservation'], 'required_dimensions': ['text_paramdict_failure', 'text_layer_load_param_failure', 'bin_paramdict_failure', 'bin_layer_load_param_failure']},
      'safety': {'no_external_inputs': True, 'no_network_target_execution': True, 'no_oom_or_huge_allocation': True, 'no_exploit_chain': True},
      'asset_coverage': {}, 'inventory': {'enumeration_method': 'pinned src/net.cpp text/bin diff plus four bounded local fixtures', 'source_basis': 'ncnn_pr6383_bin_path_inventory.json', 'external_boundaries': ['finite local TEXT parameter file', 'finite local BIN parameter file', 'Net::load_param', 'Net::load_param_bin'], 'reachable_sinks': ['TEXT ParamDict failure', 'TEXT layer failure', 'BIN ParamDict failure', 'BIN layer failure'], 'declared_path_ids': ['text-paramdict-load-failure-cleanup', 'text-layer-load-param-failure-cleanup', 'bin-paramdict-load-failure-cleanup', 'bin-layer-load-param-failure-cleanup'], 'unverified': []}, 'paths': [], 'path_coverage': {}, 'path_dimension_coverage': {}, 'exclusions': [{'dimension': 'text_custom_cpu_fallback', 'reason': 'requires Vulkan-enabled paired build'}, {'dimension': 'bin_custom_cpu_fallback', 'reason': 'requires Vulkan-enabled paired build'}, {'dimension': 'vulkan_fallback', 'reason': 'pinned worktree lacks glslang submodule and system target'}, {'dimension': 'asan_instrumentation', 'reason': 'NCNN_ASAN=OFF'}]
    }
    import hashlib
    def digest(name):
        h = hashlib.sha256(); h.update((ROOT / name).read_bytes()); return h.hexdigest()
    static_sha = digest('ncnn_pr6383_text_paramdict_static_evidence.json')
    inv_sha = digest('ncnn_pr6383_bin_path_inventory.json')
    sym_sha = digest('ncnn_pr6383_bin_path_symmetry.json')
    bin_sha = digest('ncnn_pr6383_bin_failure_evidence.json')
    out['asset_coverage'] = {
      'official_provenance': ref('ncnn_pr6383_text_paramdict_static_evidence.json', static_sha, [{'path': 'case_id', 'equals': 'NCNN-PR-6383'}]),
      'source_scope': ref('ncnn_pr6383_bin_path_inventory.json', inv_sha, [{'path': 'declared_path_ids.0', 'equals': 'text-paramdict-load-failure-cleanup'}]),
      'inventory_completeness': ref('ncnn_pr6383_bin_path_inventory.json', inv_sha, [{'path': 'declared_path_ids.3', 'equals': 'bin-layer-load-param-failure-cleanup'}]),
      'reproducibility': ref('ncnn_pr6383_bin_failure_evidence_validation.json', digest('ncnn_pr6383_bin_failure_evidence_validation.json'), [{'path': 'valid', 'equals': True}]),
      'safety': ref('ncnn_pr6383_bin_failure_evidence.json', bin_sha, [{'path': 'safety.local_pinned_artifacts_only', 'equals': True}])
    }
    path_specs = [
      ('text-paramdict-load-failure-cleanup', 'Net::load_param', ['ParamDict::load_param','pdlr != 0','cleanup','return -1'], 'text_paramdict_failure', 'ncnn_pr6383_paramdict_failure_evidence.json', 'b2bf81f464150b4a1cf2d9e90e7a8c5986af5c86c58d13c34b774ab03c69475b'),
      ('text-layer-load-param-failure-cleanup', 'Net::load_param', ['Interp::load_param','lr != 0','cleanup','return -1'], 'text_layer_load_param_failure', 'ncnn_pr6383_text_layer_failure_evidence.json', '929fc165a706ad4273d8fbbc002df3125863c8f32159eac8f777acbf57d303ca'),
      ('bin-paramdict-load-failure-cleanup', 'Net::load_param_bin', ['ParamDict::load_param_bin','pdlr != 0','cleanup','return -1'], 'bin_paramdict_failure', 'ncnn_pr6383_bin_failure_evidence.json', bin_sha),
      ('bin-layer-load-param-failure-cleanup', 'Net::load_param_bin', ['Interp::load_param','lr != 0','cleanup','return -1'], 'bin_layer_load_param_failure', 'ncnn_pr6383_bin_failure_evidence.json', bin_sha),
    ]
    for pid, entry, call_path, dim, ev, evsha in path_specs:
        gates = {'detect': ref('ncnn_pr6383_bin_path_inventory.json', inv_sha, [{'path': 'declared_path_ids.0', 'equals': 'text-paramdict-load-failure-cleanup'}]), 'repair_plan': ref('ncnn_pr6383_bin_path_symmetry.json', sym_sha, [{'path': 'verdict', 'equals': 'PASS'}]), 'static_contract': ref('ncnn_pr6383_bin_path_symmetry.json', sym_sha, [{'path': 'verdict', 'equals': 'PASS'}]), 'symmetry': ref('ncnn_pr6383_bin_path_symmetry.json', sym_sha, [{'path': 'verdict', 'equals': 'PASS'}])}
        gates.update(runtime_gates(ev, evsha))
        out['paths'].append({'id': pid, 'source': 'src/net.cpp', 'entrypoint': entry, 'call_path': call_path, 'required_dimensions': [dim]})
        gates['detect']['evidence_role']='detector'; gates['repair_plan']['evidence_role']='repair_plan'
        out['path_coverage'][pid] = gates
        out['path_dimension_coverage'][pid] = {dim: ref(ev, evsha, [{'path': 'runtime.head.malicious_rejected', 'equals': '1/1'}])}
    (ROOT / 'ncnn_pr6383_four_parser_paths_asset_contract.json').write_text(json.dumps(out, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('generated four-path contract')

if __name__ == '__main__': main()
