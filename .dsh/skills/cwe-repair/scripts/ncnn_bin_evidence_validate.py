#!/usr/bin/env python3
"""Validate NCNN BIN evidence with Windows UNC and WSL build paths."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

SHA256 = re.compile(r"^[0-9a-f]{64}$", re.I)
SHA1 = re.compile(r"^[0-9a-f]{40}$", re.I)

def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def check_file(item, label, errors, base_dir):
    if not isinstance(item, dict) or not isinstance(item.get('path'), str):
        errors.append(label + '-missing')
        return
    if not SHA256.fullmatch(str(item.get('sha256', ''))):
        errors.append(label + '-sha256-invalid')
        return
    path = Path(item['path'])
    if not path.is_absolute():
        path = base_dir / path
    if not path.is_file():
        errors.append(label + '-file-missing')
        return
    if sha(path) != item['sha256'].lower():
        errors.append(label + '-sha256-mismatch')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--evidence', required=True)
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()
    p = Path(args.evidence)
    errors = []
    try:
        d = json.loads(p.read_text(encoding='utf-8'))
    except Exception as exc:
        result = {'valid': False, 'verdict': 'REVIEW', 'errors': ['read-failed:' + type(exc).__name__]}
    else:
        if d.get('case_id') != 'NCNN-PR-6383': errors.append('case-id-invalid')
        if d.get('formal_proof') is not False or d.get('universal_claim') is not False: errors.append('claim-boundary-invalid')
        for side in ('base', 'head'):
            entry = d.get(side, {})
            if not SHA1.fullmatch(str(entry.get('sha', ''))): errors.append(side + '-revision-invalid')
            for name in ('cmake_cache', 'harness'):
                check_file(entry.get(name), side + '-' + name, errors, p.parent)
            lib = entry.get('library_cmake_cache')
            check_file(lib, side + '-library-cmake-cache', errors, p.parent)
        check_file(d.get('harness_source'), 'harness-source', errors, p.parent)
        check_file(d.get('fixtures', {}).get('malicious'), 'malicious-fixture', errors, p.parent)
        benign = d.get('fixtures', {}).get('benign', {})
        check_file(benign.get('base'), 'benign-base-fixture', errors, p.parent)
        check_file(benign.get('head'), 'benign-head-fixture', errors, p.parent)
        runtime = d.get('runtime', {})
        for side in ('base', 'head'):
            r = runtime.get(side, {})
            if r.get('executed') is not True: errors.append('runtime-' + side + '-not-executed')
            if r.get('infrastructure_failures') != 0: errors.append('runtime-' + side + '-infrastructure-failures')
        result = {'schema_version': 1, 'case_id': d.get('case_id'), 'valid': not errors, 'verdict': 'NCNN_PR6383_BIN_ARTIFACT_BINDING_VERIFIED' if not errors else 'REVIEW', 'runtime_status': 'RECORDED_LOCAL_BASE_HEAD_PAIR' if not errors else 'REVIEW', 'errors': errors, 'formal_proof': False, 'proof_scope': 'pinned NCNN PR #6383 binary parser failure paths only'}
    print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else result['verdict'])
    return 0 if result['valid'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
