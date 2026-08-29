#!/usr/bin/env python3
"""Validate NCNN PR #6383 local source, build, fixture, and runtime records.

The validator binds a narrow text-parser failure-cleanup contract to actual pinned
WSL worktrees, CMake caches, harness binaries, and fixture files. It validates
that the recorded base/head observations refer to the declared artifacts; it
never promotes the result to universal or formal semantic verification.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RATIO_RE = re.compile(r"^(\d+)\s*/\s*(\d+)$")
CACHE_RE = re.compile(r"^([^:#=\r\n]+):[^=\r\n]*=([^\r\n]*)$", re.MULTILINE)
CONFIG_KEYS = (
    "CMAKE_BUILD_TYPE",
    "CMAKE_CXX_COMPILER",
    "CMAKE_GENERATOR",
    "CMAKE_CXX_FLAGS",
    "CMAKE_CXX_FLAGS_RELEASE",
    "NCNN_RUNTIME_CPU",
    "NCNN_VULKAN",
    "NCNN_OPENMP",
    "NCNN_ASAN",
)


def _result(record, errors):
    valid = not errors
    return {
        "schema_version": 1,
        "case_id": record.get("case_id") if isinstance(record, dict) else None,
        "valid": valid,
        "verdict": "NCNN_PR6383_ARTIFACT_BINDING_VERIFIED" if valid else "REVIEW",
        "runtime_status": "RECORDED_LOCAL_BASE_HEAD_PAIR" if valid else "REVIEW",
        "errors": errors,
        "formal_proof": False,
        "proof_scope": "pinned NCNN PR #6383 text ParamDict-failure contract artifacts and recorded local base/head observations only",
    }


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve(path_value, base_dir):
    if not isinstance(path_value, str) or not path_value.strip():
        return None
    path = Path(path_value)
    return path if path.is_absolute() else base_dir / path


def _valid_sha(value, pattern):
    return isinstance(value, str) and pattern.fullmatch(value.lower()) is not None


def _check_file(entry, base_dir, label, errors, expected_path=None):
    if not isinstance(entry, dict):
        errors.append(f"{label}-missing")
        return None
    path = _resolve(entry.get("path"), base_dir)
    expected_hash = entry.get("sha256")
    if path is None:
        errors.append(f"{label}-path-invalid")
        return None
    if expected_path is not None:
        try:
            if path.resolve() != expected_path.resolve():
                errors.append(f"{label}-path-not-bound")
        except OSError:
            errors.append(f"{label}-path-unresolvable")
    if not path.is_file():
        errors.append(f"{label}-file-missing")
        return None
    if not _valid_sha(expected_hash, SHA256_RE):
        errors.append(f"{label}-sha256-invalid")
        return None
    try:
        actual_hash = _sha256(path)
    except OSError:
        errors.append(f"{label}-unreadable")
        return None
    if actual_hash != expected_hash.lower():
        errors.append(f"{label}-sha256-mismatch")
    if path.stat().st_size <= 0:
        errors.append(f"{label}-empty")
    return path


def _read_cache(path, label, errors):
    if path is None or not path.is_file():
        errors.append(f"{label}-missing")
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        errors.append(f"{label}-unreadable")
        return None
    return {match.group(1): match.group(2) for match in CACHE_RE.finditer(text)}


def _wsl_git(worktree_wsl, distro, arguments, label, errors):
    if not isinstance(worktree_wsl, str) or not worktree_wsl.startswith("/"):
        errors.append(f"{label}-wsl-worktree-invalid")
        return None
    if not isinstance(distro, str) or not distro:
        errors.append(f"{label}-wsl-distro-invalid")
        return None
    try:
        completed = subprocess.run(
            ["wsl.exe", "-d", distro, "--", "git", "-C", worktree_wsl, *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError:
        errors.append(f"{label}-wsl-git-unavailable")
        return None
    if completed.returncode != 0:
        errors.append(f"{label}-wsl-git-failed")
        return None
    return completed.stdout.strip()


def _ratio(value, require_complete):
    if not isinstance(value, str):
        return False
    match = RATIO_RE.fullmatch(value.strip())
    if match is None:
        return False
    left, right = (int(item) for item in match.groups())
    if right <= 0:
        return False
    return left == right if require_complete else left < right


def _check_revision(label, entry, base_dir, expected_sha, config, errors):
    if not isinstance(entry, dict):
        errors.append(f"{label}-missing")
        return
    worktree = _resolve(entry.get("worktree"), base_dir)
    build_dir = _resolve(entry.get("build_dir"), base_dir)
    library_build_dir = _resolve(entry.get("library_build_dir"), base_dir) or build_dir
    if worktree is None or not worktree.is_dir():
        errors.append(f"{label}-worktree-missing")
    if build_dir is None or not build_dir.is_dir():
        errors.append(f"{label}-build-dir-missing")
    if not _valid_sha(entry.get("sha"), SHA1_RE) or entry.get("sha", "").lower() != expected_sha:
        errors.append(f"{label}-sha-invalid")

    if worktree is not None:
        _check_file(entry.get("source"), base_dir, f"{label}-source", errors, worktree / "src" / "net.cpp")
    else:
        _check_file(entry.get("source"), base_dir, f"{label}-source", errors)
    if build_dir is not None:
        expected_harness = build_dir / entry.get("harness_name", "pr6383_error_path")
        _check_file(entry.get("harness"), base_dir, f"{label}-harness", errors, expected_harness)
        cache_entry = entry.get("cmake_cache")
        cache_name = entry.get("cache_name", "CMakeCache.txt")
        cache_expected_dir = build_dir / entry.get("cache_subdir", "")
        cache_path = _check_file(cache_entry, base_dir, f"{label}-cmake-cache", errors, cache_expected_dir / cache_name)
        cache = _read_cache(cache_path, f"{label}-cmake-cache", errors)
        if cache is not None:
            if worktree is not None and entry.get("cache_home_is_worktree", True):
                expected_home = entry.get("worktree_wsl")
                if cache.get("CMAKE_HOME_DIRECTORY") != expected_home:
                    errors.append(f"{label}-cmake-home-directory-mismatch")
            wrapper_config = entry.get("wrapper_config", not bool(entry.get("library_build_dir")))
            if wrapper_config:
                for key, expected in config.items():
                    if key in cache and cache.get(key) != expected:
                        errors.append(f"{label}-cmake-config-mismatch-{key}")
    if library_build_dir is not None and library_build_dir != build_dir:
        library_cache_entry = entry.get("library_cmake_cache")
        library_cache = _check_file(library_cache_entry, base_dir, f"{label}-library-cmake-cache", errors, library_build_dir / "CMakeCache.txt")
        library_values = _read_cache(library_cache, f"{label}-library-cmake-cache", errors)
        if library_values is not None:
            for key, expected in config.items():
                if library_values.get(key) != expected:
                    errors.append(f"{label}-library-cmake-config-mismatch-{key}")

    worktree_wsl = entry.get("worktree_wsl")
    distro = entry.get("wsl_distro")
    actual_head = _wsl_git(worktree_wsl, distro, ["rev-parse", "HEAD"], label, errors)
    if actual_head is not None and actual_head.lower() != expected_sha:
        errors.append(f"{label}-git-head-mismatch")
    status = _wsl_git(worktree_wsl, distro, ["status", "--porcelain"], label, errors)
    if status is not None and status:
        errors.append(f"{label}-git-worktree-not-clean")


def _check_runtime(record, errors):
    runtime = record.get("runtime")
    if not isinstance(runtime, dict):
        errors.append("runtime-missing")
        return
    base = runtime.get("base")
    head = runtime.get("head")
    if not isinstance(base, dict) or not isinstance(head, dict):
        errors.append("runtime-base-or-head-missing")
        return
    if base.get("executed") is not True or head.get("executed") is not True:
        errors.append("runtime-execution-not-recorded")
    if base.get("unsafe_behavior_observed") is not True:
        errors.append("runtime-base-unsafe-behavior-not-observed")
    if not _ratio(base.get("malicious_rejected"), require_complete=False):
        errors.append("runtime-base-preimage-ratio-invalid")
    if not _ratio(base.get("benign_passed"), require_complete=True):
        errors.append("runtime-base-benign-ratio-invalid")
    if not _ratio(head.get("malicious_rejected"), require_complete=True):
        errors.append("runtime-head-malicious-ratio-invalid")
    if not _ratio(head.get("benign_passed"), require_complete=True):
        errors.append("runtime-head-benign-ratio-invalid")
    if base.get("infrastructure_failures") != 0 or head.get("infrastructure_failures") != 0:
        errors.append("runtime-infrastructure-failures")
    if head.get("verdict") != "PASS":
        errors.append("runtime-head-verdict-not-pass")


def validate_evidence(record, base_dir=None):
    if not isinstance(record, dict):
        return _result({}, ["record-root-not-object"])
    base_dir = Path(base_dir or Path.cwd()).resolve()
    errors = []
    if record.get("case_id") != "NCNN-PR-6383":
        errors.append("case-id-invalid")
    if not isinstance(record.get("official_source"), str) or not record["official_source"].startswith("https://"):
        errors.append("official-source-invalid")
    if record.get("contract_id") not in {
        "text-paramdict-failure-cleanup",
        "text-layer-load-param-failure-cleanup",
        "bin-parser-failure-cleanup",
    }:
        errors.append("contract-id-invalid")
    if record.get("formal_proof") is not False or record.get("universal_claim") is not False:
        errors.append("proof-or-universal-claim-invalid")
    revisions = record.get("revisions")
    if not isinstance(revisions, dict) or not _valid_sha(revisions.get("base"), SHA1_RE) or not _valid_sha(revisions.get("head"), SHA1_RE):
        errors.append("revisions-invalid")
        return _result(record, errors)
    if revisions["base"].lower() == revisions["head"].lower():
        errors.append("revisions-not-distinct")

    config = record.get("configuration")
    if not isinstance(config, dict) or any(not isinstance(config.get(key), str) for key in CONFIG_KEYS):
        errors.append("configuration-invalid")
        config = {}
    _check_revision("base", record.get("base"), base_dir, revisions["base"].lower(), config, errors)
    _check_revision("head", record.get("head"), base_dir, revisions["head"].lower(), config, errors)
    _check_file(record.get("harness_source"), base_dir, "harness-source", errors)
    fixtures = record.get("fixtures")
    if not isinstance(fixtures, dict):
        errors.append("fixtures-missing")
    else:
        _check_file(fixtures.get("malicious"), base_dir, "malicious-fixture", errors)
        benign = fixtures.get("benign")
        if isinstance(benign, dict) and isinstance(benign.get("base"), dict) and isinstance(benign.get("head"), dict):
            _check_file(benign["base"], base_dir, "benign-base-fixture", errors)
            _check_file(benign["head"], base_dir, "benign-head-fixture", errors)
        else:
            _check_file(benign, base_dir, "benign-fixture", errors)
    _check_runtime(record, errors)
    return _result(record, errors)


def main():
    parser = argparse.ArgumentParser(description="Validate NCNN PR #6383 asset evidence")
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--out")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    evidence_path = Path(args.evidence)
    try:
        record = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result = _result({}, [f"evidence-read-failed:{exc.__class__.__name__}"])
    else:
        result = validate_evidence(record, evidence_path.parent)
    if args.out:
        Path(args.out).write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"verdict={result['verdict']}")
        for error in result["errors"]:
            print(f"  {error}")
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
