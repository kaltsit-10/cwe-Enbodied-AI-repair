#!/usr/bin/env python3
"""Verify local paired build artifacts for a PR that adds a test source.

The verifier reads the declared CMake manifests, source trees, CMake caches, and
output binaries. It deliberately reports verdict=REVIEW even when artifacts are
valid: build-only evidence must never be reusable as a runtime or semantic PASS.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CACHE_RE = re.compile(r"^([^:#=\r\n]+):[^=\r\n]*=([^\r\n]*)$", re.MULTILINE)
MANIFEST_SOURCE_RE = re.compile(r'^\s*"([^"]+\.cc)"\s+"([^"]+\.o)"', re.MULTILINE)
CONFIGURATION_KEYS = (
    "CMAKE_BUILD_TYPE",
    "CMAKE_CXX_COMPILER",
    "CMAKE_GENERATOR",
    "CMAKE_CXX_FLAGS",
    "CMAKE_CXX_FLAGS_DEBUG",
    "CMAKE_CXX_STANDARD",
)


def _result(record, errors):
    return {
        "schema_version": 1,
        "case_id": record.get("case_id") if isinstance(record, dict) else None,
        "target": record.get("target") if isinstance(record, dict) else None,
        "valid": not errors,
        "verdict": "REVIEW",
        "build_only_status": "BUILD_ONLY_NOT_RUN" if not errors else "REVIEW",
        "runtime_status": "NOT_RUN",
        "errors": errors,
        "formal_proof": False,
        "proof_scope": "local pinned base/head manifests, sources, caches, and target binaries only; no test binary executed",
    }


def _sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def _read_text(path, label, errors):
    if not path.is_file():
        errors.append(f"{label}-missing")
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        errors.append(f"{label}-unreadable")
        return None


def _cache_values(path, label, errors):
    text = _read_text(path, label, errors)
    if text is None:
        return None
    return {match.group(1): match.group(2) for match in CACHE_RE.finditer(text)}


def _resolved_within(path, root):
    """Return a resolved path only when it stays under root."""
    try:
        resolved_path = path.resolve()
        resolved_path.relative_to(root.resolve())
        return resolved_path
    except (OSError, ValueError):
        return None


def _manifest_sources(path, label, source_root, build_dir, errors):
    """Read and bind DependInfo source/object entries to actual local paths."""
    text = _read_text(path, label, errors)
    if text is None:
        return None
    entries = {}
    for raw_source, raw_object in MANIFEST_SOURCE_RE.findall(text):
        source_path = _resolved_within(Path(raw_source), source_root)
        if source_path is None:
            errors.append(f"{label}-source-outside-source-root")
            continue
        try:
            source = source_path.relative_to(source_root.resolve()).as_posix()
        except ValueError:
            errors.append(f"{label}-source-relative-path-invalid")
            continue
        if not source.startswith("onnxruntime/"):
            errors.append(f"{label}-source-outside-onnxruntime")
            continue
        if not source_path.is_file():
            errors.append(f"{label}-source-file-missing")
            continue
        object_relative = Path(raw_object)
        object_path = _resolved_within(build_dir / object_relative, build_dir)
        if object_relative.is_absolute() or object_path is None:
            errors.append(f"{label}-object-path-outside-build-dir")
            continue
        if not object_path.is_file() or object_path.stat().st_size <= 0:
            errors.append(f"{label}-object-file-missing")
        if source in entries:
            errors.append(f"{label}-source-list-duplicates")
            continue
        entries[source] = {"source_path": source_path, "object_path": object_path}
    if not entries:
        errors.append(f"{label}-source-list-empty")
        return None
    return entries


def _valid_sha(value, pattern):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _valid_nonbool_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _entry(record, label, target, source, configuration, errors):
    entry = record.get(label)
    if not isinstance(entry, dict):
        errors.append(f"{label}-missing")
        return None
    if not _valid_sha(entry.get("sha"), SHA1_RE):
        errors.append(f"{label}-sha-invalid")

    source_root_value = entry.get("source_root")
    source_root = Path(source_root_value) if isinstance(source_root_value, str) and source_root_value else None
    if source_root is None or not source_root.is_dir():
        errors.append(f"{label}-source-root-missing")
        source_root = None
    else:
        source_root = source_root.resolve()
    source_file = source_root / source if source_root is not None else None

    build = entry.get("build")
    build_dir = None
    sources = None
    if not isinstance(build, dict):
        errors.append(f"{label}-build-missing")
    else:
        build_dir_value = build.get("build_dir")
        build_dir = Path(build_dir_value) if isinstance(build_dir_value, str) and build_dir_value else None
        if build_dir is None or not build_dir.is_dir():
            errors.append(f"{label}-build-dir-missing")
            build_dir = None
        else:
            build_dir = build_dir.resolve()
        if build.get("status") != "PASS" or build.get("exit_code") != 0:
            errors.append(f"{label}-build-not-pass")
        if build.get("target") != target:
            errors.append(f"{label}-target-mismatch")

    configure = entry.get("configure")
    cache_values = None
    if not isinstance(configure, dict) or configure.get("status") != "PASS":
        errors.append(f"{label}-configure-not-pass")
    else:
        cache_path_value = configure.get("cmake_cache")
        cache_path = Path(cache_path_value) if isinstance(cache_path_value, str) and cache_path_value else None
        expected_cache = build_dir / "CMakeCache.txt" if build_dir is not None else None
        if cache_path is None:
            errors.append(f"{label}-cmake-cache-path-missing")
        elif expected_cache is None or cache_path.resolve() != expected_cache:
            errors.append(f"{label}-cmake-cache-not-in-build-dir")
        else:
            cache_values = _cache_values(cache_path, f"{label}-cmake-cache", errors)
            if cache_values is not None:
                for key, expected in configuration.items():
                    if cache_values.get(key) != expected:
                        errors.append(f"{label}-configuration-{key.lower()}-mismatch")

    if isinstance(build, dict):
        manifest_value = build.get("target_source_manifest")
        expected_manifest = build_dir / "CMakeFiles" / f"{target}.dir" / "DependInfo.cmake" if build_dir is not None else None
        if not isinstance(manifest_value, str) or not manifest_value:
            errors.append(f"{label}-manifest-path-missing")
        elif expected_manifest is None or Path(manifest_value).resolve() != expected_manifest:
            errors.append(f"{label}-manifest-not-target-manifest")
        elif source_root is not None:
            sources = _manifest_sources(expected_manifest, f"{label}-manifest", source_root, build_dir, errors)
            declared_count = build.get("manifest_test_source_count")
            if not _valid_nonbool_int(declared_count) or declared_count <= 0:
                errors.append(f"{label}-manifest-count-invalid")
            elif sources is not None and declared_count != len(sources):
                errors.append(f"{label}-manifest-count-does-not-match-artifact")

        binary_value = build.get("binary")
        binary_size = build.get("binary_size")
        digest = build.get("binary_sha256")
        expected_binary = build_dir / target if build_dir is not None else None
        if not isinstance(binary_value, str) or not binary_value:
            errors.append(f"{label}-binary-path-missing")
        elif expected_binary is None or Path(binary_value).resolve() != expected_binary:
            errors.append(f"{label}-binary-not-target-output")
        elif not _valid_nonbool_int(binary_size) or binary_size <= 0:
            errors.append(f"{label}-binary-size-invalid")
        elif not _valid_sha(digest, SHA256_RE):
            errors.append(f"{label}-binary-sha256-invalid")
        elif not expected_binary.is_file() or expected_binary.stat().st_size <= 0:
            errors.append(f"{label}-binary-missing")
        elif expected_binary.stat().st_size != binary_size:
            errors.append(f"{label}-binary-size-mismatch")
        else:
            try:
                if _sha256_file(expected_binary) != digest:
                    errors.append(f"{label}-binary-sha256-mismatch")
            except OSError:
                errors.append(f"{label}-binary-unreadable")

    return {
        "source_root": source_root,
        "source_file": source_file,
        "build_dir": build_dir,
        "sources": sources,
        "cache_values": cache_values,
    }


def validate_evidence(record):
    """Verify artifact-backed paired build-only evidence without runtime uplift."""
    if not isinstance(record, dict):
        return _result({}, ["record-root-not-object"])

    errors = []
    if not isinstance(record.get("case_id"), str) or not record["case_id"]:
        errors.append("case-id-missing")
    target = record.get("target")
    if not isinstance(target, str) or not target:
        errors.append("target-missing")
    source = record.get("added_contract_test_source")
    if not isinstance(source, str) or not source.startswith("onnxruntime/") or not source.endswith(".cc"):
        errors.append("added-contract-test-source-invalid")
    source_sha256 = record.get("head_added_test_source_sha256")
    if not _valid_sha(source_sha256, SHA256_RE):
        errors.append("head-added-test-source-sha256-invalid")

    configuration = record.get("configuration")
    if not isinstance(configuration, dict) or set(configuration) != set(CONFIGURATION_KEYS):
        errors.append("configuration-keys-invalid")
        configuration = {}
    elif any(
        not isinstance(configuration[key], str)
        or (key != "CMAKE_CXX_FLAGS" and not configuration[key])
        for key in CONFIGURATION_KEYS
    ):
        errors.append("configuration-values-invalid")

    toolchain = record.get("toolchain")
    if not isinstance(toolchain, dict) or any(not isinstance(toolchain.get(key), str) or not toolchain[key] for key in ("cmake", "compiler", "generator")):
        errors.append("toolchain-missing")
    elif configuration:
        if toolchain["compiler"] != configuration["CMAKE_CXX_COMPILER"]:
            errors.append("toolchain-compiler-does-not-match-configuration")
        if toolchain["generator"] != configuration["CMAKE_GENERATOR"]:
            errors.append("toolchain-generator-does-not-match-configuration")

    execution = record.get("execution")
    if not isinstance(execution, dict) or execution.get("mode") != "build-only" or execution.get("test_binary_execution") is not False:
        errors.append("execution-must-be-build-only")

    runtime = record.get("runtime")
    if not isinstance(runtime, dict) or set(runtime) != {"base", "head"} or runtime.get("base") != "NOT_RUN" or runtime.get("head") != "NOT_RUN":
        errors.append("runtime-must-be-exactly-not-run")

    if not isinstance(target, str) or not isinstance(source, str) or not isinstance(configuration, dict):
        return _result(record, errors)
    base = _entry(record, "base", target, source, configuration, errors)
    head = _entry(record, "head", target, source, configuration, errors)
    if isinstance(record.get("base"), dict) and isinstance(record.get("head"), dict):
        if record["base"].get("sha") == record["head"].get("sha"):
            errors.append("revisions-not-distinct")

    if base is not None and head is not None and isinstance(source, str):
        if base["source_file"] is not None and base["source_file"].exists():
            errors.append("base-added-test-source-present")
        if head["source_file"] is None or not head["source_file"].is_file():
            errors.append("head-added-test-source-missing")
        elif _valid_sha(source_sha256, SHA256_RE):
            try:
                if _sha256_file(head["source_file"]) != source_sha256:
                    errors.append("head-added-test-source-sha256-mismatch")
            except OSError:
                errors.append("head-added-test-source-unreadable")
        base_sources = base["sources"]
        head_sources = head["sources"]
        if base_sources is not None and head_sources is not None:
            base_names = set(base_sources)
            head_names = set(head_sources)
            if source in base_names:
                errors.append("base-manifest-includes-added-test")
            if source not in head_names:
                errors.append("head-manifest-excludes-added-test")
            if head_names - base_names != {source} or base_names - head_names:
                errors.append("manifest-source-delta-not-exactly-added-test")

            if source in head_sources:
                added_object = head_sources[source]["object_path"]
                if not added_object.is_file() or added_object.stat().st_size <= 0:
                    errors.append("head-added-test-object-missing")
                else:
                    head_build = record["head"].get("build", {})
                    declared_object_value = head_build.get("added_test_object")
                    if not isinstance(declared_object_value, str) or not declared_object_value:
                        errors.append("head-added-test-object-path-missing")
                    elif Path(declared_object_value).resolve() != added_object:
                        errors.append("head-added-test-object-path-mismatch")
                    declared_size = head_build.get("added_test_object_size")
                    if not _valid_nonbool_int(declared_size) or declared_size <= 0:
                        errors.append("head-added-test-object-size-invalid")
                    elif declared_size != added_object.stat().st_size:
                        errors.append("head-added-test-object-size-mismatch")
                    declared_digest = head_build.get("added_test_object_sha256")
                    if not _valid_sha(declared_digest, SHA256_RE):
                        errors.append("head-added-test-object-sha256-invalid")
                    else:
                        try:
                            if _sha256_file(added_object) != declared_digest:
                                errors.append("head-added-test-object-sha256-mismatch")
                        except OSError:
                            errors.append("head-added-test-object-unreadable")

    return _result(record, errors)


def main():
    parser = argparse.ArgumentParser(description="Verify paired artifacts for a PR-added test source")
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    record = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
    result = validate_evidence(record)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"verdict={result['verdict']}")
        print(f"build_only_status={result['build_only_status']}")
        for error in result["errors"]:
            print(f"  {error}")
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
