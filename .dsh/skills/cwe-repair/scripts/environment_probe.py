#!/usr/bin/env python3
"""Record local toolchain availability without installing or mutating dependencies."""
import argparse
import json
import shutil
from pathlib import Path

TOOLS = ("cppcheck", "semgrep", "codeql", "cmake", "ninja", "clang++", "g++")


def probe(source_root=None):
    tools = {name: shutil.which(name) for name in TOOLS}
    source = Path(source_root) if source_root else None
    source_snapshot = None
    if source is not None:
        source_snapshot = {
            "path": str(source),
            "exists": source.is_dir(),
            "cmake_files": len(list(source.rglob("CMakeLists.txt"))) if source.is_dir() else 0,
            "ros_package_manifests": len(list(source.rglob("package.xml"))) if source.is_dir() else 0,
        }
    return {
        "schema_version": 1,
        "probe_scope": "local availability only; no package installation, source mutation, or network activity",
        "tools": {name: {"available": path is not None, "path": path} for name, path in tools.items()},
        "source_snapshot": source_snapshot,
        "conclusion": {
            "external_baselines_runnable": all(tools[name] is not None for name in ("cppcheck", "semgrep", "codeql")),
            "native_cxx_slice_runnable": any(tools[name] is not None for name in ("clang++", "g++")) and (source_snapshot is None or source_snapshot["cmake_files"] > 0),
        },
        "universal_claim": False,
        "formal_proof": False,
    }


def main():
    parser = argparse.ArgumentParser(description="Probe local cwe-repair baseline/build availability")
    parser.add_argument("--source-root")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = probe(args.source_root)
    if args.out:
        args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else json.dumps(result["conclusion"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
