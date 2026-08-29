#!/usr/bin/env python3
"""Extract small, reviewable before/after repair evidence from local source files."""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.stdout.reconfigure(encoding="utf-8")


def compare_guard(filepath_before, filepath_after, pattern):
    rx = re.compile(pattern)
    def lines(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            return [{"line": i, "text": value.rstrip()} for i, value in enumerate(f, 1) if rx.search(value)]
    before = lines(filepath_before)
    after = lines(filepath_after)
    return {
        "before": before,
        "after": after,
        "changed": before != after,
        "files": [os.path.abspath(filepath_before), os.path.abspath(filepath_after)],
    }


def summarize_patch(filepath, guard_patterns=None):
    """Summarize local unified-diff additions without treating them as source proof."""
    guard_patterns = guard_patterns or []
    compiled = [re.compile(pattern) for pattern in guard_patterns]
    files = []
    added = []
    current_file = None
    with open(filepath, encoding="utf-8", errors="replace") as patch:
        for raw in patch:
            line = raw.rstrip("\n")
            if line.startswith("+++ b/"):
                current_file = line[6:]
                files.append(current_file)
            elif line.startswith("+") and not line.startswith("+++"):
                text = line[1:]
                added.append({
                    "file": current_file,
                    "text": text,
                    "guard_matches": [pattern.pattern for pattern in compiled if pattern.search(text)],
                })
    return {
        "patch": os.path.abspath(filepath),
        "files": files,
        "added_lines": added,
        "added_guard_lines": [line for line in added if line["guard_matches"]],
        "source_proof": False,
    }


def check_patch_addition_subset(container_patch, fragment_patch):
    """Report whether one local patch's additions are included by another patch."""
    container = summarize_patch(container_patch)
    fragment = summarize_patch(fragment_patch)
    container_keys = {(item["file"], item["text"]) for item in container["added_lines"]}
    missing = [
        item for item in fragment["added_lines"]
        if (item["file"], item["text"]) not in container_keys
    ]
    return {
        "container_patch": container["patch"],
        "fragment_patch": fragment["patch"],
        "fragment_added_lines": len(fragment["added_lines"]),
        "contained_added_lines": len(fragment["added_lines"]) - len(missing),
        "unmatched_added_lines": missing,
        "addition_subset": not missing,
        "source_proof": False,
    }


def check_patch_application(source_path, patch_path, target_path):
    """Check a local patch against one source file in an isolated temporary tree."""
    source_path = os.path.abspath(source_path)
    patch_path = os.path.abspath(patch_path)
    target_path = target_path.replace("\\", "/").lstrip("/")
    if not target_path or target_path.startswith("../") or "/../" in target_path:
        raise ValueError("target_path must be a relative repository path")
    if not os.path.isfile(source_path):
        raise FileNotFoundError(source_path)
    if not os.path.isfile(patch_path):
        raise FileNotFoundError(patch_path)

    with tempfile.TemporaryDirectory(prefix="cwe-repair-patch-") as root:
        target = os.path.join(root, *target_path.split("/"))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copyfile(source_path, target)
        init = subprocess.run(
            ["git", "-C", root, "init", "-q"], capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        if init.returncode:
            return {
                "source": source_path,
                "patch": patch_path,
                "target_path": target_path,
                "forward_applicable": False,
                "reverse_applicable": False,
                "error": init.stderr.strip(),
                "runtime_verdict": "REVIEW",
            }
        forward = subprocess.run(
            ["git", "-C", root, "apply", "--check", patch_path],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        reverse = subprocess.run(
            ["git", "-C", root, "apply", "--reverse", "--check", patch_path],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
    return {
        "source": source_path,
        "patch": patch_path,
        "target_path": target_path,
        "forward_applicable": forward.returncode == 0,
        "reverse_applicable": reverse.returncode == 0,
        "forward_error": forward.stderr.strip(),
        "reverse_error": reverse.stderr.strip(),
        "runtime_verdict": "REVIEW",
    }


def build_evidence_summary(static_evidence, verify_result=None):
    """Combine static guard evidence and runtime verification without overclaiming."""
    runtime_verdict = "REVIEW"
    if verify_result:
        runtime_verdict = verify_result.get("summary", {}).get("verdict", "REVIEW")
    complete = bool(static_evidence.get("changed")) and runtime_verdict == "PASS"
    return {
        "static_guard_changed": bool(static_evidence.get("changed")),
        "static_matches_before": len(static_evidence.get("before", [])),
        "static_matches_after": len(static_evidence.get("after", [])),
        "runtime_verdict": runtime_verdict,
        "complete": complete,
    }


def main():
    ap = argparse.ArgumentParser(description="Extract defensive before/after repair evidence")
    ap.add_argument("--before")
    ap.add_argument("--after")
    ap.add_argument("--pattern")
    ap.add_argument("--source", help="local source file for isolated patch applicability checks")
    ap.add_argument("--patch", help="local unified-diff patch")
    ap.add_argument("--target-path", help="patch-relative path where --source is placed")
    ap.add_argument("--container-patch", help="aggregate local patch for addition-subset checks")
    ap.add_argument("--fragment-patch", help="candidate sub-patch for addition-subset checks")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    patch_mode = any((args.source, args.patch, args.target_path))
    subset_mode = any((args.container_patch, args.fragment_patch))
    if patch_mode and subset_mode:
        ap.error("patch applicability and addition-subset options cannot be mixed")
    if subset_mode:
        if not all((args.container_patch, args.fragment_patch)):
            ap.error("--container-patch and --fragment-patch must be used together")
        result = check_patch_addition_subset(args.container_patch, args.fragment_patch)
        summary = (
            f"addition_subset={result['addition_subset']} "
            f"contained={result['contained_added_lines']}/{result['fragment_added_lines']}"
        )
    elif patch_mode:
        if not all((args.source, args.patch, args.target_path)):
            ap.error("--source, --patch, and --target-path must be used together")
        result = check_patch_application(args.source, args.patch, args.target_path)
        summary = (
            f"forward_applicable={result['forward_applicable']} "
            f"reverse_applicable={result['reverse_applicable']}"
        )
    else:
        if not all((args.before, args.after, args.pattern)):
            ap.error("--before, --after, and --pattern are required without patch options")
        result = compare_guard(args.before, args.after, args.pattern)
        summary = f"changed={result['changed']} before={len(result['before'])} after={len(result['after'])}"
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=1))
    else:
        print(summary)


if __name__ == "__main__":
    main()
