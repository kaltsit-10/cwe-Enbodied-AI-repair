#!/usr/bin/env python3
"""Validate a narrowly scoped checked-addition source contract.

This is a source-ordering validator for a paired repair. It confirms that the
head adds an explicit representability check before a named offset-plus-size
expression and its update. It does not execute code, prove caller constraints,
or infer behavior for other providers/configurations.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


def _line(text, index):
    return text.count("\n", 0, index) + 1


def _sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _contract_patterns(offset, size):
    offset_pattern = re.escape(offset)
    size_pattern = re.escape(size)
    addition = re.compile(rf"\b{offset_pattern}\s*\+\s*{size_pattern}\b")
    update = re.compile(rf"\b{offset_pattern}\s*\+=\s*{size_pattern}\b")
    guard = re.compile(
        rf"\bif\s*\([^;\n]*?\b{offset_pattern}\b(?:\s*\))*\s*>\s*SIZE_MAX\s*-\s*{size_pattern}\b[^;\n]*?\)"
    )
    return addition, update, guard


def validate_pair(base_text, head_text, offset, size):
    """Return a conservative source-only before/after contract verdict."""
    addition, update, guard = _contract_patterns(offset, size)
    base_additions = list(addition.finditer(base_text))
    base_updates = list(update.finditer(base_text))
    base_guards = list(guard.finditer(base_text))
    head_additions = list(addition.finditer(head_text))
    head_updates = list(update.finditer(head_text))
    head_guards = list(guard.finditer(head_text))
    errors = []

    if not base_additions:
        errors.append("base-addition-missing")
    if not base_updates:
        errors.append("base-update-missing")
    if base_guards:
        errors.append("base-already-has-representability-guard")
    if not head_additions:
        errors.append("head-addition-missing")
    if not head_updates:
        errors.append("head-update-missing")
    if not head_guards:
        errors.append("head-representability-guard-missing")

    guard_lines = [_line(head_text, match.start()) for match in head_guards]
    guarded = False
    if head_guards and head_additions and head_updates:
        guard_match = head_guards[0]
        first_operation = min(match.start() for match in [*head_additions, *head_updates])
        return_match = re.search(r"\breturn\s*;", head_text[guard_match.end():first_operation])
        guarded = guard_match.start() < first_operation and return_match is not None
        if not guarded:
            errors.append("head-guard-not-before-returning-operation")

    return {
        "schema_version": 1,
        "verdict": "STATIC_CONTRACT_DELTA_VERIFIED" if not errors else "REVIEW",
        "valid": not errors,
        "checks": {
            "base_addition_lines": [_line(base_text, match.start()) for match in base_additions],
            "base_update_lines": [_line(base_text, match.start()) for match in base_updates],
            "base_guard_lines": [_line(base_text, match.start()) for match in base_guards],
            "head_addition_lines": [_line(head_text, match.start()) for match in head_additions],
            "head_update_lines": [_line(head_text, match.start()) for match in head_updates],
            "head_guard_lines": guard_lines,
            "head_guard_returns_before_operation": guarded,
        },
        "contract": {
            "offset": offset,
            "size": size,
            "guard": f"{offset} > SIZE_MAX - {size}",
            "scope": "paired source text and lexical ordering only",
        },
        "errors": errors,
        "formal_proof": False,
        "limitations": [
            "Does not establish the origin, range, or concurrency semantics of the offset or size.",
            "Does not execute the target or test other cache-writing entry points.",
            "Does not establish provider, hardware, allocator, or caller behavior.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="Validate a paired checked-addition source contract")
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--offset", required=True)
    parser.add_argument("--size", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    base_path = Path(args.base)
    head_path = Path(args.head)
    base_text = base_path.read_text(encoding="utf-8")
    head_text = head_path.read_text(encoding="utf-8")
    result = validate_pair(base_text, head_text, args.offset, args.size)
    result["base"] = {"path": str(base_path), "sha256": _sha256(base_text)}
    result["head"] = {"path": str(head_path), "sha256": _sha256(head_text)}
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
