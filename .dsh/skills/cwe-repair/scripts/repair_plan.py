#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate an auditable, contract-gated defensive repair plan.

A plan is not an automatic source rewrite. Only AUTO_CANDIDATE plans contain a
patch candidate; REVIEW and REFUSE plans expose the missing proof obligations.
"""
import argparse
import importlib.util
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPT_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description="Create a contract-gated defensive repair plan")
    parser.add_argument("--file", required=True)
    parser.add_argument("--line", required=True, type=int)
    parser.add_argument("--cwe", required=True, type=int)
    parser.add_argument("--idx", default="idx")
    parser.add_argument("--size", default="size")
    parser.add_argument("--count", default="count")
    parser.add_argument("--max", dest="maximum", default="MAX_COUNT")
    parser.add_argument("--den", default="den")
    parser.add_argument("--fallback", default="")
    parser.add_argument("--cleanup", default="")
    parser.add_argument("--log", default="generic", choices=["ncnn", "aimrt", "mindspore", "generic"])
    parser.add_argument("--fail-ret", default="-1")
    parser.add_argument("--out", help="write a candidate patch only for AUTO_CANDIDATE")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    contract = load("repair_contract")
    repair = load("cwe_repair")
    params = {
        "cwe": args.cwe,
        "idx": args.idx,
        "size": args.size,
        "count": args.count,
        "max": args.maximum,
        "den": args.den,
        "fallback": args.fallback,
        "cleanup": args.cleanup,
        "log": args.log,
        "fail_ret": args.fail_ret,
    }
    analysis = contract.analyze_contract(args.file, args.line, args.cwe, params)
    plan = {
        "schema_version": 1,
        "tool": "cwe-repair",
        "mode": "defensive-contract-gated",
        "analysis": analysis,
        "apply_allowed": False,
        "patch_status": "not-generated",
        "patch": None,
    }
    if analysis["status"] == "AUTO_CANDIDATE":
        patch, ok = repair.generate_patch(args.file, args.line, args.cwe, params)
        if ok:
            plan["patch"] = patch
            plan["patch_status"] = "candidate"
            plan["apply_allowed"] = False
            if args.out:
                Path(args.out).write_text(patch, encoding="utf-8")
                plan["patch_file"] = str(args.out)
        else:
            plan["patch_status"] = "generation-failed"
            plan["analysis"]["status"] = "REVIEW"
            plan["analysis"]["reason"] = "contract-satisfied-but-patch-generation-failed"
    if not args.json:
        print(f"status={plan['analysis']['status']}")
        print(f"reason={plan['analysis']['reason']}")
        for obligation in plan["analysis"]["obligations"]:
            print(f"  [{obligation['status']}] {obligation['name']}: {obligation['evidence']}")
        print(f"patch_status={plan['patch_status']} apply_allowed={plan['apply_allowed']}")
    else:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
    if plan["analysis"]["status"] == "REFUSE":
        return 2
    if plan["analysis"]["status"] == "REVIEW":
        return 1
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
