#!/usr/bin/env python3
"""Portable CLI adapter for cwe-repair core scripts.

This command is independent of DSH. The DSH skill is one orchestration adapter;
CI jobs and local terminals can invoke the same subcommands through this file.
"""
import argparse
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
COMMANDS = {
    "detect": "cwe_detect.py",
    "reach": "cwe_reach.py",
    "symmetry": "symmetry_check.py",
    "repair": "cwe_repair.py",
    "plan": "repair_plan.py",
    "verify": "cwe_verify.py",
    "contract": "asset_semantic_contract.py",
    "profile": "embodied_profile_validate.py",
    "callback-review": "embodied_callback_review.py",
    "environment-probe": "environment_probe.py",
    "slice-plan": "source_slice_plan_validate.py",
    "evaluate": "evaluation_summary.py",
    "readiness": "pr_case_readiness.py",
    "release-audit": "release_audit.py",
}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Portable cwe-repair command-line interface")
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("args", nargs=argparse.REMAINDER, help="arguments passed unchanged to the selected command")
    parsed = parser.parse_args(argv)
    target = SCRIPT_DIR / COMMANDS[parsed.command]
    return subprocess.run([sys.executable, str(target), *parsed.args], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
