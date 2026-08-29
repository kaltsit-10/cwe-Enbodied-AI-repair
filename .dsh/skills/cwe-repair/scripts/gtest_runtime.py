#!/usr/bin/env python3
"""Run a bounded allowlisted GoogleTest plan against a local pinned binary.

This runner is for defensive runtime evidence. It never shells out, accepts no
model/input files, and only executes filters explicitly listed in the JSON plan.
A PASS proves the declared GoogleTest cases passed; it is not a formal proof.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

RUN_RE = re.compile(r"\[==========\]\s+Running\s+(\d+)\s+tests?\b")
PASS_RE = re.compile(r"\[\s+PASSED\s+\]\s+(\d+)\s+tests?\b")
FAIL_RE = re.compile(r"\[\s+FAILED\s+\]\s+(\d+)\s+tests?\b")
SKIP_RE = re.compile(r"\[\s+SKIPPED\s+\]\s+(\d+)\s+tests?\b")
SAFE_FILTER_RE = re.compile(r"^RNNTest\.[A-Za-z0-9_*:?\-]+$")


def parse_gtest_summary(output):
    """Parse the stable GTest summary lines without trusting exit code alone."""
    def read_count(pattern):
        matches = pattern.findall(output)
        return int(matches[-1]) if matches else None

    return {
        "tests_run": read_count(RUN_RE),
        "tests_passed": read_count(PASS_RE),
        "tests_failed": read_count(FAIL_RE) or 0,
        "tests_skipped": read_count(SKIP_RE) or 0,
    }


def validate_plan(plan):
    """Return schema/safety errors before any target process is started."""
    errors = []
    if plan.get("execution_scope") != "local-pinned-binary-only":
        errors.append("execution-scope-invalid")
    safety = plan.get("safety")
    if not isinstance(safety, dict):
        errors.append("safety-missing")
    else:
        for name in ("no_external_inputs", "no_network_target_execution", "no_oom_or_huge_allocation", "no_exploit_chain"):
            if safety.get(name) is not True:
                errors.append(f"safety-{name}-required")
    binary = plan.get("binary")
    if not isinstance(binary, str) or not binary:
        errors.append("binary-missing")
    cases = plan.get("cases")
    if not isinstance(cases, list) or not cases:
        errors.append("cases-missing")
        return errors
    ids = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            errors.append(f"case-{index}-invalid")
            continue
        case_id = case.get("id")
        filt = case.get("filter")
        expected = case.get("expected_test_count")
        if not isinstance(case_id, str) or not case_id or case_id in ids:
            errors.append(f"case-{index}-id-invalid")
        ids.add(case_id)
        if not isinstance(filt, str) or not SAFE_FILTER_RE.fullmatch(filt):
            errors.append(f"case-{index}-filter-not-allowlisted")
        if not isinstance(expected, int) or expected <= 0:
            errors.append(f"case-{index}-expected-count-invalid")
    return errors


def run_case(binary, case, timeout):
    """Run one GTest filter with no shell and return a structured outcome."""
    case_id = case["id"]
    filt = case["filter"]
    expected = case["expected_test_count"]
    metadata = {key: case[key] for key in ("role", "contract_paths") if key in case}
    command = [binary, f"--gtest_filter={filt}", "--gtest_color=no"]
    env = os.environ.copy()
    env["GTEST_COLOR"] = "no"
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
            env=env,
        )
        output = (completed.stdout or b"").decode("utf-8", errors="replace")
        summary = parse_gtest_summary(output)
        passed = (
            completed.returncode == 0
            and summary["tests_run"] == expected
            and summary["tests_passed"] == expected
            and summary["tests_failed"] == 0
            and summary["tests_skipped"] == 0
        )
        return {
            "id": case_id,
            "filter": filt,
            "expected_test_count": expected,
            **metadata,
            "exit_code": completed.returncode,
            **summary,
            "status": "PASS" if passed else "REVIEW",
            "output_tail": output[-1000:],
        }
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or b"").decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else str(exc.stdout or "")
        return {
            "id": case_id,
            "filter": filt,
            "expected_test_count": expected,
            **metadata,
            "exit_code": "TIMEOUT",
            "tests_run": None,
            "tests_passed": None,
            "tests_failed": None,
            "tests_skipped": None,
            "status": "REVIEW",
            "output_tail": output[-1000:],
        }
    except OSError as exc:
        return {
            "id": case_id,
            "filter": filt,
            "expected_test_count": expected,
            **metadata,
            "exit_code": f"OSERROR:{exc.__class__.__name__}",
            "tests_run": None,
            "tests_passed": None,
            "tests_failed": None,
            "tests_skipped": None,
            "status": "REVIEW",
            "output_tail": str(exc)[-1000:],
        }


def execute_plan(plan):
    """Execute a validated local plan and return runtime evidence."""
    errors = validate_plan(plan)
    if errors:
        return {
            "schema_version": 1,
            "case_id": plan.get("case_id"),
            "status": "REVIEW",
            "errors": errors,
            "cases": [],
            "summary": {"passed": "0/0", "verdict": "REVIEW"},
            "formal_proof": False,
        }

    binary = plan["binary"]
    if not Path(binary).is_file():
        return {
            "schema_version": 1,
            "case_id": plan.get("case_id"),
            "status": "REVIEW",
            "errors": ["binary-missing"],
            "cases": [],
            "summary": {"passed": "0/0", "verdict": "REVIEW"},
            "formal_proof": False,
        }

    timeout = plan.get("timeout_seconds", 120)
    if not isinstance(timeout, int) or timeout <= 0 or timeout > 600:
        return {
            "schema_version": 1,
            "case_id": plan.get("case_id"),
            "status": "REVIEW",
            "errors": ["timeout-invalid"],
            "cases": [],
            "summary": {"passed": "0/0", "verdict": "REVIEW"},
            "formal_proof": False,
        }

    results = [run_case(binary, case, timeout) for case in plan["cases"]]
    passed = sum(item["status"] == "PASS" for item in results)
    total = len(results)
    verdict = "PASS" if total and passed == total else "REVIEW"
    return {
        "schema_version": 1,
        "case_id": plan.get("case_id"),
        "official_source": plan.get("official_source"),
        "source_revision": plan.get("source_revision"),
        "target": plan.get("target"),
        "binary": binary,
        "binary_sha256": plan.get("binary_sha256"),
        "runtime_scope": plan.get("runtime_scope"),
        "execution_scope": plan["execution_scope"],
        "safety": plan["safety"],
        "status": verdict,
        "errors": [],
        "cases": results,
        "summary": {"passed": f"{passed}/{total}", "verdict": verdict},
        "formal_proof": False,
        "proof_scope": "declared local GoogleTest filters only",
    }


def main():
    parser = argparse.ArgumentParser(description="Run a bounded local GoogleTest evidence plan")
    parser.add_argument("--plan", required=True)
    parser.add_argument("--out", help="write JSON result")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    result = execute_plan(plan)
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    if args.json or not args.out:
        print(rendered)
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
