#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Contract gates for defensive, semantics-aware repair planning.

This module does not claim formal verification. It checks local proof obligations
that must hold before a deterministic patch can be proposed as an automatic
candidate. Missing obligations produce REVIEW/REFUSE instead of a patch.
"""
import re
from pathlib import Path


PLACEHOLDER_VALUES = {
    "",
    "/* TODO: 释放/清理已分配资源 */",
    "/* TODO: 设置安全默认值 */",
}


def _read_lines(path):
    return Path(path).read_text(encoding="utf-8", errors="replace").splitlines()


def _context(lines, lineno, before=48, after=20):
    start = max(0, lineno - 1 - before)
    end = min(len(lines), lineno + after)
    return "\n".join(lines[start:end]), "\n".join(lines[start:lineno - 1])


def _function_context(lines, lineno):
    """Return a conservative local function window, or an empty window."""
    signature = re.compile(
        r"^\s*(?:(?:static|inline|virtual|const|constexpr)\s+)*"
        r"[\w:<>,*&\s]+\s+[\w:~]+\s*\([^;]*\)\s*(?:const\s*)?\{?\s*$"
    )
    start = None
    for index in range(lineno - 1, max(-1, lineno - 240), -1):
        candidate = lines[index]
        if re.match(r"^\s*(?:if|for|while|switch|SCAN_VALUE|READ_VALUE)\b", candidate):
            continue
        if '"' in candidate or "=" in candidate or ";" in candidate:
            continue
        if signature.search(candidate):
            start = index
            break
    if start is None:
        return ""
    depth = 0
    seen_open = False
    for index in range(start, min(len(lines), lineno + 240)):
        depth += lines[index].count("{") - lines[index].count("}")
        seen_open = seen_open or "{" in lines[index]
        if seen_open and depth <= 0 and index >= lineno - 1:
            return "\n".join(lines[start:index + 1])
    return "\n".join(lines[start:min(len(lines), lineno + 120)])


def _has_bounds(context, index_name, size_name):
    idx = re.escape(index_name)
    size = re.escape(size_name)
    lower = re.search(rf"\b{idx}\s*(?:<\s*0|<=\s*-?1)", context)
    upper = re.search(rf"\b{idx}\s*>=\s*{size}", context)
    return bool(lower and upper), bool(lower), bool(upper)


def _return_obligation(function_text, target_context):
    if re.search(r"\breturn\s+-1\s*;", function_text) or re.search(
        r"\b(?:int|bool|size_t)\s+\w+\s*\([^;]*\)", function_text
    ):
        return {"status": "satisfied", "evidence": "integer-like return/error convention observed"}
    if re.search(r"\breturn\s+(?:0|false|true)\s*;", function_text):
        return {"status": "review", "evidence": "return convention exists but failure value is not proven"}
    return {"status": "missing", "evidence": "no compatible explicit error return observed"}


def _obligation(name, status, evidence, required=True):
    return {"name": name, "status": status, "evidence": evidence, "required": required}


def analyze_contract(path, lineno, cwe, params=None):
    """Analyze local proof obligations for a deterministic repair candidate."""
    params = params or {}
    try:
        lines = _read_lines(path)
    except OSError as exc:
        return {
            "status": "REFUSE",
            "reason": "source-unreadable",
            "path": str(path),
            "line": lineno,
            "cwe": cwe,
            "obligations": [_obligation("source-readable", "missing", str(exc))],
        }
    if lineno < 1 or lineno > len(lines):
        return {
            "status": "REFUSE",
            "reason": "target-line-out-of-range",
            "path": str(path),
            "line": lineno,
            "cwe": cwe,
            "obligations": [_obligation("target-line", "missing", f"valid range is 1..{len(lines)}")],
        }

    target = lines[lineno - 1]
    context, before = _context(lines, lineno)
    function_text = _function_context(lines, lineno) or context
    scope_text = function_text or context
    obligations = [_obligation("target-line", "satisfied", target.strip()[:240])]
    status = "AUTO_CANDIDATE"
    reason = "all local contract obligations satisfied"

    if cwe in (125, 787):
        index_name = params.get("idx", "idx")
        size_name = params.get("size", "size")
        if not index_name or not size_name:
            obligations.append(_obligation("index-and-capacity-identifiers", "missing", "idx and size are required"))
            return _result(path, lineno, cwe, target, obligations, "REFUSE", "missing-repair-identifiers")
        if not re.search(rf"\b{re.escape(index_name)}\b", target):
            obligations.append(_obligation("target-uses-index", "missing", f"{index_name} is absent from target line"))
            return _result(path, lineno, cwe, target, obligations, "REFUSE", "target-does-not-use-index")
        guarded, lower, upper = _has_bounds(before, index_name, size_name)
        if guarded:
            obligations.append(_obligation("bounds-before-access", "satisfied", "lower and upper guards precede access"))
            return _result(path, lineno, cwe, target, obligations, "NO_CHANGE", "already-guarded")
        obligations.append(_obligation("lower-bound-before-access", "satisfied" if lower else "to-add", f"{index_name} < 0"))
        obligations.append(_obligation("upper-bound-before-access", "satisfied" if upper else "to-add", f"{index_name} >= {size_name}"))
        if not re.search(rf"\b{re.escape(size_name)}\b", scope_text):
            obligations.append(_obligation("capacity-symbol-in-scope", "missing", f"{size_name} is not visible in function scope"))
        else:
            obligations.append(_obligation("capacity-symbol-in-scope", "satisfied", size_name))
        return_obligation = _return_obligation(function_text, context)
        obligations.append(_obligation("explicit-error-return", return_obligation["status"], return_obligation["evidence"]))
        cleanup_required = bool(re.search(r"\bLayer\s*\*\s*layer\b|\bd->layers\b|\bclear\s*\(\s*\)", function_text))
        cleanup = params.get("cleanup", "")
        if cleanup_required:
            cleanup_ok = cleanup.strip() not in PLACEHOLDER_VALUES
            obligations.append(_obligation("partial-state-cleanup", "satisfied" if cleanup_ok else "missing", cleanup or "cleanup argument required for parser state"))
        else:
            obligations.append(_obligation("partial-state-cleanup", "not-required", "no parser-owned partial state detected", required=False))
        if not re.search(rf"\b{re.escape(size_name)}\b", scope_text) or return_obligation["status"] != "satisfied":
            status = "REVIEW"
            reason = "one or more local safety obligations are unproven"
        if cleanup_required and cleanup.strip() in PLACEHOLDER_VALUES:
            status = "REVIEW"
            reason = "partial parser state requires explicit cleanup"
    elif cwe == 369:
        denominator = params.get("den", "den")
        if not denominator or not re.search(rf"[/％%]\s*{re.escape(denominator)}\b", target):
            obligations.append(_obligation("target-uses-denominator", "missing", denominator))
            return _result(path, lineno, cwe, target, obligations, "REFUSE", "target-does-not-use-denominator")
        guarded = bool(re.search(rf"\b{re.escape(denominator)}\s*(?:!=|>)\s*0", before))
        obligations.append(_obligation("nonzero-denominator-before-use", "satisfied" if guarded else "missing", denominator))
        fallback = params.get("fallback", "")
        obligations.append(_obligation("defined-zero-contract", "satisfied" if fallback.strip() not in PLACEHOLDER_VALUES else "missing", fallback or "fallback/explicit rejection required"))
        if not guarded or fallback.strip() in PLACEHOLDER_VALUES:
            status, reason = "REVIEW", "zero-denominator behavior is not fully specified"
    elif cwe == 190:
        count = params.get("count", "count")
        maximum = params.get("max", "MAX_COUNT")
        has_upper = bool(re.search(rf"\b{re.escape(count)}\s*<=?\s*{re.escape(maximum)}\b|\b{re.escape(count)}\s*>\s*{re.escape(maximum)}\b", before))
        obligations.append(_obligation("bounded-count-before-use", "satisfied" if has_upper else "missing", f"{count} and {maximum}"))
        if not has_upper:
            status, reason = "REVIEW", "count upper bound is not proven before use"
    else:
        obligations.append(_obligation("supported-semantic-contract", "missing", f"CWE {cwe} has no contract gate"))
        status, reason = "REVIEW", "unsupported contract requires manual semantic review"

    return _result(path, lineno, cwe, target, obligations, status, reason)


def _result(path, lineno, cwe, target, obligations, status, reason):
    return {
        "status": status,
        "reason": reason,
        "path": str(path),
        "line": lineno,
        "cwe": cwe,
        "target": target.strip(),
        "obligations": obligations,
        "proof_scope": "local-contract-obligations-only",
        "formal_proof": False,
    }
