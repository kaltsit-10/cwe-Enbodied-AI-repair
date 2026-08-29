#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cwe_repair.py — 为已确认的 CWE 缺陷生成修复补丁（防御侧，修复阶段）

核心思想：本项目实证的 4 类漏洞，修复模式高度统一（"补一行检查"）：
  CWE-125/787 越界   → 索引前补 `if (idx < 0 || idx >= size) { 报错; return; }`
  CWE-190 溢出      → 分配/乘法前补上限与符号校验
  CWE-369 除零      → 分母前补 `if (den == 0) { 报错; return; }`
  CWE-476 空指针    → 使用前补判空

用法:
  python cwe_repair.py --file <源文件> --line <行号> --cwe 787 \
      --idx <索引变量> --size <容量变量或表达式> [--dry-run] [--out <补丁文件>]

生成: unified diff 补丁（同项目 PR 材料格式），供人工审阅后套用。
"""
import argparse
import os
import re
import subprocess
import sys

# 鲁棒性修复模板（v2）：不止补单行检查，而是防御性编程——
# 1) 校验 + 显式错误路径（清理/释放后返回，防泄漏）
# 2) 合法边界内的默认值回退（不因畸形输入直接崩溃整个模块）
# 3) 语义明确的错误日志（便于诊断）
# 生成后必须人工审阅：返回值/错误路径与项目惯例对齐。

REPAIR_SNIPPETS = {
    # CWE-125/787: 索引边界校验 + 错误路径清理（防泄漏/防悬垂）
    125: """if ({idx} < 0 || {idx} >= {size}) {{
    {log}("invalid index {idx} %d (size=%zu)", {idx}, (size_t){size});
    return {fail_ret};
}}""",
    787: """if ({idx} < 0 || {idx} >= {size}) {{
    {log}("invalid index {idx} %d (size=%zu)", {idx}, (size_t){size});
    return {fail_ret};
}}""",
    # CWE-190: 容量/计数校验 + 明确上限常量（防二次利用）
    190: """if ({count} <= 0 || {count} > {max}) {{
    {log}("invalid count {count} %d (max={max})", {count});
    return {fail_ret};
}}""",
    # CWE-190 截断变体: size_t→int 截断（MNN FileLoader::merge 同款）
    "190_trunc": """// [cwe-repair] size_t -> int truncation: verify range before narrowing
if ({src} > static_cast<size_t>(std::numeric_limits<int>::max())) {{
    {log}("value {src} %zu exceeds int range, refusing", (size_t){src});
    return {fail_ret};
}}
int {dst} = static_cast<int>({src});""",
    # CWE-369: 除零检查 + 防御性回退（不崩溃；由调用方决定是否拒绝）
    369: """if ({den} == 0) {{
    {log}("division by zero: {den}, falling back");
    {fallback}
}}""",
    # CWE-476: 判空 + 错误路径清理（分配失败不继续）
    476: """if (!{ptr}) {{
    {log}("{ptr} is null after {fn}");
    {cleanup};
    return {fail_ret};
}}""",
    # CWE-248: .at() 未捕获 → find() + 检查 + 错误路径清理（AGIBOT X1-8 同款）
    248: """auto it = {map}.find({key});
if (it == {map}.end()) {{
    {log}("key not found: {key}");
    {cleanup};
    return {fail_ret};
}}
{idx} = it->second;""",
}

LOG_CALLS = {
    "ncnn": "NCNN_LOGE",
    "aimrt": "AIMRT_WARN",
    "mindspore": "MS_LOG(ERROR)",
    "generic": "// TODO: add error log",
}


def patch_path(filepath):
    """Return a stable patch path across Windows drives and WSL UNC mounts."""
    try:
        return os.path.relpath(filepath)
    except ValueError:
        normalized = str(filepath).replace("\\\\", "/").replace("\\", "/")
        match = re.search(r"/(src|include|tests|examples)/(.+)$", normalized)
        if match:
            return f"{match.group(1)}/{match.group(2)}"
        return os.path.basename(normalized)


def generate_patch(filepath, lineno, cwe, params):
    """生成 unified diff。返回 (patch_text, 是否成功)"""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        return f"ERROR: 无法读取 {filepath}: {e}", False

    if lineno < 1 or lineno > len(lines):
        return f"ERROR: 行号 {lineno} 超出文件范围 (1-{len(lines)})", False

    # 目标行（插入检查的位置 = 缺陷行前）
    target = lines[lineno - 1]

    # 组装代码片段（log = 完整的日志调用前缀，如 "NCNN_LOGE" 或 "AIMRT_WARN"）
    log = LOG_CALLS.get(params.get("log", "generic"), "// TODO: add error log")
    fail_ret = params.get("fail_ret", "-1")
    fallback = params.get("fallback", "/* TODO: 设置安全默认值 */")
    cleanup = params.get("cleanup", "/* TODO: 释放/清理已分配资源 */")
    if params.get("cwe") in (125, 787):
        idx = params.get("idx", "idx")
        size = params.get("size", "size")
        cleanup = params.get("cleanup", "").strip()
        if cleanup and cleanup != "/* TODO: 释放/清理已分配资源 */":
            snippet = f'''if ({idx} < 0 || {idx} >= {size}) {{
    {log}("invalid index {idx} %d (size=%zu)", {idx}, (size_t){size});
    {cleanup}
    return {fail_ret};
}}'''
        else:
            snippet = REPAIR_SNIPPETS[cwe].format(
                idx=idx,
                size=size,
                log=log, fail_ret=fail_ret,
            )
    elif cwe == 190 and params.get("trunc"):
        snippet = REPAIR_SNIPPETS["190_trunc"].format(
            src=params.get("src", "src"), dst=params.get("dst", "dst"),
            log=log, fail_ret=fail_ret,
        )
    elif cwe == 190:
        snippet = REPAIR_SNIPPETS[190].format(
            count=params.get("count", "count"), max=params.get("max", "MAX_COUNT"),
            log=log, fail_ret=fail_ret,
        )
    elif cwe == 369:
        snippet = REPAIR_SNIPPETS[369].format(
            den=params.get("den", "den"), log=log, fallback=fallback,
        )
    elif cwe == 476:
        snippet = REPAIR_SNIPPETS[476].format(
            ptr=params.get("ptr", "ptr"), fn=params.get("fn", "fn"),
            log=log, cleanup=cleanup, fail_ret=fail_ret,
        )
    elif cwe == 248:
        snippet = REPAIR_SNIPPETS[248].format(
            map=params.get("map", "map"), key=params.get("key", "key"),
            idx=params.get("idx", "idx"), log=log,
            cleanup=cleanup, fail_ret=fail_ret,
        )
    else:
        return f"ERROR: 不支持的 CWE {cwe}", False

    # 构造 unified diff：检查必须位于危险目标行之前。
    indent = target[:len(target) - len(target.lstrip())]
    inserted_lines = [indent + l for l in snippet.splitlines()]

    patch = [
        f"--- a/{patch_path(filepath)}",
        f"+++ b/{patch_path(filepath)}",
        f"@@ -{lineno},{1} +{lineno},{len(inserted_lines) + 1} @@",
    ]
    for line in inserted_lines:
        patch.append("+" + line)
    patch.append(" " + target.rstrip("\n"))
    return "\n".join(patch) + "\n", True


def main():
    ap = argparse.ArgumentParser(description="CWE 修复补丁生成器")
    ap.add_argument("--file", required=True, help="源文件路径")
    ap.add_argument("--line", type=int, required=True, help="缺陷行号")
    ap.add_argument("--cwe", type=int, required=True, choices=[125, 787, 190, 369, 476, 248])
    ap.add_argument("--idx", default="idx", help="索引变量名（125/787/248）")
    ap.add_argument("--size", default="size", help="容量变量/表达式（125/787）")
    ap.add_argument("--map", default="map", help="容器名（248）")
    ap.add_argument("--key", default="key", help="键名（248）")
    ap.add_argument("--count", default="count", help="计数变量（190）")
    ap.add_argument("--max", default="MAX_COUNT", help="上限（190）")
    ap.add_argument("--trunc", action="store_true", help="截断修复模式（190：size_t→int 范围校验）")
    ap.add_argument("--src", default="src", help="截断源变量（190-trunc）")
    ap.add_argument("--dst", default="dst", help="截断目标变量（190-trunc）")
    ap.add_argument("--den", default="den", help="分母变量（369）")
    ap.add_argument("--ptr", default="ptr", help="指针变量（476）")
    ap.add_argument("--fn", default="fn", help="分配函数名（476）")
    ap.add_argument("--fail-ret", default="-1", help="错误返回码（默认 -1）")
    ap.add_argument("--fallback", default="/* TODO: 设置安全默认值 */", help="除零回退代码（369）")
    ap.add_argument("--cleanup", default="/* TODO: 释放/清理已分配资源 */", help="错误路径清理代码")
    ap.add_argument("--log", default="generic", choices=["ncnn", "aimrt", "mindspore", "generic"])
    ap.add_argument("--out", help="补丁输出文件（默认打印到 stdout）")
    args = ap.parse_args()

    params = {
        "cwe": args.cwe, "idx": args.idx, "size": args.size, "count": args.count,
        "max": args.max, "den": args.den, "ptr": args.ptr, "fn": args.fn, "log": args.log,
        "fail_ret": args.fail_ret, "fallback": args.fallback, "cleanup": args.cleanup,
        "trunc": args.trunc, "src": args.src, "dst": args.dst,
    }
    patch, ok = generate_patch(args.file, args.line, args.cwe, params)
    if not ok:
        print(patch, file=sys.stderr)
        sys.exit(1)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(patch)
        print(f"补丁已写入: {args.out}")
        print("人工审阅后使用: git apply <补丁> 或 patch -p1 < <补丁>")
    else:
        print(patch)


if __name__ == "__main__":
    main()
