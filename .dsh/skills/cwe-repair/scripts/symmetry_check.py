#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
symmetry_check.py — 修复对称性检查器（针对 Codex 迭代问题的根因）

Codex 在 PR #6922 的 2 条 P1 批评：
  1) net.cpp:31 资源上限只加了 text 路径，bin 路径（load_param_bin）没应用
  2) net.cpp:1406 top_count==0 除零守卫不完整（text/bin 两处都要）
共同根因 = "修复不对称"：同一校验只打了一个入口，另一个入口（bin/text/兄弟函数）漏补。

本检查器：给定源码目录，检测"成对入口"中是否存在"一处有守卫、一处没有"的不对称。
用法:
  python symmetry_check.py <src_dir> --pair "load_param:load_param_bin" --guard "bottom_count|top_count"
  或自动模式: python symmetry_check.py <src_dir> --auto
"""
import argparse
import json
import os
import re
import sys

# 已知"成对入口"模式（本项目实证）：
# 格式: (入口1名, 入口2名, 守卫关键词[校验语句特征], 说明)
KNOWN_PAIRS = [
    ("load_param", "load_param_bin",
     r"(?:invalid\s+(?:bottom|top)_count|if\s*\(\s*(?:bottom|top)_count\s*[<>])",
     "ncnn 文本/二进制双解析器——Codex P1@net.cpp:31 批评点"),
    ("WriteMember", "WriteMemberNested",
     r"array_size_\s*[=!<>]|[<>=]+\s*[\w.]*array_size_|is_upper_bound",
     "AimRT json_convert 兄弟函数——AR-1 只修一个"),
    ("JointCmdCallback", "WriteMotorCmd",
     r"size\(\s*\)\s*[=!<>]|length|count",
     "AGIBOT 平行数组双回调"),
]


def find_functions(filepath):
    """提取文件中的函数定义行号（支持多行签名；排除调用语句）"""
    funcs = []
    with open(filepath, encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    for i, line in enumerate(lines, 1):
        stripped = line.lstrip()
        # 排除注释、预处理、调用语句、宏调用（SCAN_VALUE/READ_VALUE 等）
        if stripped.startswith(("//", "/*", "*", "#")) or re.search(r";|=\s*[\w:<>]+\(|\breturn\b|\bif\s*\(|\bfor\s*\(|\bwhile\s*\(|\.\w+\(|SCAN_VALUE|READ_VALUE|NCNN_LOGE|MNN_", stripped):
            continue
        # 定义特征：非缩进或轻缩进的行，含返回类型 + 函数名(
        indent = len(line) - len(stripped)
        if indent > 8:
            continue
        m = re.search(r"[\w:<>,*&\s]+?(?:[\w:]+::)?(\w+)\s*\(", stripped)
        if m and m.group(1) not in ("if", "for", "while", "switch", "return", "sizeof", "sequences", "layout"):
            funcs.append((m.group(1), i, stripped[:60]))
    return funcs


def check_symmetry(filepath, funcs, pair, guard_pat):
    """检查一对函数中是否一个含守卫、一个不含。返回 (不对称, 证据)"""
    name1, name2 = pair
    # pair 是函数名（精确匹配定义行：函数名后跟 "(" 且行内含函数定义特征）
    def match(name):
        return [f for f in funcs if f[0] == name]
    f1 = match(name1)
    f2 = match(name2)
    if not f1 or not f2:
        return None

    with open(filepath, encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    def has_guard(func_line, func_name):
        # 从函数定义到下一个函数定义之间搜守卫
        start = func_line
        end = len(lines)
        for other in funcs:
            if other[1] > start and other[0] != func_name:
                end = other[1]
                break
        body = "\n".join(lines[start:end])
        return bool(re.search(guard_pat, body)), body

    g1, body1 = has_guard(f1[0][1], f1[0][0])
    g2, body2 = has_guard(f2[0][1], f2[0][0])

    if g1 and not g2:
        return (f"⚠️ 不对称: {f1[0][0]} 有守卫, 但 {f2[0][0]} 没有 → 修复未覆盖兄弟路径",
                f1[0][1], f2[0][1])
    if g2 and not g1:
        return (f"⚠️ 不对称: {f2[0][0]} 有守卫, 但 {f1[0][0]} 没有",
                f2[0][1], f1[0][1])
    return None


def main():
    ap = argparse.ArgumentParser(description="修复对称性检查器")
    ap.add_argument("src_dir", help="源码目录")
    ap.add_argument("--auto", action="store_true", help="自动用 KNOWN_PAIRS")
    ap.add_argument("--file", help="指定文件（默认递归扫描）")
    ap.add_argument("--json", action="store_true", help="JSON 输出")
    args = ap.parse_args()

    files = []
    if args.file:
        # Accept the documented directory-relative form: <src_dir> --file net.cpp.
        selected = args.file
        if not os.path.isabs(selected) and not os.path.isfile(selected):
            selected = os.path.join(args.src_dir, selected)
        if not os.path.isfile(selected):
            ap.error(f"--file not found: {args.file}")
        files = [selected]
    else:
        for root, _, fnames in os.walk(args.src_dir):
            if any(s in root for s in ("build", ".git", "node_modules")):
                continue
            for fn in fnames:
                if fn.endswith((".cpp", ".cc", ".c", ".h", ".hpp")):
                    files.append(os.path.join(root, fn))

    findings = []
    for fp in files:
        funcs = find_functions(fp)
        for p1, p2, guard, desc in KNOWN_PAIRS:
            result = check_symmetry(fp, funcs, (p1, p2), guard)
            if result:
                msg, l1, l2 = result
                findings.append((fp, msg, l1, l2, desc))

    rows = [{"file": os.path.relpath(fp), "message": msg, "guard_line": l1,
             "unguarded_line": l2, "description": desc} for fp, msg, l1, l2, desc in findings]
    if args.json:
        print(json.dumps({"files_scanned": len(files), "findings": rows,
                          "symmetric": not bool(rows)}, ensure_ascii=False, indent=1))
    elif not findings:
        print("No repair asymmetry found")
    else:
        print(f"Found {len(findings)} repair asymmetry finding(s):")
        for row in rows:
            print(f"  {row['file']}: {row['message']}")
            print(f"    [reference] {row['description']}")


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    main()
