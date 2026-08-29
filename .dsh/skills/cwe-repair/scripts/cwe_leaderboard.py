#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cwe_leaderboard.py — 检测基准化（借鉴 RepairBench 思路，2026-08-22）

对 34-finding 数据集（embodied-ai-cwe-dataset.json）运行当前 detect，
输出"每个已知漏洞是否被命中"的基准表——用于：
  1) 防回归：工具迭代后确认已知漏洞仍被检出（回归测试）
  2) 可对比基线：评估工具对不同组件/不同 CWE 的检出能力

用法:
  python cwe_leaderboard.py [--json]

输出: 表格（组件 | finding | 位置 | detect 命中? | CWE | 模式）
      + 汇总（总检出率、按组件、按 CWE）
"""
import argparse
import json
import os
import re
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE = os.environ.get("DSH_WORKSPACE", os.path.abspath(os.path.join(SCRIPT_DIR, "..", "..", "..", "..")))
DSET = os.path.join(BASE, "研究文档", "embodied-ai-cwe-dataset.json")
DETECT = os.path.join(SCRIPT_DIR, "cwe_detect.py")

# 组件 → 本地源码路径（用于 detect 定位）
COMPONENT_SRC = {
    "Tencent ncnn": os.path.join(BASE, "TOOLTEST_NCNN"),
    "Huawei MindSpore": None,  # 无本地源码
    "AgiBot agibot_x1_infer": os.path.join(BASE, "AGIBOT", "repos", "agibot_x1_infer_src", "src"),
    "AimRT (AgiBot)": os.path.join(BASE, "AGIBOT", "repos", "aimrt_src"),
    "Unitree xr_teleoperate": os.path.join(BASE, "xr-teleop-work", "kaltsit-10-xr_teleoperate-845b25a"),
}


def run_detect(target, cwes, ext=None):
    """对目标跑 detect，返回命中列表"""
    if not target or not os.path.exists(target):
        return None
    cmd = [sys.executable, "-X", "utf8", DETECT, target, "--cwe", cwes, "--json"]
    if ext:
        cmd += ["--ext", ext]
    r = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
    try:
        return json.loads(r.stdout).get("findings", [])
    except Exception:
        return []


def location_match(finding, loc):
    """判断 finding 是否命中数据集声明的漏洞位置（行号/证据近似匹配）"""
    evidence = finding.get("evidence", "")
    # 从数据集 loc 提取函数名/关键变量（如 "net.cpp:1809" 或 "FileLoader.cpp"）
    loc_lower = loc.lower()
    # 统一 Windows/Unix 分隔符和大小写，只比较 basename。
    fname_base = re.split(r"[\\/]+", finding.get("file", "" ).lower())[-1]
    loc_files = re.findall(r"([a-z_0-9][a-z_0-9.-]*\.(?:cc|cpp|c|h|py))", loc_lower)
    if not any(part == fname_base or part in fname_base or fname_base in part for part in loc_files):
        return False
    # 若数据集提供行号，要求主证据行或 evidence_lines 命中范围。
    # 只解析文件名之后的定位部分，避免把文件名中的版本数字当成行号。
    loc_tail = loc_lower
    for part in loc_files:
        pos = loc_lower.find(part)
        if pos >= 0:
            loc_tail = loc_lower[pos + len(part):]
            break
    line_tokens = re.findall(r"(?:^|[:;,/ l])\s*(\d+)(?:\s*-\s*(\d+))?", loc_tail)
    if not line_tokens:
        return True
    candidate_lines = [finding.get("line", 0)] + finding.get("evidence_lines", [])
    for start, end in line_tokens:
        low = int(start)
        high = int(end or start)
        if any(low <= int(line) <= high for line in candidate_lines):
            return True
    return False


def nearby_finding(finding, loc, max_distance=12):
    """判断候选是否与数据集位置处于同文件、同范围或邻近范围。"""
    if location_match(finding, loc):
        return True
    files = re.findall(r"([a-z_0-9][a-z_0-9.-]*\.(?:cc|cpp|c|h|py))", loc.lower())
    fname = re.split(r"[\\/]+", finding.get("file", "").lower())[-1]
    if not any(part == fname or part in fname or fname in part for part in files):
        return False
    tokens = re.findall(r"(?:^|[:;,/ l])\s*(\d+)(?:\s*-\s*(\d+))?", loc.lower())
    if not tokens:
        return False
    line = int(finding.get("line", 0))
    return any(int(start) - max_distance <= line <= int(end or start) + max_distance for start, end in tokens)


def has_nearby_guard(lines, loc, guard_patterns, max_distance=40):
    """在本地源码中查找声明位置附近的明确边界守卫。"""
    files = re.findall(r"([a-z_0-9][a-z_0-9.-]*\.(?:cc|cpp|c|h|py))", loc.lower())
    tokens = re.findall(r"(?:^|[:;,/ l])\s*(\d+)(?:\s*-\s*(\d+))?", loc.lower())
    if not files or not tokens:
        return False
    ranges = [(int(start) - max_distance, int(end or start) + max_distance) for start, end in tokens]
    return any(any(pattern.search(line) and any(low <= lineno <= high for low, high in ranges)
                   for pattern in guard_patterns)
               for lineno, line in enumerate(lines, 1))


def guarded_status(component, cwe, src, locations):
    """返回 (是否有位置相关源码守卫, 原因)。"""
    if component != "Tencent ncnn" or cwe not in (125, 190, 248, 369, 400, 787):
        return False, ""
    source_file = os.path.join(src or "", "net.cpp")
    if not os.path.isfile(source_file):
        return False, ""
    guard_regex = {
        125: [re.compile(r"\b(?:bottom_blob_index|top_blob_index)\s*<\s*0"), re.compile(r"\b(?:bottom_blob_index|top_blob_index)\s*>=\s*blob_count")],
        787: [re.compile(r"\b(?:bottom_blob_index|top_blob_index)\s*<\s*0"), re.compile(r"\b(?:bottom_blob_index|top_blob_index)\s*>=\s*blob_count")],
        190: [re.compile(r"\b(?:layer_count|blob_count|bottom_count|top_count)\s*[<>]=?\s*(?:MAX_|0)")],
        400: [re.compile(r"\b(?:layer_count|blob_count|bottom_count|top_count)\s*[<>]=?\s*(?:MAX_|0)")],
        248: [re.compile(r"\bif\s*\(\s*!layer\s*\)"), re.compile(r"\bif\s*\(\s*!d->")],
        369: [re.compile(r"\bif\s*\([^\n]*\b(?:den|divisor|count)\s*==\s*0")],
    }[cwe]
    with open(source_file, encoding="utf-8", errors="replace") as sf:
        lines = sf.readlines()
    if any(has_nearby_guard(lines, loc, guard_regex, 40) for loc in locations if loc):
        return True, "explicit-nearby-source-guard"
    return False, ""


def main():
    ap = argparse.ArgumentParser(description="cwe-repair 检测基准化（leaderboard）")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    with open(DSET, encoding="utf-8") as f:
        data = json.load(f)

    rows = []
    for comp in data["components"]:
        src = COMPONENT_SRC.get(comp["name"])
        # 组件相关的 CWE 范围 + 文件类型
        if comp["name"] == "Unitree xr_teleoperate":
            findings = run_detect(src, "125,787,190,369,476,248,306,502,78,20", ext=".py")
        else:
            findings = run_detect(src, "78,125,129,190,369,400,457,476,502,787,789,248")
        for fnd in comp["findings"]:
            cwe = fnd["cwe"]
            loc = fnd.get("loc", fnd.get("title", ""))
            related_loc = fnd.get("related_loc", "")
            hit = None
            if findings is not None:
                # 匹配：CWE 同族（125/787 越界读写常同源）+ 文件位置
                cwe_family = {125, 787} if cwe in (125, 787) else {cwe}
                # 数据集将无效迭代器按越界访问记录，检测器按空指针/无效引用记录。
                if cwe == 125:
                    cwe_family |= {476, 129}
                cands = [x for x in findings if x["cwe"] in cwe_family]
                hit = any(location_match(x, loc) for x in cands)
                if not hit and related_loc:
                    hit = any(location_match(x, related_loc) for x in cands)
                legacy_hit = any(any(part == re.split(r"[\\/]+", x.get("file", "").lower())[-1] or part in re.split(r"[\\/]+", x.get("file", "").lower())[-1] for part in re.findall(r"([a-z_0-9][a-z_0-9.-]*\.(?:cc|cpp|c|h|py))", loc.lower())) for x in cands)
            else:
                legacy_hit = None
            guarded = False
            guarded_reason = ""
            input_guarded = False
            input_guard_reason = ""
            if findings is not None and comp["name"] == "Unitree xr_teleoperate" and fnd["id"] == "VUL-06":
                source_file = os.path.join(src, "teleop", "utils", "ipc.py")
                if not os.path.isfile(source_file):
                    source_file = os.path.join(src, "teleop", "utils", "ipc.py")
                if os.path.isfile(source_file):
                    with open(source_file, encoding="utf-8", errors="replace") as sf:
                        text = sf.read()
                    input_guarded = all(token in text for token in ("msg.get(\"reqid\"", "msg.get(\"cmd\"", "cmd not supported"))
                    if input_guarded:
                        input_guard_reason = "explicit-message-and-command-validation"
            if findings is not None and comp["name"] == "Tencent ncnn" and cwe in (125, 190, 248, 369, 400, 787):
                guard_locs = [loc] + ([related_loc] if related_loc else [])
                guard_regex = {
                    125: [re.compile(r"\b(?:bottom_blob_index|top_blob_index)\s*<\s*0"),
                         re.compile(r"\b(?:bottom_blob_index|top_blob_index)\s*>=\s*blob_count")],
                    787: [re.compile(r"\b(?:bottom_blob_index|top_blob_index)\s*<\s*0"),
                         re.compile(r"\b(?:bottom_blob_index|top_blob_index)\s*>=\s*blob_count")],
                    190: [re.compile(r"\b(?:layer_count|blob_count|bottom_count|top_count)\s*[<>]=?\s*(?:MAX_|0)")],
                    400: [re.compile(r"\b(?:layer_count|blob_count|bottom_count|top_count)\s*[<>]=?\s*(?:MAX_|0)")],
                    248: [re.compile(r"\bif\s*\(\s*!layer\s*\)"), re.compile(r"\bif\s*\(\s*!d->")],
                    369: [re.compile(r"\bif\s*\([^\n]*\b(?:den|divisor|count)\s*==\s*0")],
                }[cwe]
                source_lines = []
                for candidate in guard_locs:
                    source_lines.extend([x for x in (findings or []) if nearby_finding(x, candidate, 40)])
                # 当前本地 NCNN 资产只有 net.cpp；用源码文本确认明确 guard。
                source_file = os.path.join(src, "net.cpp")
                if os.path.isfile(source_file):
                    with open(source_file, encoding="utf-8", errors="replace") as sf:
                        guarded = any(has_nearby_guard(sf.readlines(), candidate, guard_regex, 40) for candidate in guard_locs)
                if guarded:
                    guarded_reason = "explicit-nearby-source-guard"
            status = "no-src" if findings is None else ("HIT" if hit else ("GUARDED" if guarded else "MISS"))
            rows.append({
                "component": comp["name"], "id": fnd["id"], "cwe": cwe,
                "loc": loc[:50], "related_loc": related_loc[:50], "detected": hit, "legacy_detected": legacy_hit,
                "guarded": guarded, "guarded_reason": guarded_reason,
                "input_guarded": input_guarded, "input_guard_reason": input_guard_reason,
                "status": status,
            })

    # 汇总
    evaluated = [r for r in rows if r["status"] != "no-src"]
    strict_hits = sum(1 for r in evaluated if r["status"] == "HIT")
    guarded = sum(1 for r in evaluated if r["status"] == "GUARDED")
    legacy_hits = sum(1 for r in evaluated if r.get("legacy_detected"))
    if args.json:
        print(json.dumps({"total": len(evaluated), "hit": strict_hits,
                          "strict_rate": f"{strict_hits}/{len(evaluated)}",
                          "legacy_rate": f"{legacy_hits}/{len(evaluated)}",
                          "guarded": guarded,
                          "rate": f"{strict_hits}/{len(evaluated)}", "rows": rows},
                         ensure_ascii=False, indent=1))
        return

    print(f"=== cwe-repair 检测基准（{len(evaluated)} 个可评估 finding，{strict_hits} 严格命中）===")
    print(f"严格检出率: {strict_hits}/{len(evaluated)} ({strict_hits*100//max(1,len(evaluated))}%)")
    print(f"文件级参考检出率: {legacy_hits}/{len(evaluated)} ({legacy_hits*100//max(1,len(evaluated))}%)")
    print()
    print("按组件:")
    by_comp = {}
    for r in evaluated:
        by_comp.setdefault(r["component"], [0, 0])
        by_comp[r["component"]][1] += 1
        if r["status"] == "HIT":
            by_comp[r["component"]][0] += 1
    for c, (h, t) in by_comp.items():
        print(f"  {c}: {h}/{t}")
    print()
    print("明细（MISS 项）:")
    for r in evaluated:
        if r["status"] == "MISS":
            print(f"  [{r['component']}] {r['id']} CWE-{r['cwe']} {r['loc']}")


if __name__ == "__main__":
    main()
