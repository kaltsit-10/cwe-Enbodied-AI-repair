#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
coverage_analysis.py — 工具覆盖度分析

将 embodied-ai-cwe-dataset.json 的 34 个 findings 与 cwe-repair 工具能力关联，
标注每个漏洞是否可被 检测(detect) / 修复(repair) / 验证(verify) 覆盖。

输出: 覆盖度矩阵（组件 x CWE 类别 x 工具阶段），用于论文"方法覆盖范围"论证。
"""
import json
import os
import sys

sys.stdout.reconfigure(encoding="utf-8")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE = os.environ.get("DSH_WORKSPACE", os.path.abspath(os.path.join(SCRIPT_DIR, "..", "..", "..", "..")))
DSET = os.path.join(BASE, "研究文档", "embodied-ai-cwe-dataset.json")

# 工具覆盖规则：按 CWE 判定三阶段覆盖
# detect: 模式库覆盖的 CWE（125/787/190/369/476/248 + 逻辑类 306/502/78/20 Python 模式）
# repair: 模板库覆盖的 CWE（125/787/190/369/476/248）
# verify: 通用（任何"输入→二进制"可测的漏洞）
DETECT_CWES = {78, 125, 129, 190, 248, 306, 369, 400, 457, 476, 502, 787, 789, 20}
REPAIR_CWES = {125, 787, 190, 369, 476, 248}
ADVISORY_CWES = {78, 129, 400, 457, 789}
# verify 需要"本地二进制 + 输入文件"可复现
VERIFY_REQUIRES = {125, 787, 190, 369, 476, 789, 248}
# 逻辑类（认证/反序列化/注入）— detect 已有 Python 模式；repair/verify 需不同机制
LOGIC_CWES = {306, 502, 78, 20}

CWE_TO_TOOL = {}
for cwe in DETECT_CWES:
    CWE_TO_TOOL[cwe] = {"detect": True, "repair": cwe in REPAIR_CWES, "verify": cwe in VERIFY_REQUIRES}
for cwe in VERIFY_REQUIRES - DETECT_CWES:
    CWE_TO_TOOL.setdefault(cwe, {})["verify"] = True
for cwe in LOGIC_CWES:
    CWE_TO_TOOL[cwe]["detect"] = True
    CWE_TO_TOOL[cwe]["repair"] = False
    CWE_TO_TOOL[cwe]["verify"] = "partial"  # 需网络/多进程/运行时环境


def main():
    with open(DSET, encoding="utf-8") as f:
        data = json.load(f)

    rows = []
    for comp in data["components"]:
        for fnd in comp["findings"]:
            cwe = fnd["cwe"]
            tool = CWE_TO_TOOL.get(cwe, {"detect": False, "repair": False, "verify": False})
            rows.append({
                "component": comp["name"],
                "id": fnd["id"],
                "cwe": cwe,
                "title": fnd["title"],
                "detect": tool.get("detect", False),
                "repair": tool.get("repair", False),
                "verify": tool.get("verify", False),
            })

    # 汇总
    total = len(rows)
    d = sum(1 for r in rows if r["detect"] is True)
    rp = sum(1 for r in rows if r["repair"] is True)
    vf = sum(1 for r in rows if r["verify"] is True or r["verify"] == "partial")
    vf_full = sum(1 for r in rows if r["verify"] is True)
    full_auto = sum(1 for r in rows if r["detect"] and r["repair"] and r["verify"] is True)
    advisory = sum(1 for r in rows if r["cwe"] in ADVISORY_CWES and r["detect"])

    print(f"=== 工具覆盖度分析（{total} findings）===")
    print(f"detect 覆盖: {d}/{total} ({d*100//total}%)")
    print(f"repair 覆盖: {rp}/{total} ({rp*100//total}%)")
    print(f"verify 能力覆盖（按 CWE 推导，非逐条运行）: {vf}/{total} (完整能力 {vf_full})")
    print(f"理论能力交集（detect+repair+verify，非实际逐条闭环）: {full_auto}/{total} ({full_auto*100//total}%)")
    print(f"仅检测/建议覆盖: {advisory}/{total}（CWE-78/129/400/457/789 等，未计入自动修复）")
    print()
    print("=== 按组件 ===")
    by_comp = {}
    for r in rows:
        by_comp.setdefault(r["component"], {"t": 0, "full": 0})
        by_comp[r["component"]]["t"] += 1
        if r["detect"] and r["repair"] and r["verify"] is True:
            by_comp[r["component"]]["full"] += 1
    for c, v in by_comp.items():
        print(f"  {c}: 全自动 {v['full']}/{v['t']}")
    print()
    print("=== 未全自动覆盖项（逻辑类/需环境）===")
    for r in rows:
        if not (r["detect"] and r["repair"] and r["verify"] is True):
            print(f"  {r['id']} CWE-{r['cwe']} [{r['component']}] {r['title'][:45]}")


if __name__ == "__main__":
    main()
