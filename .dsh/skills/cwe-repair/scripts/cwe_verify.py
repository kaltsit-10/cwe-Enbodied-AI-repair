#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cwe_verify.py — 修复正确性双向验证器（防御侧，验证阶段 —— 本项目核心差异化）

对"修复后的二进制"自动运行双向回归：
  A（恶意输入拒绝）: 每个恶意 PoC 必须被修复版拒绝（exit 非崩溃/ret=-1），不得 SEGV/ABRT
  B（合法输入不误拒）: 每个合法输入必须正常通过（ret=0 / 无崩溃），修复不得破坏功能

这是现有工具（回归测试/静态 oracle/LLM 判别）都不做的闭环：
- 回归测试只测合法功能，不测恶意输入是否被拒
- 静态 oracle 无运行证据
- 本验证器用真实 ASan/退出码做双向实证

用法（两种模式）:
  1) 二进制模式: python cwe_verify.py --binary <修复版可执行> \
       --malicious "<poc1> <poc2>" --benign "<valid1> <valid2>" [--asan]
  2) 配置模式:   python cwe_verify.py --config verify.json

输出: PASS/FAIL 逐项 + 汇总 + 机器可读 JSON（供 DSH agent 生成报告）
"""
import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def run_case(binary, inp, timeout=30, asan=False):
    """运行单个输入，返回 (exit_code, output)。binary 支持带参数的命令。"""
    env = os.environ.copy()
    if asan:
        env["ASAN_OPTIONS"] = "abort_on_error=1:symbolize=1:detect_leaks=0"
    try:
        cmd = shlex.split(binary, posix=False) + [inp]
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, env=env)
        return proc.returncode, (proc.stdout or b"").decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return "TIMEOUT", ""
    except FileNotFoundError:
        return "NOBINARY", ""
    except Exception as e:
        return f"ERR:{e}", ""


CRASH_CODES = (139, 134, 132, 136, 133, -11, -6, -4, -7, -8)  # 正=exit code, 负=信号(SIGSEGV/SIGABRT/ILL/BUS/FPE/KILL)
WSL_UNAVAILABLE_MARKERS = (
    "HCS_E_HYPERV_NOT_INSTALLED",
    "Wsl/Service/CreateInstance",
    "WSL2 is not supported with your current machine configuration",
)


def infrastructure_reason(rc, output):
    """Return a host/launcher failure reason, never an input-rejection verdict."""
    if rc == "NOBINARY":
        return "missing-binary"
    if rc == "TIMEOUT":
        return "timeout"
    if isinstance(rc, str) and rc.startswith("ERR:"):
        return "process-error"
    normalized_output = output.replace("\x00", "").lower()
    if any(marker.lower() in normalized_output for marker in WSL_UNAVAILABLE_MARKERS):
        return "wsl-unavailable"
    return None


def verify_binary(binary, malicious, benign, timeout=30, asan=False):
    """执行双向验证。返回结果 dict。"""
    results = {"binary": binary, "malicious": [], "benign": [], "summary": {}}

    def parse_ret(out):
        """从输出解析加载器返回码：'ret=-1' 拒绝 / 'ret=0' 通过 / None 未知"""
        m = re.search(r"ret=(-?\d+)", out)
        return int(m.group(1)) if m else None

    # A 方向：恶意输入必须被拒绝（无崩溃 + ret=-1）
    for inp in malicious:
        if not os.path.exists(inp):
            results["malicious"].append({"input": inp, "status": "MISSING"})
            continue
        rc, out = run_case(binary, inp, timeout, asan)
        crashed = (rc in CRASH_CODES) or (isinstance(rc, int) and rc < 0)
        infra_reason = infrastructure_reason(rc, out)
        infra_error = infra_reason is not None
        ret = parse_ret(out)
        # 只有程序确实运行且明确拒绝时才算通过；基础设施失败不能伪装成拒绝。
        rejected = (not crashed) and (not infra_error) and (ret == -1 or (isinstance(rc, int) and rc != 0 and ret is None))
        results["malicious"].append({
            "input": os.path.basename(inp), "exit": rc, "ret": ret,
            "crashed": crashed, "infra_error": infra_error, "infra_reason": infra_reason,
            "rejected": rejected, "output_tail": out[-300:],
            "pass": rejected,  # 恶意输入要求被拒绝
        })

    # B 方向：合法输入必须正常（无崩溃 + ret=0 或 正常退出）
    for inp in benign:
        if not os.path.exists(inp):
            results["benign"].append({"input": inp, "status": "MISSING"})
            continue
        rc, out = run_case(binary, inp, timeout, asan)
        crashed = (rc in CRASH_CODES) or (isinstance(rc, int) and rc < 0)
        infra_reason = infrastructure_reason(rc, out)
        infra_error = infra_reason is not None
        ret = parse_ret(out)
        # 正常 = 程序确实运行、未崩溃，且 ret=0 或明确正常退出。
        ok = (not crashed) and (not infra_error) and (ret == 0 or (rc == 0 and ret is None))
        results["benign"].append({
            "input": os.path.basename(inp), "exit": rc, "ret": ret,
            "crashed": crashed, "infra_error": infra_error, "infra_reason": infra_reason,
            "ok": ok, "output_tail": out[-300:],
            "pass": ok,  # 合法输入要求不崩溃
        })

    # 汇总
    m_pass = sum(1 for r in results["malicious"] if r.get("pass"))
    b_pass = sum(1 for r in results["benign"] if r.get("pass"))
    m_total = len([r for r in results["malicious"] if r.get("status") != "MISSING"])
    b_total = len([r for r in results["benign"] if r.get("status") != "MISSING"])
    infra_failures = sum(1 for group in (results["malicious"], results["benign"])
                         for r in group if r.get("infra_error"))
    infra_reasons = {}
    for group in (results["malicious"], results["benign"]):
        for result in group:
            reason = result.get("infra_reason")
            if reason:
                infra_reasons[reason] = infra_reasons.get(reason, 0) + 1
    missing_inputs = sum(1 for group in (results["malicious"], results["benign"])
                         for r in group if r.get("status") == "MISSING")
    results["summary"] = {
        "malicious_rejected": f"{m_pass}/{m_total}",
        "benign_passed": f"{b_pass}/{b_total}",
        "infrastructure_failures": infra_failures,
        "infrastructure_reasons": infra_reasons,
        "missing_inputs": missing_inputs,
        "verdict": "PASS" if (m_total > 0 and m_pass == m_total and b_total > 0 and b_pass == b_total and infra_failures == 0) else "REVIEW",
    }
    return results


def main():
    ap = argparse.ArgumentParser(description="修复正确性双向验证器（A:恶意拒绝 / B:合法不误拒）")
    ap.add_argument("--binary", help="修复后二进制")
    ap.add_argument("--malicious", help="恶意 PoC 列表（空格分隔或引号包裹）")
    ap.add_argument("--benign", help="合法输入列表（空格分隔或引号包裹）")
    ap.add_argument("--asan", action="store_true", help="设置 ASAN_OPTIONS")
    ap.add_argument("--config", help="JSON 配置文件（替代命令行）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    args = ap.parse_args()

    if args.config:
        with open(args.config, encoding="utf-8") as f:
            cfg = json.load(f)
        binary = cfg["binary"]
        malicious = cfg.get("malicious", [])
        benign = cfg.get("benign", [])
        asan = cfg.get("asan", False)
        timeout = cfg.get("timeout", 30)
    else:
        binary = args.binary
        malicious = args.malicious.split() if args.malicious else []
        benign = args.benign.split() if args.benign else []
        asan = args.asan
        timeout = 30

    if not binary:
        print("ERROR: 需要 --binary 或 --config", file=sys.stderr)
        sys.exit(2)

    results = verify_binary(binary, malicious, benign, timeout, asan)

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=1))
    else:
        print(f"=== 修复正确性双向验证: {binary} ===")
        print(f"\n[A] 恶意输入必须被拒绝 ({results['summary']['malicious_rejected']}):")
        for r in results["malicious"]:
            mark = "✅" if r.get("pass") else "❌"
            print(f"  {mark} {r['input']}  exit={r.get('exit')}  crashed={r.get('crashed', '-')}")
        print(f"\n[B] 合法输入必须不误拒 ({results['summary']['benign_passed']}):")
        for r in results["benign"]:
            mark = "✅" if r.get("pass") else "❌"
            print(f"  {mark} {r['input']}  exit={r.get('exit')}  crashed={r.get('crashed', '-')}")
        print(f"\n=== 判定: {results['summary']['verdict']} ===")


if __name__ == "__main__":
    main()
