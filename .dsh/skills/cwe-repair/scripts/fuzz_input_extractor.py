#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fuzz_input_extractor.py — 验证输入自动扩充（借鉴 oss-fuzz-gen）

从 fuzz crash 目录 / corpus 提取"恶意输入集"和"合法输入集"，自动生成
cwe_verify 可用的 JSON 配置。解决 cwe_verify 的"验证输入覆盖面"短板
（人工 PoC → 自动 fuzz 产出）。

用法:
  python fuzz_input_extractor.py --crash-dir <crash目录> \
      --corpus-dir <corpus目录> --output verify_auto.json \
      --binary /path/to/fixed_binary [--max-malicious 20] [--max-benign 10]

逻辑:
  - crash 目录下的文件 → 恶意输入（修复版应拒绝）
  - corpus 目录下随机抽样 → 合法输入候选（先用 binary 过滤 ret=0 的）
"""
import argparse
import json
import os
import random
import shlex
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")


def run_binary(binary, inp, timeout=10):
    """跑二进制看输出 ret。返回 (rc, ret_val)"""
    try:
        cmd = shlex.split(binary, posix=False) + [inp]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=timeout)
        out = (proc.stdout or b"").decode("utf-8", errors="replace")
        import re
        m = re.search(r"ret=(-?\d+)", out)
        ret = int(m.group(1)) if m else None
        return proc.returncode, ret
    except Exception:
        return None, None


def main():
    ap = argparse.ArgumentParser(description="fuzz 验证输入自动扩充")
    ap.add_argument("--crash-dir", required=True, help="fuzz crash 目录")
    ap.add_argument("--corpus-dir", required=True, help="fuzz corpus 目录")
    ap.add_argument("--output", required=True, help="输出 JSON 路径")
    ap.add_argument("--binary", required=True, help="修复版二进制（用于过滤合法输入）")
    ap.add_argument("--benign-dir", help="合法输入来源目录（真实模型文件，如 ncnn examples/）")
    ap.add_argument("--max-malicious", type=int, default=20)
    ap.add_argument("--max-benign", type=int, default=10)
    args = ap.parse_args()

    # 恶意输入：crash 目录全部文件（或抽样）
    malicious = []
    if os.path.isdir(args.crash_dir):
        files = [os.path.join(args.crash_dir, f) for f in os.listdir(args.crash_dir)
                 if os.path.isfile(os.path.join(args.crash_dir, f))]
        random.shuffle(files)
        malicious = files[:args.max_malicious]
    print(f"恶意输入候选: {len(malicious)}")

    # 合法输入：corpus 抽样后用 binary 过滤（ret=0 或 exit 0）
    # ⚠️ 实测（2026-08-22）：fuzz corpus 多为畸形输入，对修复版几乎不返回 ret=0——
    #    fuzz 语料不适合当"合法输入"。合法输入应来自真实模型文件（--benign-dir 参数）。
    benign = []
    benign_dir = getattr(args, "benign_dir", None)
    sources = [benign_dir] if benign_dir else []
    for src in sources:
        if src and os.path.isdir(src):
            files = [os.path.join(src, f) for f in os.listdir(src)
                     if os.path.isfile(os.path.join(src, f))]
            random.shuffle(files)
            for f in files:
                if len(benign) >= args.max_benign:
                    break
                rc, ret = run_binary(args.binary, f)
                if rc == 0 and (ret == 0 or ret is None):
                    benign.append(f)
    if not benign:
        print("⚠️ 合法输入为 0：fuzz corpus 不适合当合法输入（畸形为主）。")
        print("   请用 --benign-dir <真实模型目录> 提供合法样本（如 ncnn examples/）。")

    config = {
        "binary": args.binary,
        "malicious": malicious,
        "benign": benign,
        "asan": True,
        "timeout": 30,
        "source": "fuzz-auto-extracted",
        "crash_dir": args.crash_dir,
        "benign_dir": getattr(args, "benign_dir", None),
    }
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
    print(f"配置已写入: {args.output}")
    print(f"  恶意: {len(malicious)} 个 | 合法: {len(benign)} 个")


if __name__ == "__main__":
    main()
