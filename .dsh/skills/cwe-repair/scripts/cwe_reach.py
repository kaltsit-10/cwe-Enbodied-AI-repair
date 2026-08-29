#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cwe_reach.py — 可达性标注器（垂直领域增强）

对检测到的缺陷，结合机器人组件的 YAML 配置判断"默认可达性"：
  - default-reachable : 默认配置即可达（0.0.0.0 绑定 / DDS 默认 domain / sub 含 ros2）
  - config-reachable  : 需配置变更才可达（sub 从 local 改 ros2、启用某插件）
  - local-only        : 仅本地/进程内可达
  - model-file        : 经模型文件（供应链投递）可达

依据（项目实证）：
  - agibot_x1_infer: sub_topics_options 默认 [local]，pub 默认 [local, ros2]（x1_cfg.yaml）
  - AimRT: net_plugin 默认未启用（需配置加载 .so 插件）
  - xr_teleoperate: Vuer 绑定 0.0.0.0:8012（默认即达）；DDS domain 0（默认即达）
  - NCNN/MindSpore: 文件解析，经模型投递可达（供应链）

用法:
  python cwe_reach.py --file <源文件> --line <行号> --component <ncnn|mindspore|agibot|aimrt|xr> [--json]
  python cwe_reach.py --detect-json <cwe_detect 的 JSON 输出> --component agibot  # 批量
"""
import argparse
import json
import os
import re
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.environ.get("DSH_WORKSPACE", os.path.abspath(os.path.join(SCRIPT_DIR, "..", "..", "..", "..")))

# ---- 组件默认输入/配置条件规则表 ----
COMPONENT_RULES = {
    "ncnn": {
        "input_type": "模型文件 (.param/.parambin)",
        "default": "model-file",
        "note": "解析器加载任意来源模型文件；默认经模型投递（供应链/本地）可达",
        "reachable_if": "用户加载恶意模型文件即触发（UI:R）",
    },
    "mindspore": {
        "input_type": "checkpoint 文件 (.ckpt)",
        "default": "model-file",
        "note": "load_checkpoint 解析不可信 ckpt；HF/ModelScope 投毒链",
        "reachable_if": "加载投毒 checkpoint（供应链）",
    },
    "agibot": {
        "input_type": "ROS2 消息 / YAML 配置 / 模型文件",
        "default": "config-reachable",
        "note": "sub_topics_options 默认 [local]（进程内）；pub 默认 [local, ros2]（状态外泄）；改 sub 为 ros2 后 DDS 网络可达",
        "reachable_if": "运维改 sub_topics_options 为 [local, ros2]，或本地进程/配置投递",
        "yaml_key": "sub_topics_options",
    },
    "aimrt": {
        "input_type": "HTTP/TCP/UDP JSON / 配置",
        "default": "config-reachable",
        "note": "net_plugin 需配置加载 .so 插件并绑定端口；启用后 HTTP RPC/channel 网络可达",
        "reachable_if": "部署配置启用 net_plugin（HTTP/WS/TCP）",
    },
    "xr": {
        "input_type": "WSS 控制帧 / DDS / ZMQ 视频 / 本地 pickle",
        "default": "default-reachable",
        "note": "Vuer 绑定 0.0.0.0:8012、DDS domain 0、ZMQ 0.0.0.0 —— 默认局域网可达",
        "reachable_if": "默认部署即可达（0.0.0.0 + DDS domain 0）",
        "exceptions": {"VUL-02": "local-only", "VUL-06": "local-only"},
    },
}


def check_yaml_backends(component, filepath=None):
    """尝试读组件默认 YAML 配置判断 sub 后端。返回 (default_reach, evidence)。"""
    if component != "agibot":
        return None, None
    # 常见配置路径
    candidates = [
        os.path.join(WORKSPACE, "AGIBOT", "repos", "agibot_x1_infer_src", "src", "install", "linux", "bin", "cfg", "x1_cfg.yaml"),
        os.path.join(WORKSPACE, "AGIBOT", "repos", "agibot_x1_infer_src", "src", "install", "linux", "bin", "cfg", "x1_cfg_sim.yaml"),
    ]
    for p in candidates:
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                content = f.read()
            m = re.search(r"sub_topics_options:.*?enable_backends:\s*(\[[^\]]*\])", content, re.S)
            if m:
                return "default-reachable" if "ros2" in m.group(1) else "config-reachable", m.group(1)
    return None, None


def classify(component, line=None, detect_json=None):
    """返回可达性标注 dict。"""
    rule = COMPONENT_RULES.get(component, {})
    default = rule.get("default", "unknown")
    evidence = rule.get("note", "")

    # YAML 实证（agibot）
    yaml_reach, yaml_ev = check_yaml_backends(component)
    if yaml_reach:
        default = yaml_reach
        evidence += f" | YAML 实测 sub backends={yaml_ev}"

    return {
        "component": component,
        "input_type": rule.get("input_type", "?"),
        "default_reachability": default,
        "reachable_if": rule.get("reachable_if", "?"),
        "evidence": evidence,
    }


def main():
    ap = argparse.ArgumentParser(description="可达性标注器（具身智能垂直领域）")
    ap.add_argument("--component", required=True, choices=list(COMPONENT_RULES.keys()))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--detect-json", help="cwe_detect 的 JSON 输出文件（批量标注）")
    args = ap.parse_args()

    if args.detect_json:
        with open(args.detect_json, encoding="utf-8") as f:
            data = json.load(f)
        reach = classify(args.component)
        for fnd in data.get("findings", []):
            fnd["reachability"] = reach
        print(json.dumps(data, ensure_ascii=False, indent=1))
        return

    result = classify(args.component)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=1))
    else:
        print(f"组件: {result['component']}")
        print(f"输入类型: {result['input_type']}")
        print(f"默认可达性: {result['default_reachability']}")
        print(f"可达条件: {result['reachable_if']}")
        print(f"证据: {result['evidence']}")


if __name__ == "__main__":
    main()
