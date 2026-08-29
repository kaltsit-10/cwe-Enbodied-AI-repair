---
name: cwe-repair
description: 以越界读写 CWE-125/787、整数溢出 CWE-190、除零 CWE-369 为核心的防御性“检测→修复建议→正确性验证”研究原型，并包含少量 CWE-476/248 及 Python/逻辑类实验规则。适用于 C/C++ 具身智能组件与授权本地源码回归。
whenToUse: 用户要求检测或修复特定类型漏洞（越界/整数溢出/除零）、验证修复是否有效、对 C/C++ 组件做防御性加固、或生成带回归证据的修复 PR 材料时。
---

# CWE Repair — 防御性检测·修复建议·验证研究原型

## 定位（与现有工具的区别）

| 环节 | 通用工具 | 本技能 |
|---|---|---|
| 检测 | CodeQL/cppcheck（通用规则） | **规则模板**聚焦本项目实证的 4 类模式，低误报优先 |
| 修复 | Copilot Autofix（LLM 生成，无保证） | **模式化修复建议**（确定性、可审阅，非自动语义修复） |
| 验证 | 回归测试（只测合法功能） | ⭐ **双向回归**：恶意输入必须被拒 + 合法输入不误拒 |

## 工作流程（四阶段）

### 阶段 0：可达性标注（reach，具身智能垂直领域）

```bash
python .dsh/skills/cwe-repair/scripts/cwe_reach.py --component <ncnn|mindspore|agibot|aimrt|xr> [--json]
# 批量：detect 输出 JSON 后逐条标注
python cwe_reach.py --detect-json detect_out.json --component agibot
```

- 输出默认可达性：`default-reachable` / `config-reachable` / `local-only` / `model-file`
- agibot 组件会实时读取 YAML 配置（`sub_topics_options`）作为证据
- 用途：区分"默认即达漏洞"（XR）与"配置后可达"（AGIBOT/AimRT），避免上报时夸大可达性

### 阶段 1：检测（detect）

```bash
python .dsh/skills/cwe-repair/scripts/cwe_detect.py <目标文件或目录> --cwe 125,787,190,369
```

- 输出：文件:行号:CWE:模式:证据片段
- 优先关注 `index_from_attacker`（下标来自 msg/data/input）与 `parallel_array_loop`（平行数组不互检）——与 AGIBOT/NCNN 漏洞同构
- 用 `--json` 获取机器可读结果供后续阶段解析
- ⚠️ 检测器是"低误报优先"的规则扫描：命中 ≠ 漏洞，需结合上下文人工/agent 确认（查同函数内是否已有 `if (idx < 0 || idx >= size)` 之类的守卫；有则跳过）

### 阶段 1.5：对称性检查（symmetry，提交前防 bot 迭代）

```bash
python .dsh/skills/cwe-repair/scripts/symmetry_check.py <src_dir> --file <目标文件>
```

- 检测"成对入口"（text/bin 双解析器、WriteMember/WriteMemberNested 兄弟函数）中
  **一处有守卫、一处没有**的修复不对称
- **实证**：ncnn PR #6922 的 2 次 Codex P1 打回（资源上限未应用到 bin 路径、
  top_count=0 除零不完整）都是这类不对称——本工具提交前即可发现
- 用法：生成修复补丁前先跑一次；修复后再跑一次确认对称

### 阶段 2：修复（repair）

```bash
python .dsh/skills/cwe-repair/scripts/cwe_repair.py \
    --file <源文件> --line <行号> --cwe 787 \
    --idx bottom_blob_index --size blob_count --log ncnn --out fix.patch
```

- 模板化补丁（与 NCNN PR #6922 / AimRT AR-1 修复同构）：
  - 越界（125/787）：`if (idx < 0 || idx >= size) { 报错; return -1; }`
  - 溢出（190）：`if (count <= 0 || count > MAX) { 报错; return -1; }`
  - 除零（369）：`if (den == 0) { 报错; return -1; }`
  - 空指针（476）：`if (!ptr) { 报错; return -1; }`
  - 未捕获异常（248）：`.at()` → `find()` + 存在性检查（AGIBOT X1-8 同款）
- `--log` 选择项目日志宏（ncnn/aimrt/mindspore/generic）
- ⚠️ 生成的是"建议补丁"，**必须人工审阅**后 `git apply`（缩进/变量名/返回语义需核对）

### 阶段 3：验证（verify）⭐ 本技能核心

```bash
python .dsh/skills/cwe-repair/scripts/cwe_verify.py \
    --binary <修复版可执行> \
    --malicious "poc1.parambin poc2.parambin" \
    --benign "valid1.param valid2.param" --asan
```

- **A 方向（恶意拒绝）**：每个恶意 PoC 必须被修复版拒绝（exit 非 139/134 崩溃信号），证明漏洞被修
- **B 方向（合法不误拒）**：每个合法输入必须正常通过（exit 0 / ret=0，无崩溃），证明修复无误伤
- 输出 `PASS`（双向全过）或 `REVIEW`（有失败项需人工复核）
- 支持 `--config verify.json` 批量跑（示例见下）

#### verify.json 示例

```json
{
  "binary": "/home/kaltsit/vuln_repro/ncnn_fuzz/assess/loadpoc_file_fixed2",
  "malicious": [
    "/home/kaltsit/vuln_repro/ncnn_fuzz/ncnn_blobidx_oob_149B.parambin",
    "/home/kaltsit/vuln_repro/ncnn_fuzz/ncnn_blobidx_oob_negidx.parambin"
  ],
  "benign": [
    "/home/kaltsit/vuln_repro/ncnn_fuzz/valid_minimal.parambin",
    "/home/kaltsit/vuln_repro/ncnn_fuzz/squeezenet_v1.1.param"
  ],
  "asan": true,
  "timeout": 30
}
```

### 阶段 4：单资产全路径语义复核门禁（asset semantic contract）

```bash
python .dsh/skills/cwe-repair/scripts/asset_semantic_contract.py \
    --contract examples/<asset>_semantic_contract.json --json
```

该门禁将一个 pinned 资产的声明范围拆成：

- 资产级：官方 provenance、base/head source scope、入口/边界/sink inventory、可复现 build、执行安全边界；
- 路径级：static contract、symmetry、paired build、base/head runtime、恶意拒绝、合法保留；
- 维度级：每条入口/调用路径实际声明的输入契约维度。

只有每一条声明路径和维度都绑定了可读、SHA-256 一致、case ID 一致且断言通过的 evidence artifact，且所有 required gate 为 `PASS`，才输出 `ASSET_SCOPE_COMPLETE`。`artifact_integrity=true` 只代表证据文件和结构可复核，不代表语义 scope 已闭合；缺任一 gate 必须输出 `REVIEW`。

这个结果的含义严格限于一个资产及其显式声明的 provider、target、configuration、input domain；不外推为所有输入/所有 provider 的正确性，也不产生形式化证明。`universal_claim` 和 `formal_proof` 必须为 `false`。

## 输出交付（供 PR/上报材料）

三阶段完成后，用 `--json` 汇总生成：

```
[检测] N 个命中（按 CWE 分布）
[修复] M 个补丁（每个对应 file:line:CWE）
[验证] 恶意拒绝 a/b，合法通过 c/d → PASS/REVIEW
```

此三元组可作为本地研究和修复审阅材料；只有实际运行 `verify` 且通过时，才可称为该案例的完整双向验证证据。

## 边界与纪律

- **防御侧工具**：不生成利用代码，不研究 RCE 利用链——符合项目授权边界
- **修复必须验证**：没有跑 verify 的补丁视为"未完成"，不能作为上报材料
- **人工审阅**：repair 生成物是模板建议，套用前需审阅语义（尤其返回值/错误路径与项目惯例一致）
- **误报处理**：detect 命中后若发现已有守卫，标注 `false-positive` 并跳过，不强行生成补丁
- **不连接真实执行器**：verify 只针对本地二进制与本地输入文件

## English Guide

### Purpose

This skill is a defensive research prototype for CWE-125/787, CWE-190, CWE-369, selected CWE-476/248 patterns, and a small set of Python or logic experiments. It is intended for authorized local C/C++ component review.

### Workflow

1. `cwe_reach.py` labels reachability from component configuration.
2. `cwe_detect.py` reports conservative rule-template candidates; a finding is not automatically a vulnerability.
3. `symmetry_check.py` checks paired entry points for asymmetric guards.
4. `cwe_repair.py` generates a reviewable template patch, never an autonomous semantic repair.
5. `cwe_verify.py` requires malicious rejection and benign preservation.
6. `asset_semantic_contract.py` aggregates hash-bound provenance, inventory, build, runtime, path, dimension, and safety evidence for one declared asset scope.

### Evidence Boundary

`ASSET_SCOPE_COMPLETE` requires every declared gate to pass for the declared scope only. `artifact_integrity=true` means artifacts are readable and internally consistent, not that semantic coverage is complete. Missing evidence must remain `REVIEW`; `universal_claim=false` and `formal_proof=false` are mandatory. Do not generate exploit chains, use external targets, connect real actuators, or treat template repairs as complete without appropriate local verification.
