# 核心架构 / Core Architecture

## 中文说明

`cwe-repair` 由可移植的防御性核心和可选 adapter 组成。核心负责检测、repair plan、对称性检查、双向验证、asset semantic contract、profile validation、evaluation manifest、release audit，以及 JSON evidence/contract 格式。DSH skill 只是第一个面向 agent 的编排 adapter；本地终端和 CI 可通过 `scripts/cwe_repair_cli.py` 使用同一核心，未来 CI/IDE adapter 也应复用相同 JSON contracts。

DSH 或其他 adapter 不定义验证语义。所有完成性声明均必须经过相同的 portable scripts 和 validators。`embodied-ai-runtime-safety` profile 只增加输入来源、runtime 阶段、控制影响和 fail-closed 修复约束，绝不授权真实机器人执行。AGIBOT joint-command fake-sink 是 `LOCAL_REDUCED_FAKE_SINK`，仅验证有限修复策略；在 exact source、build 和授权本地 runtime 路径 materialize 前，不得作为 `ASSET_SCOPE_COMPLETE` 证据。

## English

`cwe-repair` is organized as a portable defensive core with optional adapters.

```text
Portable core
  detect / repair-plan / symmetry / verify
  asset semantic contract / profile validation
  evaluation manifest / release audit
  JSON evidence and contract formats

Adapters
  DSH skill: agent-oriented orchestration and context collection
  CLI: scripts/cwe_repair_cli.py for local terminals and CI
  Future: CI and IDE adapters consume the same JSON contracts
```

The DSH skill does not define verification semantics. The portable scripts and JSON artifacts do. An adapter may orchestrate evidence collection, but every completion claim must pass the same validators.

## Embodied Profile Boundary

The `embodied-ai-runtime-safety` profile adds input-source, runtime-stage, control-impact, and fail-closed repair constraints. It does not authorize real-robot execution.

The AGIBOT joint-command fake-sink simulation is a `LOCAL_REDUCED_FAKE_SINK` artifact. It validates a bounded repair policy, not AGIBOT/AimRT production execution. It must remain separate from `ASSET_SCOPE_COMPLETE` evidence until an exact source, build, and authorized local runtime path are materialized.
