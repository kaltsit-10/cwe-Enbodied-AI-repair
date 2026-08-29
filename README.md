# cwe-repair

## 中文说明

面向选定 C/C++ AI runtime 与具身智能组件的、基于 artifact 的修复保障研究原型。

本仓库保留 `.dsh/skills/cwe-repair` 作为 DSH 可验证实例，同时提供 portable CLI、JSON contracts、validators、fixtures 与 release audit。它在明确声明范围内给出检测、repair plan、对称性检查、恶意输入拒绝与合法输入保留的可审计证据。

当前可公开发布为研究 artifact，而不是生产级机器人安全产品。`ASSET_SCOPE_COMPLETE` 仅针对每个 pinned asset 的显式 provider、target、configuration、input domain、path 和 dimension；ORT full RNN 与 ORT RNN narrowing scoped 仍为 `REVIEW`。AGIBOT source review 是 `STATIC_ONLY`，fake-sink 是 `LOCAL_REDUCED_FAKE_SINK`；两者均不表示真实机器人、ROS2/AimRT、DDS、CAN、执行器或 production callback runtime 验证。

### 开放过程与可复核验证

本公开包保留 DSH skill、portable scripts、contracts、fixtures、hash-bound evidence 和 GitHub Actions 配置；不包含 AGIBOT/ORT/NCNN 第三方源码树、WSL build output、设备配置、凭据或真实控制接口。公开 clone 会校验 Python scripts、全部公开 JSON、release artifact hash 与 fail-closed release audit。当前已实际验证：四个声明范围内的 contracts 为 `ASSET_SCOPE_COMPLETE`（三个 NCNN parser/path contract 与 ORT SafeMul helper）；两个 ORT RNN contracts 显式为 `REVIEW`；AGIBOT callback 的 source-hash-bound static review 与一恶意一合法的 local fake-sink 双向策略验证均已记录。所有未闭合证据保持可见，不以文档描述替代 runtime 或修复结论。

公开 clone 请运行：

```powershell
python tools\validate_release.py
```

预期输出为 `public release validation: PASS`。详细边界、发布步骤和未来迭代见本文英文部分、`RELEASE_CHECKLIST.md` 与 `.dsh/skills/cwe-repair/RELEASE_SCOPE.md`。

## English

Artifact-backed repair assurance for selected C/C++ AI-runtime and embodied-AI components.

> Research prototype. cwe-repair emits auditable detection, repair-plan, paired-validation, and semantic-contract evidence within explicitly declared scopes. It does not claim universal correctness, formal proof, production robot validation, or real actuator safety.

## What Is Included

- A DSH skill at `.dsh/skills/cwe-repair`, retained as the first integration adapter.
- A portable CLI plus JSON contracts, validators, fixtures, and release audit artifacts.
- Defensive CWE-focused detection, reviewable repair plans, symmetry checks, and malicious-rejection plus benign-preservation verification.
- Embodied-AI profile metadata, source-bound AGIBOT callback static review, and bounded local fake-sink evidence.

## Quick Verification

Python 3.10 or newer is required. From the repository root:

```powershell
python tools\validate_release.py
```

Expected result:

```text
public release validation: PASS
```

`tools/validate_release.py` is intentionally self-contained: it compiles the public Python scripts, parses public JSON artifacts, and runs the release audit without requiring third-party source trees. `scripts/test_cwe_repair.py` remains the broader development regression and additionally exercises optional local NCNN/AGIBOT research corpora when they are available.

The portable CLI can be used without a DSH session:

```powershell
python .dsh\skills\cwe-repair\scripts\cwe_repair_cli.py contract --contract .dsh\skills\cwe-repair\examples\ncnn_pr6383_asset_semantic_contract.json --json
python .dsh\skills\cwe-repair\scripts\cwe_repair_cli.py release-audit --json
```

## DSH Integration

This repository intentionally preserves the skill layout. Place the repository directory in a DSH workspace and load the `cwe-repair` skill. The same scripts remain usable directly from a terminal.

## Evidence Semantics

`ASSET_SCOPE_COMPLETE` means all required gates passed only for one pinned asset and its explicitly declared provider, target, configuration, input domain, paths, and dimensions. It is not an all-input, all-provider, all-configuration, or formal-proof claim.

`REVIEW` is an intended fail-closed result when evidence is incomplete. In this release, ORT full RNN and ORT RNN narrowing scoped contracts remain `REVIEW`.

AGIBOT evidence is intentionally split:

```text
Production source review:       STATIC_ONLY / REVIEW
Local policy simulation:        LOCAL_REDUCED_FAKE_SINK
Future source-slice plan:       REVIEW
```

No result in this repository validates a real robot, ROS2/AimRT transport, DDS, CAN, actuator, or production AGIBOT callback runtime.

## Repository Layout

```text
.dsh/skills/cwe-repair/
  SKILL.md                 DSH adapter entry point
  scripts/                 portable core commands and validators
  examples/                hash-bound evidence, fixtures, contracts
  README.md                detailed skill guide
  RELEASE_SCOPE.md         release boundary and claims
  CORE_ARCHITECTURE.md     portable-core and adapter design
```

## Next Iterations

1. Materialize a C++ callback-to-local-fake-sink slice from the AGIBOT plan without ROS, DDS, CAN, or physical devices.
2. Run normalized cppcheck, Semgrep, and CodeQL baselines and report measured precision, recall, F1, guarded false-positive rate, and runtime cost.
3. Find a safe, finite, attributable full-provider ORT RNN negative witness, or preserve `REVIEW`.
4. Package the portable CLI and schemas as a versioned installable API with CI and IDE adapters.

## Security and Contribution Rules

- This is defensive research tooling. Do not submit exploit chains, real-device credentials, endpoints, or actuator configurations.
- A repair is not complete until its evidence includes the appropriate verification results.
- Any upgrade from `REVIEW` to `ASSET_SCOPE_COMPLETE` must be supported by provenance, source scope, inventory, paired build, runtime evidence, safety boundaries, and hash-bound artifacts.

See [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), and the detailed [skill README](.dsh/skills/cwe-repair/README.md).
