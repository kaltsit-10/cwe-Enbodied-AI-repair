# 发布范围 / Release Scope

## 中文说明

本版本是具身智能 AI runtime 安全复核研究原型，覆盖 inference output 影响下游系统之前的有限 model-file 与 tensor-shape input path。任何 contract 都不授权真实机器人执行。

已闭合的声明范围包括三个 NCNN parser/path contracts 与 ORT `SafeMul<T>` helper。前两个 NCNN contract 是可审计 passing subset，四路径 contract 才是本版本的 NCNN release coverage；它们不覆盖未列出的 parser、Vulkan 或 custom fallback。每份闭合 contract 均只针对 pinned revision、声明 build configuration、local fixture domain、listed entrypoint 与 dimension。

ORT `rnn_narrowing_scoped_contract`、ORT full RNN、NCNN Vulkan/custom fallback、non-CPU provider、未列 configuration matrix，以及真实 sensor/DDS/ROS/actuator/robot-control execution 均保持 `REVIEW`。AGIBOT `JointCmdCallback` artifact 是 source-hash-bound `STATIC_ONLY` review；fake-sink artifact 是一恶意一合法输入的 `LOCAL_REDUCED_FAKE_SINK` policy simulation；二者不等于 production runtime 或 asset contract gate。evaluation manifest 中只有 cwe-repair local artifact 标记为 measured，cppcheck/Semgrep/CodeQL 均为 `pending-environment`。

`ASSET_SCOPE_COMPLETE` 只表示声明 scope 的全部 evidence gate 通过；任何 path、dimension、runtime witness、provider 或 safety condition 未闭合时必须是 `REVIEW`。release audit 自动发现 semantic contracts，并在 declared inventory 不一致时 fail-closed。

## English

This release is an embodied-AI runtime safety verification prototype. It covers bounded model-file and tensor-shape input paths before inference output can affect a downstream system. No contract authorizes real-robot execution.

## Verified Contracts

- `ncnn_pr6383_asset_semantic_contract.json`: CPU Release, one TEXT ParamDict parser failure-cleanup path.
- `ncnn_pr6383_two_text_failure_asset_contract.json`: CPU Release, two ordinary TEXT parser failure-cleanup paths.
- `ncnn_pr6383_four_parser_paths_asset_contract.json`: CPU Release, the released NCNN superset of four ordinary TEXT/BIN parser failure-cleanup paths.
- `ort_pr28003_safeint_helper_asset_contract.json`: CPU Debug `SafeMul<T>` helper behavior and its finite upstream `SafeIntTest.*` cases only.

The first two NCNN contracts are retained as auditable, passing subsets. The four-path contract is the NCNN release coverage claim; the subset contracts do not add unlisted parser, Vulkan, or custom-fallback coverage.

Each verified contract is limited to its pinned revisions, declared build configuration, local fixture domain, listed entrypoints, and listed dimensions.

## Review Boundaries

The following remain `REVIEW` and must not be presented as completed verification:

- ORT `rnn_narrowing_scoped_contract`: valid scoped CPU contract but `REVIEW`; inventory and full-provider negative rejection remain incomplete.
- ORT full RNN shape/narrowing behavior, including a full-provider oversized-dimension malicious witness.
- NCNN Vulkan and custom CPU fallback paths.
- Non-CPU providers and unlisted configuration matrices.
- Real sensor, DDS/ROS message, actuator, and robot-control execution.
- Universal correctness and formal proof.

## Embodied-AI Semantics

The profile in `examples/embodied_ai_profile.json` records input source, runtime stage, hardware dependency, failure mode, control impact, and repair constraints. A current `control_impact=indirect` label means a runtime boundary can affect a later embodied pipeline but was not run against a control interface.

`examples/agibot_jointcmd_callback_static_review.json` is a source-hash-bound review of the real AGIBOT `DcuDriverModule::JointCmdCallback` path. It identifies missing parallel-array length contracts before the static `SetMitCmd` control boundary. Its evidence level is `STATIC_ONLY` and verdict is `REVIEW`: it is neither an upstream repair pair nor fake-sink or real-actuator runtime evidence.

`examples/agibot_jointcmd_fake_sink_runtime_evidence.json` records a one-malicious/one-benign local fake-sink simulation of the required command-vector rejection policy. It is `LOCAL_REDUCED_FAKE_SINK`, not AGIBOT/AimRT production runtime and not an asset contract gate. `examples/agibot_jointcmd_source_slice_plan.json` hashes the exact production source anchors and defines the future callback-to-local-fake-sink materialization boundary; its `REVIEW` status records the absent standalone AGIBOT build manifest/type materialization and no official repair pair.
`examples/evaluation_manifest.json` defines the reproducible comparison plan. `examples/baseline_environment_probe.json` records the Windows-host absence of cppcheck, Semgrep, CodeQL, CMake, Ninja, and a C/C++ compiler, plus the AGIBOT snapshot's missing CMake/package metadata. Local WSL separately provides the pinned ORT C++ executor; its availability does not supply an AGIBOT standalone build manifest. Only cwe-repair's local artifacts are marked measured; cppcheck, Semgrep, and CodeQL remain `pending-environment` until normalized commands and result mappings are recorded.

## Release Rule

`ASSET_SCOPE_COMPLETE` means all required evidence gates passed for the declared scope only. `REVIEW` is the required result whenever a declared gate, path, dimension, runtime witness, provider, or safety condition is incomplete. Release audit discovers every `examples/*_asset_contract.json`, `examples/*_semantic_contract.json`, and `examples/*_scoped_contract.json` semantic contract, deliberately excluding matrices, evidence artifacts, and audit records; it fails closed if that discovered set differs from its declared expected-verdict inventory.
