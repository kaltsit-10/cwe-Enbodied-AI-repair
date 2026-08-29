# v0.1.0-research：基于 Artifact 的修复保障原型 / Artifact-Backed Repair Assurance Prototype

## 中文说明

本版本发布 cwe-repair 作为选定 C/C++ AI runtime 与具身智能组件的防御性研究 artifact。它包括 DSH skill 与 portable CLI、检测、可审阅 repair plans、对称性检查、双向验证、hash-bound semantic contracts 和 fail-closed release audit。选定 NCNN parser paths 与 ORT SafeMul helper 在声明范围内闭合；ORT full RNN 与 narrowing scoped 保持 `REVIEW`。AGIBOT callback 为 source-bound static review，local fake-sink 为有限 policy evidence。它不验证真实机器人、ROS2/AimRT、DDS、CAN、物理执行器或 production callback runtime，也不主张 universal/formal proof 或外部工具对比。

公开 clone 后运行 `python tools/validate_release.py` 验证发布 artifact。

## English

This release publishes cwe-repair as a defensive research artifact for selected C/C++ AI-runtime and embodied-AI components.

## Included

- DSH skill integration and a portable CLI.
- Detection, reviewable repair plans, symmetry checking, and paired malicious-rejection/benign-preservation verification utilities.
- Hash-bound semantic contracts and a fail-closed release audit.
- Declared-scope closed artifacts for selected NCNN parser paths and the ORT SafeMul helper.
- Source-bound AGIBOT callback static review and bounded local fake-sink policy evidence.

## Explicit Boundaries

- `ASSET_SCOPE_COMPLETE` applies only to each explicitly declared asset scope.
- ORT full RNN and ORT RNN narrowing scoped contracts remain `REVIEW`.
- AGIBOT static review is `STATIC_ONLY`; local fake-sink evidence is `LOCAL_REDUCED_FAKE_SINK`.
- This release does not validate real robots, ROS2/AimRT, DDS, CAN, physical actuators, or production AGIBOT callback runtime.
- This release makes no universal, formal-proof, or external-baseline comparison claim.

Run `python tools/validate_release.py` after cloning to verify the public artifact.
