# 更新记录 / Changelog

## 中文说明

### v0.1.0-research

首个公开研究 artifact 版本。包含 DSH `cwe-repair` skill、portable CLI、JSON semantic contracts、profile/evaluation/release validators、CWE-focused detect/repair-plan/symmetry/paired verification，以及 NCNN 选定 parser paths 和 ORT SafeMul helper 的声明范围闭合 artifact。ORT RNN narrowing 与 full RNN 保持 `REVIEW`；AGIBOT 仅提供 source-bound static review 和 bounded local fake-sink policy evidence。没有真实机器人、ROS2/AimRT、DDS、CAN、执行器、通用正确性、formal proof 或外部 baseline comparison 声明。

## English

## v0.1.0-research

Initial public research-artifact release.

### Included

- DSH `cwe-repair` skill as the first integration adapter.
- Portable CLI, JSON semantic contracts, profile validation, evaluation manifest, and fail-closed release audit.
- CWE-focused detection, reviewable repair plans, symmetry checks, and paired verification utilities.
- Declared-scope `ASSET_SCOPE_COMPLETE` artifacts for selected NCNN parser paths and the ORT SafeMul helper.
- Explicit `REVIEW` artifacts for ORT RNN narrowing and full RNN coverage gaps.
- AGIBOT source-bound callback static review and bounded local fake-sink policy evidence.

### Boundaries

- No production robot, ROS2/AimRT, DDS, CAN, or actuator execution.
- No claim of universal correctness or formal proof.
- No normalized cppcheck, Semgrep, or CodeQL comparison result.
