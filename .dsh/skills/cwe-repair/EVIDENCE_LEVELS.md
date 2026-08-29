# 证据等级 / Evidence Levels

## 中文说明

证据按声明范围报告，不是通用安全评分。`STATIC_ONLY` 表示源码检测、contract 或 matrix 证据，没有 build/runtime proof；`BUILD_VERIFIED` 表示 pinned source/configuration 已构建；`SCOPED_RUNTIME` 表示有限本地 executor 已运行声明的 filter 或 fixture；`PREIMAGE_VERIFIED` 表示 base 复现不安全行为且 head 在无基础设施故障时拒绝恶意 fixture；`ASSET_SCOPE_COMPLETE` 表示单资产声明范围的全部必需 gate 已通过；`REVIEW` 表示 artifact 结构有效但仍有 gate/dimension 未闭合。

更高等级不覆盖未列出的 provider、configuration、path、input 或真实机器人行为。发布中 `formal_proof=false` 与 `universal_claim=false` 是强制边界。

## English

Evidence is reported by scope, not as a universal security score.

- `STATIC_ONLY`: source detector, contract, or matrix evidence; no build/runtime proof.
- `BUILD_VERIFIED`: pinned source and configuration built successfully; runtime not established.
- `SCOPED_RUNTIME`: bounded local executor ran a declared filter or fixture set.
- `PREIMAGE_VERIFIED`: base reproduces unsafe behavior and head rejects the malicious fixture without infrastructure failure.
- `ASSET_SCOPE_COMPLETE`: every required gate for the declared single-asset scope passes.
- `REVIEW`: evidence is structurally valid but a declared gate or dimension remains incomplete.

A higher level does not imply coverage of unlisted providers, configurations, paths, inputs, or real-robot behavior. `formal_proof=false` and `universal_claim=false` are mandatory release boundaries.
