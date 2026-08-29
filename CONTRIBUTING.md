# 贡献指南 / Contributing

## 中文说明

提交 Pull Request 前，请把变更限制在声明的 asset、path、provider、configuration 和 input domain 内；不要修改 pinned upstream source 来制造 evidence；不要加入 credentials、private endpoint、设备配置或 binary build output。运行 `python tools/validate_release.py` 验证公开发布包；拥有本地研究 corpus 时，再运行 skill README 中的开发 regression 与 release audit。

`REVIEW` 是有效且经常必需的结论。只有全部声明 gate 具备可读、hash-consistent、case-consistent evidence，且 scope/safety boundary 明确时，才可将 contract 升级为 `ASSET_SCOPE_COMPLETE`。PR 应说明 CWE、asset、path、source revision、变更 evidence、验证命令、剩余缺口和任何 claim boundary 变化。

## English

## Before Opening a Pull Request

1. Keep changes scoped to the declared asset, paths, providers, configurations, and input domains.
2. Do not modify pinned upstream source to manufacture evidence.
3. Do not add credentials, private endpoints, device configuration, or binary build outputs.
4. Run `python tools/validate_release.py` for a clean public clone. Run the broader development regression only when its optional local research corpora are available.

## Evidence Rules

`REVIEW` is a valid and often required result. A change may promote a contract to `ASSET_SCOPE_COMPLETE` only when every declared gate is supported by readable, hash-consistent, case-consistent evidence and all scope and safety boundaries remain explicit.

## Pull Request Content

Describe the affected CWE, asset, path, source revision, evidence added or changed, validation commands, remaining gaps, and any claim boundary that changed.
