# Contract Schema / Contract 结构

## 中文说明

一个 contract 是绑定一个 pinned asset 与一个显式声明验证范围的标准化 JSON record。它必须记录 asset identity、case、official source、精确 base/head revisions，并且 `universal_claim=false`、`formal_proof=false`。`declared_scope` 必须声明 providers、targets、configurations、input domains；inventory 必须说明枚举方法、source basis、外部边界、可达 sink、已声明 path 与未验证项。

Asset gate 包括 official provenance、source scope、inventory completeness、reproducibility 和 safety。Path gate 包括 static contract、symmetry、detect、repair plan、paired build、preimage witness、runtime head、negative rejection、benign preservation。detect evidence 必须使用 `evidence_role=detector`，repair plan evidence 必须使用 `evidence_role=repair_plan`。`ASSET_SCOPE_COMPLETE` 仅在声明范围内全部 gate/dimension 通过时成立；`REVIEW` 是任何未闭合声明 gate 的必需 fail-closed 结果；`artifact_integrity=true` 只表示文件、hash、case ID 和 assertions 可复核。

## English

A contract is a normalized JSON record for one pinned asset and one explicitly declared verification scope.

## Required Asset Fields

```text
asset_id, case_id, asset_kind, scope_type, official_source
universal_claim=false, formal_proof=false
revisions.base, revisions.head
```

`scope_type` is `single-asset-declared-contract`. `revisions` contains exact distinct 40-character commits.

## Scope and Inventory

`declared_scope` must contain non-empty lists for `providers`, `targets`, `configurations`, and `input_domains`.

`inventory` must state `enumeration_method`, `source_basis`, `external_boundaries`, `reachable_sinks`, `declared_path_ids`, and `unverified`. The inventory must not claim PASS while `unverified` is non-empty.

## Gates

Asset gates:

```text
official_provenance
source_scope
inventory_completeness
reproducibility
safety
```

Path gates:

```text
static_contract
symmetry
detect
repair_plan
paired_build
preimage_witness
runtime_head
negative_rejection
benign_preservation
```

`detect` evidence must declare `evidence_role=detector`. `repair_plan` evidence must declare `evidence_role=repair_plan`.

Runtime gates require complete ratios such as `4/4` and `infrastructure_failures=0`. A preimage witness must demonstrate unsafe base behavior and incomplete malicious rejection; a passing base test alone is not a preimage witness.

## Verdicts

- `ASSET_SCOPE_COMPLETE`: every required asset, path, and dimension gate passes for the declared scope.
- `REVIEW`: the artifacts are structurally usable but one or more declared gates remain incomplete.
- `artifact_integrity=true`: files, hashes, case IDs, and assertions are valid; this does not imply scope completeness.

The verdict never means all inputs, providers, configurations, deployments, or robot behaviors are verified. Both `universal_claim` and `formal_proof` must remain false.
