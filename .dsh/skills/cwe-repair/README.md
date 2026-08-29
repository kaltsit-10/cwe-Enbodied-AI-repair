# cwe-repair — 防御性输入校验与修复验证研究原型（DSH skill）

防御侧研究原型：以 C/C++ 特定 CWE 类型（越界读写、整数溢出、除零）为核心，并包含少量 Python/逻辑类实验规则的
**检测 → 修复建议 → 双向验证**流程。以 DSH skill 形式提供（`SKILL.md` + `scripts/`），
模型在会话中通过 `skill` 工具按需加载并调用脚本。

## 五阶段流水线

| 阶段 | 脚本 | 作用 |
|---|---|---|
| 0 可达性 | `scripts/cwe_reach.py` | 标注默认可达性（default/config/local/model-file），agibot 实时读 YAML |
| 1 检测 | `scripts/cwe_detect.py` | 规则模板扫描 CWE-125/787/190/369/476 模式，低误报优先，JSON 输出 |
| 2 对称性 ⭐ | `scripts/symmetry_check.py` | **修复不对称检查**：成对入口（text/bin、兄弟函数）一处有守卫一处无 → 提交前拦截 bot 多轮迭代 |
| 3 修复 | `scripts/cwe_repair.py` | 按 CWE 模板生成补丁（补一行检查），unified diff 输出 |
| 4 验证 ⭐ | `scripts/cwe_verify.py` | **双向回归**：恶意输入必须被拒 + 合法输入必须不误拒 → PASS/REVIEW |

## 为什么需要对称性检查（symmetry_check）

**实测案例**：ncnn PR #6922 曾被 Codex bot 打回 2 次 P1（[PR 6922 reviews](https://github.com/Tencent/ncnn/pull/6922)）：
1. P1@net.cpp:31：资源上限只加了 text 路径，**bin 路径（load_param_bin）没应用**
2. P1@net.cpp:1406：`top_count==0` 除零守卫不完整（text/bin 两处）

两者共同根因 = **修复不对称**（同一校验只打了一个入口）。symmetry_check 在提交前检测：
- 场景 A（只修 text 不修 bin）→ ⚠️ 报不对称 ✅（本工具实测）
- 场景 C（text+bin 都修）→ ✅ 对称良好（无误报）
- AimRT json_convert（WriteMember 有守卫 / WriteMemberNested 没有）→ ⚠️ 报不对称 ✅

```bash
python scripts/symmetry_check.py <src_dir> --file <目标文件>
# 输出: ⚠️ 不对称: load_param 有守卫, 但 load_param_bin 没有 → 修复未覆盖兄弟路径
```

## 快速开始

```bash
# 1) 检测
python .dsh/skills/cwe-repair/scripts/cwe_detect.py <目标> --cwe 125,787,190,369

# 2) 修复（人工审阅后 git apply）
python .dsh/skills/cwe-repair/scripts/cwe_repair.py \
    --file <源文件> --line <行号> --cwe 787 \
    --idx bottom_blob_index --size blob_count --log ncnn --out fix.patch

# 3) 验证（核心：证明修复有效且无误伤）
python .dsh/skills/cwe-repair/scripts/cwe_verify.py \
    --binary <修复版可执行> \
    --malicious "poc1.parambin poc2.parambin" \
    --benign "valid1.param valid2.param" --asan

# 4) 本地 patch 适配证据（在隔离临时树中，不改原源码）
python .dsh/skills/cwe-repair/scripts/repair_evidence.py \
    --source <本地源码文件> --patch <本地.patch> --target-path src/<目标文件> --json
```

`forward_applicable=true` 表示 patch 可应用到映射后的本地前像；`reverse_applicable=true` 表示当前本地快照与 patch 后像相容。两者都是静态来源证据，默认仍为 `REVIEW`，不能替代双向运行验证。

若需证明一个本地 fragment patch 已被合并 patch 吸收，可检查新增行子集：

```bash
python .dsh/skills/cwe-repair/scripts/repair_evidence.py \
    --container-patch <合并.patch> --fragment-patch <子.patch> --json
```

`addition_subset=true` 只证明补丁组成关系，不证明完整源码语义或运行时修复。

## 目录

```
.dsh/skills/cwe-repair/
├── SKILL.md                      # DSH skill 入口（frontmatter: name/description/whenToUse）
├── scripts/
│   ├── cwe_detect.py             # 阶段1 检测器
│   ├── cwe_repair.py             # 阶段2 补丁生成器
│   └── cwe_verify.py             # 阶段3 双向验证器（核心差异化）
└── examples/
    └── ncnn_blobidx_verify.json  # NCNN blob 漏洞真实验证配置（WSL 恢复后可用）
```

## 与其他工具的区别

- **检测**：规则模板聚焦本项目实证模式（平行数组不互检、外部输入直接索引等），
  比 CodeQL/cppcheck 的通用规则更贴近具身智能组件漏洞形态，低误报优先；
- **修复**：模式化补丁（确定性、可审阅），区别于纯 LLM 生成的不可控补丁；
- **验证**：⭐ 现有工具（回归测试/静态 oracle/LLM 判别）都不做的闭环——
  恶意 PoC 必须被拒 + 合法输入不误拒，用真实退出码/ASan 实证。

## 通用核心与 DSH Adapter

DSH skill 是 `cwe-repair` 的首个编排 adapter，不是工具边界。无需 DSH 时，可通过可移植 CLI 调用同一核心脚本：

```powershell
python .dsh\skills\cwe-repair\scripts\cwe_repair_cli.py detect <target> --cwe 125,787
python .dsh\skills\cwe-repair\scripts\cwe_repair_cli.py contract --contract <contract.json> --json
python .dsh\skills\cwe-repair\scripts\cwe_repair_cli.py release-audit --json
```

`embodied_ai_profile.json` 是领域 profile；以后 CI、IDE 或其他 agent adapter 可以复用 CLI、JSON contracts 和 profile validator，而不依赖 DSH 会话。架构边界见 [CORE_ARCHITECTURE.md](CORE_ARCHITECTURE.md)。

## 发布语义复核

发布级 scope、已验证 contracts 和明确的 `REVIEW` 边界见 [RELEASE_SCOPE.md](RELEASE_SCOPE.md)。Schema 和 evidence level 定义见 [CONTRACT_SCHEMA.md](CONTRACT_SCHEMA.md) 与 [EVIDENCE_LEVELS.md](EVIDENCE_LEVELS.md)。

```powershell
python .dsh\skills\cwe-repair\scripts\release_audit.py --json
python .dsh\skills\cwe-repair\scripts\test_cwe_repair.py
```

`ASSET_SCOPE_COMPLETE` 仅表示一个 pinned asset 的声明 provider、target、configuration、input domain、path 和 dimension 已闭合；它不是全项目、全输入、全 provider 或形式化证明。release audit 同时 fail-closed 校验具身 profile、候选 queue/registry 一致性、保护 artifact 哈希与敏感文件。具身智能部署语义和 fail-closed 修复限制见 `examples/embodied_ai_profile.json`。

## 当前边界与迭代方向

当前版本可作为 **artifact-backed repair-assurance 研究原型** 发布：DSH skill 是首个编排 adapter，同时可通过 portable CLI、JSON contracts 与 validators 脱离 DSH 使用。发布 audit 通过的已声明范围包括 NCNN 的三个 parser/path contracts 和 ORT SafeMul helper；完整清单与未闭合 contract 以 `release_audit.py --json` 的实际输出为准。

已具备的具身智能证据分为两层：AGIBOT `DcuDriverModule::JointCmdCallback -> XyberController::SetMitCmd` 有 source-hash-bound 静态审查；平行 command arrays 的 fail-closed 策略有恶意拒绝和合法保留的 local fake-sink 双向模拟。ORT 也有 pinned base/head `onnxruntime_provider_test` 上一条有限 RNN control 的 paired benign runtime evidence。上述证据均有明确 scope，不互相替代。

不得将当前结果表述为真实机器人、ROS2/AimRT、DDS、CAN 或执行器 runtime 验证；不得表述为 AGIBOT production callback 已修复；不得将 `LOCAL_REDUCED_FAKE_SINK` 视为 `ASSET_SCOPE_COMPLETE` runtime gate；不得宣称 all-input/all-provider/all-configuration 覆盖、formal proof 或相对 cppcheck/Semgrep/CodeQL 的性能优势。ORT full RNN 与 ORT RNN narrowing scoped contract 继续保持 `REVIEW`，其 missing gates 是正式发布结果的一部分。

下一轮可复现迭代优先级：

1. 将 AGIBOT plan materialize 为不连接 ROS/DDS/CAN/执行器的 C++ source slice，直接调用真实 callback 逻辑并注入 local fake controller sink，保留 base/head 与双向 runtime evidence。
2. 在具备工具的环境中固定 cppcheck、Semgrep、CodeQL 的版本、命令、finding mapping 和 corpus，报告真实 precision、recall、F1、runtime cost 与 guarded false-positive rate；在此之前 comparative claim 必须保持 unavailable。
3. 为 ORT RNN 搜索不触发大分配的、可归因的 full-provider negative witness；如果不存在，保留 `REVIEW`，不以 helper 或有限 benign control 替代 negative rejection。
4. 将 portable CLI 整理为 versioned package/API/schema，并为 CI、IDE 和其他 agent adapter 提供稳定集成点。

## 边界与纪律

- 防御侧工具：不生成利用代码，不研究 RCE 利用链；
- 修复必须验证：未跑 verify 的补丁视为未完成；
- WSL launcher/宿主失败会标记为 `infra_error`，不能作为恶意输入被拒绝的证据；
- 生成补丁须人工审阅后套用；
- detect 命中后若已有守卫，标注 false-positive 跳过。

## 测试记录（2026-08-22）

### v1（初版）
- detect：对 AimRT `json_convert.h`（AR-1 漏洞）命中 L170（真实越界写点），7 命中中 6 个为有守卫的正常代码；
- repair：对 AR-1 生成 `array_size_` 边界检查补丁（与人工修复思路一致）；
- verify：模拟测试——修复版 → PASS（恶意 exit=1 拒绝 + 合法 exit=0）；漏洞版 → REVIEW（恶意 exit=139 崩溃被捕获）。

### v2（误报过滤器增强）
- 新增过滤规则：map 赋值语义（`map[key]=`）、map.at 返回值作下标（X1-9 模式，**保留**）、
  边界守卫（`if idx<0||idx>=size`、等长检查 `==size()`、throw exceeded）、成员遍历（members_/typeinfo）、
  resize 后索引；
- **效果**：AR-1 json_convert.h 命中 7 → 2（L170 真实漏洞保留，安全循环过滤）；
  X1-9 controller_base.cc L21-23 保留；X1-10 除零 L154 保留；
- 使用 `--no-filter` 可关闭过滤看原始命中。

### v3（可达性标注）
- 新增 `cwe_reach.py`：5 组件默认可达性规则表 + agibot YAML 实时读取；
- 端到端验证：detect(X1-9 L21-23) JSON → reach 标注 `config-reachable`（与攻击面调研一致）。

### v4（CWE-248 扩展 + 覆盖度分析）
- detect/repair 新增 CWE-248（未捕获异常：`.at()` → `find()` 模板），命中 X1-8 L113；
- 新增 `coverage_analysis.py`：对 34-finding 数据集的工具覆盖度分析；
- **覆盖度：全自动闭环 23/34（67%）**——AimRT 4/4、AGIBOT 12/14、NCNN 5/7；
  未覆盖 = 逻辑类（CWE-306/502/78 认证/反序列化/注入，需不同模板）；
- 回归测试：AR-1 L170 / X1-9 L21 / X1-10 L154 全部保留。

### v5（真实 NCNN 二进制验证 ✅ 2026-08-22 WSL 实测）
- **修复版 PASS**：恶意 149B/negidx → `ret=-1` 拒绝（exit=0）；合法 valid_minimal → `ret=0`（exit=0）
- **漏洞版 REVIEW**：恶意 149B → SIGSEGV（exit=-11）；negidx → SIGABRT（exit=-6）
- **验证器判定逻辑在真实环境修正**：
  1. `ret=-1` 输出在 **stderr**（需合并捕获，仅 stdout 会漏）
  2. 进程被信号终止时 returncode 为**负信号码**（-11=SIGSEGV/-6=SIGABRT），crashed 判定需含负值
  3. "合法输入"选择须用**同版本格式兼容**的真实合法样本（squeezenet 旧格式报 "param is too old" 非误拒）
- 方法论收获：**真实环境验证暴露了模拟测试不会暴露的语义差异**（exit code vs ret 输出 vs 信号码）——这正是"修复必须真实验证"的理由

### v6（漏洞驱动的工具迭代 ✅ 2026-08-22，MNN 扫描驱动）
- **detect 新增 `size_truncation` 模式**：检测 `(int)size_t` 显式截断（MNN FileLoader::merge
  L130 `buffer.reset((int)mTotalSize)` 漏洞驱动——>2GB 文件截断 → 分配不足 → memcpy 越界写）
- **repair 新增 `190_trunc` 模板**：截断前校验 `src > INT_MAX` 则拒绝，再安全转换（防御性编程）
- 完整闭环验证：MNN 扫描 → 发现截断漏洞 → 扩展模式 → 生成鲁棒补丁 → 回归全过
  （AR-1 L170 / X1-9 L21 / MNN L173 / MNN L130 全部保留）
- 外部组件扫描结论（负面结果对照）：
  - onnxruntime v1.28.0：核心解析器有维度/溢出/负数全查 → 无新漏洞
  - Paddle-Lite：CHECK 断言保护 → 无新漏洞
  - 结论：工具在"已加固大厂解析器"无误报过多，在"未加固中小组件"高产出
- ⭐ **新漏洞发现**：`size_truncation` 模式在 MNN 发现第二处截断漏洞
  `Interpreter::createFromBuffer`（L107 `(int)size` 截断 + 按原 size memcpy → 越界写，
  公开 API 入口）——详见 `TOOLTEST_MNN/MNN-Interpreter截断漏洞-2026-08-22.md`

### v7（leaderboard 基准化 + 跨行匹配 ✅ 2026-08-22）
- **新增 `cwe_leaderboard.py`**：对 34-finding 数据集跑 detect，输出检出率基准（RepairBench 思路）
- **跨行匹配改进**：`parallel_array_loop`/`alloc_then_read` 从单行改为前 6 行窗口
  → X1-4/X1-5/X1-6 等平行数组漏洞首次被检出（原单行无法跨 for 头）
- **CWE 同族匹配**：125/787 视为可匹配（越界读写常同源）
- **基准驱动迭代成果**：检出率 32% → **48%**（15/31），全程由 leaderboard 暴露问题驱动
- 同时发现 MNN Interpreter::createFromBuffer 截断新漏洞（v6 模式 + 跨行扫描）

### 待办
- （无阻塞项；真实验证已完成）

## English Guide

`cwe-repair` is a defensive research prototype for selected C/C++ CWEs. Its workflow is reachability annotation, detection, symmetry review, reviewable repair-plan generation, and paired verification. Paired verification requires malicious inputs to be rejected and benign inputs to be preserved; a patch without the applicable verification evidence remains incomplete.

The DSH skill is the first adapter, while `scripts/cwe_repair_cli.py`, JSON contracts, validators, and evidence artifacts are portable integration points for terminals and future CI/IDE adapters. `ASSET_SCOPE_COMPLETE` is deliberately narrow: it applies only to an explicitly declared pinned asset scope. `REVIEW` is the mandatory result for missing provenance, inventory, path, dimension, build, runtime, negative-rejection, benign-preservation, provider, or safety evidence.

This release includes declared-scope closed NCNN parser contracts and an ORT SafeMul helper contract. ORT RNN contracts intentionally remain `REVIEW`. AGIBOT callback evidence is source-bound static review plus a bounded local fake-sink policy simulation; it is not production ROS2/AimRT, DDS, CAN, robot, or actuator validation. See `RELEASE_SCOPE.md`, `CONTRACT_SCHEMA.md`, `EVIDENCE_LEVELS.md`, and the repository-root README for the complete bilingual release boundary and next iterations.
