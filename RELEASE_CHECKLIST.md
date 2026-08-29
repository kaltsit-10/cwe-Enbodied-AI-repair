# GitHub 发布清单 / GitHub Release Checklist

## 中文说明

上传前：将 `CITATION.cff` 的 `REPLACE_WITH_OWNER` 替换为 GitHub owner；确认 `LICENSE` copyright holder；在根目录运行 `python tools/validate_release.py`；确认没有 credentials、token、私有设备配置、专有 source tree 或 build binary；阅读 `NOTICE` 并确认未复制额外第三方源码。

创建仓库：新建名为 `cwe-repair` 的仓库；short description 使用 `Artifact-backed repair assurance for C/C++ AI-runtime components: detection, repair plans, paired validation, semantic contracts, and embodied-AI safety boundaries.`；上传本目录全部内容，包含隐藏的 `.dsh`、`.github` 和 `.gitignore`；提交信息可用 `chore: publish v0.1.0-research artifact`；确认 GitHub Actions `Validate Research Artifact` 通过。

首个 Release：tag 为 `v0.1.0-research`，标题为 `v0.1.0-research: Artifact-Backed Repair Assurance Prototype`；不附加私有 source tree 或 native binary；release notes 使用 `CHANGELOG.md`、`README.md` 与 `RELEASE_NOTES_v0.1.0-research.md` 中的 boundary 文本。发布后添加 topics、配置私有 security contact，并在接受外部 evidence contribution 前启用 issue templates。

## English

## Before Upload

- [ ] Replace `REPLACE_WITH_OWNER` in `CITATION.cff` with the GitHub owner name.
- [ ] Confirm the copyright holder line in `LICENSE`.
- [ ] Run `python tools/validate_release.py` from the repository root.
- [ ] Confirm no credentials, tokens, private device configuration, proprietary source trees, or build binaries are present.
- [ ] Read `NOTICE` and verify no additional third-party source was copied into the repository.

## Create the Repository

1. Create a new GitHub repository named `cwe-repair`.
2. Set its short description to: `Artifact-backed repair assurance for C/C++ AI-runtime components: detection, repair plans, paired validation, semantic contracts, and embodied-AI safety boundaries.`
3. Upload the contents of this directory, including hidden `.dsh`, `.github`, and `.gitignore` paths.
4. Commit with: `chore: publish v0.1.0-research artifact`.
5. Verify the GitHub Actions `Validate Research Artifact` workflow passes.

## Create the First Release

- Tag: `v0.1.0-research`
- Title: `v0.1.0-research: Artifact-Backed Repair Assurance Prototype`
- Attach no private source trees or native build binaries.
- Use the boundary text from `CHANGELOG.md`, `README.md`, and `RELEASE_NOTES_v0.1.0-research.md` in the release notes.

## After Release

- [ ] Add repository topics: `cwe`, `secure-coding`, `program-repair`, `static-analysis`, `embodied-ai`, `robotics-security`, `onnxruntime`, `ncnn`, `research-prototype`.
- [ ] Configure a private security contact in GitHub repository settings.
- [ ] Enable issue templates before accepting external evidence contributions.
