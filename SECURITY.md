# 安全策略 / Security Policy

## 中文说明

cwe-repair 是防御性研究工具，不得用于生成 exploit chain、连接真实机器人/执行器/CAN 总线/ROS-DDS 网络或访问外部 target。发现本项目自身安全问题时，不要在公开 issue 中附带 credentials、私有 endpoint、专有源码或可复现 exploit chain；请通过仓库维护者在 GitHub 设置中公布的私密渠道报告。贡献不得包含真实设备配置、token、私有 artifact 或未经审查的第三方源码。任何 `ASSET_SCOPE_COMPLETE` 声明都必须保留声明范围，并提供 hash-bound provenance、source、build、runtime 与 safety evidence。

## English

## Scope

cwe-repair is defensive research tooling. It must not be used to run exploit chains, connect to real robots, actuators, CAN buses, ROS/DDS networks, or external targets.

## Reporting

Do not open a public issue for a suspected vulnerability that includes credentials, private endpoints, proprietary source, or a reproducible exploit chain. Contact the repository maintainer through the private contact channel documented in the GitHub repository instead.

## Contributions

Do not submit real-device configuration, credentials, tokens, private artifacts, or unreviewed third-party source code. Evidence claiming `ASSET_SCOPE_COMPLETE` must preserve the declared scope and include hash-bound provenance, source, build, runtime, and safety evidence.
