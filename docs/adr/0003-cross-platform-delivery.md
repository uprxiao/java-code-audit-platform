# ADR-0003：Mac ARM64开发验收与Linux x86_64发布双平台

- 状态：Accepted
- 日期：2026-08-12

## 背景

主要开发和使用机器是macOS ARM64；正式部署目标是Ubuntu 22.04 LTS x86_64、glibc2.35。Java JAR和Java工具可以跨平台，但多个扫描器包含原生二进制，Mac通过不能自动证明Linux可用。

## 决策

- 同一JAR、规则、配置和报告Schema用于两端；
- 制作`darwin-arm64`和`linux-x86_64`两个介质；
- 许可允许的原生工具通过Git LFS分别保存；
- CodeQL CLI按平台由用户从官方源本地安装，不入仓库/公共介质；
- macOS ARM64 Quick/Standard/Deep全部真实通过，作为最高优先级硬验收；
- Linux日常CI真实跑Quick/Standard；发布或手工CI真实跑Deep；
- 提供实际Linux服务器验收脚本，但实际执行暂不阻塞V1；
- V1不支持Linux ARM64、Alpine/musl或Windows。

## 影响

- Parser和核心逻辑可复用；
- 工具manifest必须包含平台条目；
- 发布包体积和工具升级测试约翻倍；
- Mac文件系统大小写、Linux权限/信号/glibc差异必须有专门测试；
- CodeQL Apple Silicon当前官方Beta状态进入已知边界。

## 未采用方案

- 只在Mac测试：不能证明部署平台可用；
- 只在Linux CI测试：无法满足首要本机使用场景；
- 一个包含所有平台工具的通用大包：体积更大且容易选错可执行文件。
