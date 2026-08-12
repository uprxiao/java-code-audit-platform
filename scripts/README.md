# Scripts

本目录只存放可审查、可重复的本地开发和验证脚本。生产扫描命令应由 Runner 的类型化任务定义生成，不接受用户提供的任意 Shell 字符串。

- `build-semgrep-pack.sh`：在本机组装带受控 Python 运行时的 Semgrep 工具包；
- `build-quick-tool-pack.sh [darwin-arm64|linux-x86_64]`：按官方资产和锁定 SHA256 组装 Gitleaks、PMD/CPD、Checkstyle 和 Trivy；
- `run-quick-tools-smoke.sh`：通过真实 Mac/Linux 工具运行五个新增 Quick 适配器的最小扫描。
- `build-standard-analysis-pack.sh` / `run-standard-analysis-smoke.sh`：组装并真实验证 SpotBugs、FindSecBugs、Maven Dependency Analysis 和 Enforcer；Java 工具包跨平台共用。
- `install-codeql-local.sh`：按官方 SHA256 在 gitignored `tools/local/` 安装 CodeQL CLI 和锁定 Java query pack；不把 CodeQL 放入仓库或发布介质。
- `build-distribution.sh <darwin-arm64|linux-x86_64> [version]`：构建 class major 61 的单 JAR介质，复制当前平台工具，生成 SHA256/manifest，并用保留 Unix 权限的 ZIP 输出到 `dist/`。

工具包统一布局为 `tools/downloads/tool-pack/{platform}/quick/{tool}`，每个工具根目录都有
`pack-metadata.json`，记录版本、启动模式、入口、入口 SHA256、官方来源和许可证。
