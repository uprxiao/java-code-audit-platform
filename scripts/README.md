# Scripts

本目录只存放可审查、可重复的本地开发和验证脚本。生产扫描命令应由 Runner 的类型化任务定义生成，不接受用户提供的任意 Shell 字符串。

- `build-semgrep-pack.sh`：在本机组装带受控 Python 运行时的 Semgrep 工具包；
- `build-quick-tool-pack.sh [darwin-arm64|linux-x86_64]`：按官方资产和锁定 SHA256 组装 Gitleaks、PMD/CPD、Checkstyle 和 Trivy；
- `run-quick-tools-smoke.sh`：通过真实 Mac/Linux 工具运行五个新增 Quick 适配器的最小扫描。
- `build-standard-analysis-pack.sh` / `run-standard-analysis-smoke.sh`：组装并真实验证 SpotBugs、FindSecBugs、Maven Dependency Analysis 和 Enforcer；Java 工具包跨平台共用。
- `install-codeql-local.sh`：按官方 SHA256 在 gitignored `tools/local/` 安装 CodeQL CLI 和锁定 Java query pack；不把 CodeQL 放入仓库或发布介质。
- `run-codeql-deep-smoke.sh`：使用显式 JDK 17、服务器 Maven、本地 CodeQL CLI 和锁定 query suite 执行真实 Apache-2.0 Java/Maven Deep 污点烟测。
- `build-distribution.sh <darwin-arm64|linux-x86_64> [version]`：构建 class major 61 的单 JAR介质，复制当前平台工具，生成 SHA256/manifest，并用保留 Unix 权限的 ZIP 输出到 `dist/`。
- `build-standard-supply-tool-pack.sh [darwin-arm64|linux-x86_64]`：组装 Dependency-Check、OSV-Scanner 和 CycloneDX 插件元数据，Trivy 复用 Quick 工具包中的同一固定二进制；
- `run-standard-supply-smoke.sh`：在 JDK 17 上真实运行 CycloneDX、OSV 和 Trivy Artifact 扫描，并验证 Dependency-Check CLI 运行时。
- `update-standard-vulnerability-data.sh`：使用独占锁在临时目录更新 Dependency-Check/Trivy 数据，完整性检查通过后再原子切换；OSV V1 默认使用在线 API。

工具包统一布局为 `tools/downloads/tool-pack/{platform}/{quick|standard}/{tool}`，每个工具根目录都有
`pack-metadata.json`，记录版本、启动模式、入口、入口 SHA256、官方来源和许可证。
