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
- `build-dependency-check-smoke-data.sh`：为 Mac/Linux acceptance 构建仅含 NVD 2021 数据的 Dependency-Check Log4Shell smoke 库。该库故意不完整，脚本会写入禁止生产使用标记；依赖 JDK 17、Dependency-Check 12.2.2、`curl`、`python3`、`gzip` 和标准 POSIX 文本工具。
- `update-standard-vulnerability-data.sh`：使用独占锁在临时目录更新 Dependency-Check/Trivy 数据，完整性检查通过后再原子切换；OSV V1 默认使用在线 API。

平台工具包布局为 `tools/downloads/tool-pack/{platform}/{quick|standard-supply}/{tool}`，
公共 Java 分析工具位于 `tools/downloads/tool-pack/common/standard-analysis/{tool}`。每个工具根目录都有
`pack-metadata.json`，记录版本、启动模式、入口、入口 SHA256、官方来源和许可证。

## Dependency-Check acceptance smoke 数据

Ubuntu 22.04 x86_64 CI 需要 JDK 17、Dependency-Check 12.2.2、`curl`、`python3`、`gzip`
以及 Ubuntu `coreutils`/`grep`/`awk`。脚本本身不需要 `jq`；如需从仓库现场组装
`standard-supply` 工具包，还需要 `unzip`。显式确认构建不完整验收数据：

```bash
JAVA_HOME=/path/to/jdk-17 \
PATH=/path/to/jdk-17/bin:/usr/bin:/bin \
AUDIT_ACCEPT_INCOMPLETE_SMOKE_DATA=YES \
AUDIT_DEPENDENCY_CHECK_EXECUTABLE="$PWD/tools/downloads/tool-pack/linux-x86_64/standard-supply/dependency-check/dependency-check/bin/dependency-check.sh" \
AUDIT_DEPENDENCY_CHECK_SMOKE_DATA="$PWD/tools/downloads/databases/dependency-check-smoke" \
scripts/build-dependency-check-smoke-data.sh
```

脚本会执行以下受控流程：

1. 从 NVD 官方 2.0 feed 下载 2021 `meta` 和 `json.gz`；
2. 按 `meta` 校验 gzip 大小、解压后大小和解压后 SHA256，并确认 feed 包含 `CVE-2021-44228`；
3. 为 2002 至当年的其他年份及 `modified` 生成合法空 feed/meta，用只监听 `127.0.0.1`
   的临时 HTTP 服务交给 Dependency-Check 初始化；
4. 构造带 Maven PURL 元数据的 Log4j 2.14.1 验收 JAR，用生成数据库真实扫描；
5. 只有报告同时出现精确 PURL、`CVE-2021-44228` 和数据源证据才原子激活输出目录。

生成目录会包含 `ACCEPTANCE-ONLY.txt` 和 `productionUseProhibited=true` 元数据。
它故意只覆盖 2021 年，**绝对不能用于生产、安全结论或真实代码审计**。
