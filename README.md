# Java Code Audit Platform

面向 Java 17 Maven 项目的个人 Web 代码审计工具。用户上传源码 ZIP 或提供 SVN 当前快照地址后，平台在本机编排多个扫描器，统一归类、分级、去重并导出 HTML、JSON、SARIF、SBOM 和原始证据。

> 当前状态：V1 已完成。Quick、Standard、Deep、ZIP/SVN、并发调度和统一报告已在 macOS ARM64 与 Ubuntu 22.04 x86_64 通过真实介质验收；详见 [V1 验收标准](docs/v1/acceptance-criteria.md) 和 [验收证据索引](docs/v1/acceptance-evidence.md)。

## V1 形态

```text
Java 17 Spring Boot JAR
  + 可再分发扫描工具（锁定脚本组装进介质）
  + 外部 YAML 配置
  + 文件任务目录
```

- 不依赖 IDEA、数据库、Redis、MQ、Docker 或 Kubernetes；
- JDK 17 和 Maven 3.9+ 由运行环境预装；
- 扫描器由 Java `ProcessBuilder` 作为本地子进程调用；
- macOS ARM64 是本机开发和最高优先级验收环境；
- Ubuntu 22.04 x86_64 是 Linux 发布和自动验收环境；
- V1 不使用 AI。

## 九组审计能力

| 能力 | 主要工具 |
| --- | --- |
| Java 潜在 Bug、空指针、异常和并发 | SpotBugs、PMD |
| Java Web 漏洞与污点分析 | FindSecBugs、Semgrep CE、CodeQL |
| 代码规范 | Checkstyle、PMD |
| 依赖漏洞 | Dependency-Check、OSV-Scanner、Trivy |
| 密钥与敏感信息 | Gitleaks、Trivy |
| 重复与可维护性 | PMD CPD、PMD |
| Maven 依赖和构建治理 | Maven Dependency Plugin、Enforcer |
| SBOM、许可证和供应链 | CycloneDX、Trivy |
| 配置与 IaC | Trivy |

详细范围见[能力矩阵](docs/v1/capability-matrix.md)。Error Prone 和 NullAway 不进入 Java 17 V1。

## 扫描档位

- `QUICK`：Gitleaks、Semgrep、PMD、CPD、Checkstyle、Trivy Repository；不依赖 Maven 构建成功。
- `STANDARD`：默认档位；Quick + Maven `-DskipTests package` + SpotBugs/FindSecBugs、依赖检查、Maven治理、SBOM和产物扫描。
- `DEEP`：Standard + 本地安装且通过使用资格检查的 CodeQL。

## 安全边界

V1 直接在宿主机运行 Maven。跳过测试并不能阻止 Maven 插件和构建生命周期执行代码，因此只能扫描维护者信任且有权分析的项目，并部署在个人机器或可信网络。它不是接收任意公网恶意上传的沙箱。

## 当前仓库结构

```text
backend/
  audit-api/           REST、任务索引、恢复与扫描集成
  finding-core/        统一 Finding、指纹、分级、去重与脱敏
  scan-orchestrator/   YAML 扫描计划、公平 DAG 和资源许可
  local-process-runner/安全本地进程、Maven、超时/取消
  scanner-adapters/    扫描器命令和 Parser 适配层
  report-service/      HTML、JSON、SARIF、manifest 与归档
config/
  profiles/           Quick/Standard/Deep目标配置
  rules/              规则与抑制配置
docs/v1/              冻结产品、架构、开发和验收规范
tools/                工具分发与本地安装约定
```

目标模块结构见[总体架构](docs/v1/architecture.md)。

## 本地构建

要求：JDK 17、Maven 3.9+。

本机 Homebrew 示例：

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@17
./mvnw clean verify
./scripts/build-semgrep-pack.sh darwin-arm64
./scripts/build-quick-tool-pack.sh darwin-arm64
./scripts/build-standard-analysis-pack.sh
./scripts/build-standard-supply-tool-pack.sh darwin-arm64

export AUDIT_SEMGREP_EXECUTABLE="$PWD/tools/downloads/tool-pack/darwin-arm64/semgrep/semgrep/bin/semgrep"
export AUDIT_QUICK_TOOL_ROOT="$PWD/tools/downloads/tool-pack/darwin-arm64/quick"
export AUDIT_STANDARD_ANALYSIS_ROOT="$PWD/tools/downloads/tool-pack/common/standard-analysis"
export AUDIT_STANDARD_SUPPLY_ROOT="$PWD/tools/downloads/tool-pack/darwin-arm64/standard-supply"
export AUDIT_VULNERABILITY_DATA_ROOT="$PWD/data/databases"
./mvnw -pl backend/audit-api -am spring-boot:run
```

Standard 还要求先通过 `bin/update-vulnerability-data.sh`（发布包）或
`scripts/update-standard-vulnerability-data.sh`（源码树）初始化 Dependency-Check、Trivy 和
Trivy Java 数据库；缺库时 Standard 会明确显示不可用，不会把缺库解释成零漏洞。

Deep 使用本机 CodeQL，且必须显式记录授权和条款确认：

```bash
export AUDIT_CODEQL_ENABLED=true
export AUDIT_CODEQL_TERMS_ACCEPTED=true
```

当前可用 `POST /api/v1/scans/zip` 执行 Quick、Standard 或受控 Deep 扫描；进度、引擎、Finding、取消、删除和报告下载接口见 [API 契约](docs/v1/api-contract.md)。

## 核心文档

- [V1 文档入口](docs/v1/README.md)
- [产品范围](docs/v1/product-scope.md)
- [决策登记册](docs/v1/decision-register.md)
- [总体架构](docs/v1/architecture.md)
- [开发计划](docs/v1/development-plan.md)
- [Worktree策略](docs/v1/worktree-strategy.md)
- [测试策略](docs/v1/testing-strategy.md)
- [验收标准](docs/v1/acceptance-criteria.md)
- [验收证据索引](docs/v1/acceptance-evidence.md)
- [早期代码审计组件调研](docs/code-audit-capabilities.md)（背景资料，非V1规范）

## 许可证

本项目采用 [Apache License 2.0](LICENSE)。第三方扫描器继续受各自许可证约束。只有完成许可复核且允许再分发的工具才会由锁定版本/SHA256的脚本组装进公开介质；CodeQL CLI 不进入仓库或公开介质。
