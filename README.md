# Java Code Audit Platform

面向 Java/Maven 开源项目的 Web 代码审计平台。用户上传源码 ZIP 或提供 SVN 地址后，平台在隔离环境中编排多个成熟扫描引擎，统一收集、归类、去重并导出审计报告。

> 当前状态：项目初始化阶段。仓库先建立可迭代的架构边界和 Maven 代码骨架，扫描器接入将在后续里程碑逐步完成。

## 项目目标

- 一个 Web 入口完成源码提交、任务启动、进度查询和报告下载。
- 覆盖代码质量、潜在 Bug、安全污点、依赖漏洞、密钥泄漏、供应链和配置安全。
- 扫描器保持独立，通过统一编排和 Finding 模型整合结果。
- 明确区分扫描成功、扫描失败、部分完成与真正的零问题。
- 第一阶段不依赖 AI；AI 仅作为后续解释、误报复核和修复建议的可选能力。

## 计划接入的扫描能力

| 审计域 | 引擎 |
| --- | --- |
| Java 潜在 Bug、空指针、并发和资源问题 | SpotBugs、PMD、Error Prone，可选 NullAway |
| Java Web 安全与污点路径 | FindSecBugs、Semgrep、CodeQL |
| 代码规范 | Checkstyle、PMD |
| 依赖漏洞 | OWASP Dependency-Check、OSV-Scanner、Trivy |
| 密钥泄漏 | Gitleaks |
| 重复代码与可维护性 | PMD CPD、PMD |
| Maven 依赖健康 | Maven Dependency Plugin、Maven Enforcer |
| SBOM | CycloneDX Maven Plugin |
| 配置、IaC、产物和许可证 | Trivy |

## 扫描模式

- **快速扫描**：Gitleaks、Semgrep、PMD、CPD、Checkstyle、Trivy Repository；不依赖 Maven 构建成功。
- **标准扫描**：快速扫描 + 隔离 Maven 构建 + SpotBugs/FindSecBugs、依赖检查、SBOM 和产物扫描。
- **深度扫描**：标准扫描 + 许可与使用策略允许时的 CodeQL，以及项目兼容时的 Error Prone/NullAway。

## 仓库结构

```text
backend/
  audit-api/          Web API 与任务入口
  finding-core/       统一 Finding、扫描任务和公共模型
  scan-orchestrator/  扫描计划、状态机和引擎编排
  scan-runner/        隔离执行器（预留）
  report-service/     HTML/PDF/JSON 报告（预留）
web-ui/               Web 前端（预留）
scanner-images/       扫描器镜像与版本清单
config/
  profiles/           quick/standard/deep 扫描配置
  rules/              平台维护的规则、过滤器和抑制配置
docs/                 架构、开发和决策文档
scripts/              本地开发与验证脚本
```

## 本地构建

要求：JDK 17、Maven 3.9+。

```bash
mvn verify
mvn -pl backend/audit-api -am spring-boot:run
```

启动后可访问：

```text
GET  /api/v1/health
POST /api/v1/scans
```

当前 `POST /api/v1/scans` 只创建内存中的任务模型，尚未执行真实扫描。

## 文档

- [代码审计能力全景与组件说明](docs/code-audit-capabilities.md)
- [系统架构](docs/architecture.md)
- [扫描流水线](docs/scanning-pipeline.md)
- [本地开发](docs/development.md)
- [路线图](docs/roadmap.md)
- [ADR-0001：多引擎编排架构](docs/adr/0001-multi-engine-orchestration.md)
- [安全策略](SECURITY.md)
- [贡献指南](CONTRIBUTING.md)

## 许可证

本项目采用 [Apache License 2.0](LICENSE)。各扫描引擎仍受其各自许可证约束，发布镜像或托管服务前需要逐项复核。
