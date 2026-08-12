# 路线图

## M0：仓库与领域骨架

- Maven 多模块工程；
- ScanJob、ScanPlan、Finding 基础模型；
- Web API 健康检查和任务创建占位接口；
- 架构、安全和流水线文档。

## M1：可用的快速扫描

- ZIP 安全上传；
- SVN 检出；
- Gitleaks、PMD/CPD、Checkstyle、Semgrep、Trivy；
- 引擎状态、原始报告存储；
- HTML/JSON 报告下载。

## M2：Maven 标准扫描

- JDK 版本识别；
- 隔离 Maven 构建；
- SpotBugs + FindSecBugs；
- Dependency-Check、OSV；
- Dependency Plugin、Enforcer；
- CycloneDX 和构建产物 Trivy 扫描。

## M3：深度扫描

- CodeQL Java 数据库与查询包；
- Error Prone 兼容性策略；
- 可选 NullAway；
- 污点路径统一展示。

## M4：质量与使用体验

- 跨引擎去重；
- 基线和忽略策略；
- 增量扫描；
- PDF/Excel 导出；
- 任务配额、取消、保留和清理策略。

## M5：可选 AI Reviewer

- 高危 Finding 解释；
- 误报辅助判断；
- 修复建议和临时补丁验证；
- 不作为扫描成功或风险结论的必要组成部分。
