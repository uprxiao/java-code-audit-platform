# 贡献指南

## 开发原则

- 扫描引擎负责确定性检测，平台负责任务编排、证据保存和统一报告。
- 新引擎必须提供版本、执行状态、覆盖范围和原始报告位置。
- 扫描失败不得被表达为“发现 0 个问题”。
- 所有上传代码和 Maven 构建都视为不可信输入，只能在隔离 Runner 中执行。
- 不把扫描器特有字段直接泄漏到公共 API；先转换为统一 Finding。

## 提交流程

1. 从 `main` 创建功能分支。
2. 在对应模块实现修改并补充测试。
3. 运行 `mvn verify`。
4. 更新相关架构、配置或 ADR 文档。
5. 提交 Pull Request，说明变更、风险与验证方式。

## Commit 建议

推荐使用简短、可检索的 Conventional Commits：

```text
feat(orchestrator): add quick scan planning
fix(finding): stabilize fingerprint generation
docs: document runner isolation boundary
```
