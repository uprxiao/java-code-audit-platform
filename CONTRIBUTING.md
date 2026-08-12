# 贡献指南

## 开发原则

- [`docs/v1/`](docs/v1/README.md) 是V1规范来源；改变冻结边界先写ADR并获得确认；
- 扫描引擎负责确定性检测，平台负责任务、证据、归一化和报告；
- 新引擎必须提供版本、SHA256、执行状态、覆盖、原始报告和Golden Fixture；
- 扫描失败不得表达为“发现0个问题”；
- V1只处理可信来源代码；本地执行不等于安全沙箱；
- 不把扫描器专属字段直接泄漏到公共API；先转换为统一Finding；
- CodeQL CLI、漏洞数据库、Maven缓存、任务和报告禁止提交；
- 允许再分发的工具只有完成许可复核后才能进入Git LFS。

## 提交流程

1. 从当前集成分支创建`codex/`功能分支；
2. 只修改对应模块，公共接口由集成分支维护；
3. 补充单元、Parser契约和适用的真实工具测试；
4. 使用JDK17运行`mvn clean verify`；
5. 更新相关配置、文档或ADR；
6. 合入`codex/v1-integration`后运行相应E2E；
7. 功能分支不直接合入`main`。

并行规则见[Worktree策略](docs/v1/worktree-strategy.md)。

## Commit建议

```text
feat(orchestrator): add bounded job scheduling
fix(finding): stabilize dependency fingerprints
test(semgrep): add malformed report fixture
docs: freeze local tool pack architecture
```
