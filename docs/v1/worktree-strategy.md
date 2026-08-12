# Git Worktree 并行开发策略

## 1. 原则

Worktree 解决的是独立模块并行，不解决共享协议尚未确定的问题。M0-M3串行；达到 G1 后最多同时开启三个功能 worktree，加一个集成 worktree。

## 2. 分支和目录

文档基线合入后创建：

```text
codex/v1-integration       集成和发布唯一入口
codex/v1-execution         调度、进程、并发
codex/v1-reporting         Finding、存储、报告
codex/v1-scanners          当前波次扫描器适配器
```

推荐目录（不放在仓库内部）：

```text
/Users/hx/Documents/信息/代码审查/worktrees/
├── v1-integration/
├── v1-execution/
├── v1-reporting/
└── v1-scanners/
```

示例命令仅在G1通过后执行：

```bash
git branch codex/v1-integration
git worktree add ../worktrees/v1-integration codex/v1-integration
git worktree add -b codex/v1-execution ../worktrees/v1-execution codex/v1-integration
git worktree add -b codex/v1-reporting ../worktrees/v1-reporting codex/v1-integration
git worktree add -b codex/v1-scanners ../worktrees/v1-scanners codex/v1-integration
```

实际绝对路径在执行时确认，不能在未验证父目录的情况下递归删除 worktree。

## 3. 集成 worktree 的独占职责

只有 `codex/v1-integration` 修改：

- 根 `pom.xml` 和模块列表；
- 公共 Java接口和Schema；
- Profile配置模型；
- 全局依赖版本管理；
- 跨模块测试基础设施；
- GitHub Actions和发布组装；
- 全量E2E Fixture入口；
- 冻结文档和ADR；
- 最终冲突解决。

功能 worktree 如果发现公共接口不够用，先提交变更提案/测试给集成分支；不能在三个分支分别修改出三个版本。

## 4. 波次1职责

| Worktree | 允许修改 | 禁止直接修改 |
| --- | --- | --- |
| execution | orchestrator、local-process-runner、并发测试 | Finding Schema、报告JSON、根POM |
| reporting | finding-core、file-storage、report-service | Scanner SPI、Profile DAG、根POM |
| scanners | scanner-adapters中的Quick工具、工具Fixture/manifest | 公共执行接口、Finding核心字段、根POM |
| integration | 共享接口、构建、跨模块E2E | 不替功能分支长期开发其内部实现 |

## 5. 波次2调整

I1通过后可删除/复用功能worktree，但仍最多三个并行方向：

- `codex/v1-bytecode`：Maven、SpotBugs/FindSecBugs、Dependency/Enforcer；
- `codex/v1-supply-chain`：Dependency-Check、OSV、CycloneDX、Trivy Artifact；
- `codex/v1-hardening`：SVN、安全、恢复、清理和质量测试。

CodeQL 最后单独分支，减少与 Maven构建和报告模型同时变化的风险。

## 6. 分支启动检查

每个 worktree 开始前：

1. 从最新 `codex/v1-integration` 创建；
2. `git status --short` 必须为空；
3. JDK17 `mvn verify` 通过；
4. 记录负责模块、接口版本和验收项；
5. 不在其他 worktree 打开同一可写任务目录；
6. 本地运行数据使用各 worktree 独立 data 目录和端口。

建议通过环境变量隔离：

```text
AUDIT_DATA_DIR=/tmp/java-audit-v1-execution
SERVER_PORT=18081
```

## 7. 提交和合并门槛

功能分支提交前：

- 只包含本职责文件；
- relevant unit/contract tests通过；
- 真实工具改动带Fixture和版本证据；
- 文档/配置同步；
- 不提交 `data/`、CodeQL、漏洞库、报告或本地缓存；
- 不提交未允许再分发的二进制；
- rebase/merge最新集成分支后复测。

合入顺序由[开发计划](development-plan.md)控制。推荐通过PR合入 `codex/v1-integration` 并保留清晰提交；集成负责人负责共享冲突和全量测试。功能分支不得直接合入 `main`。

## 8. 冲突规则

- 同一公共文件被两个分支修改：停止其中一个方向，先在集成分支确定最终协议；
- Fixture冲突：按工具/版本分目录，禁止覆盖别人的样例；
- 依赖版本冲突：统一交给dependencyManagement；
- 报告Schema冲突：以冻结Schema兼容性和E2E为准；
- 配置事实冲突：Profile YAML为唯一来源；
- 文档与代码冲突：冻结文档优先，除非新增Accepted ADR。

## 9. 清理 worktree

分支合入、状态干净且提交已推送后，才使用：

```bash
git worktree remove /absolute/path/to/worktree
git worktree prune
```

不得直接递归删除未确认路径。存在未提交修改时先检查归属，不能强制删除。

## 10. 为什么不“一扫描器一个 worktree”

扫描器共享工具发现、ExecutionSpec、Finding、Fixture和报告协议。每个扫描器单独分支会制造大量相同文件冲突。按“执行/报告/一组扫描器”分轨能让依赖边界稳定，又保留真实并行收益。
