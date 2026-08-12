# V1 决策登记册

> 状态：Frozen。这里记录产品和架构边界，不记录普通实现待办。

| ID | 决策 | 直接影响 |
| --- | --- | --- |
| D-001 | 项目只支持 Java 17 Maven | 不建设多 JDK 和 Gradle 矩阵 |
| D-002 | Mac 开发机为 macOS ARM64 | Mac Quick/Standard/Deep 都必须真实通过 |
| D-003 | Linux 目标为 x86_64、Ubuntu 22.04、glibc 2.34+ | Linux 工具选择和 CI 以该基线为准 |
| D-004 | JDK 17 由运行环境安装 | 介质不带 JDK；启动时检查版本 |
| D-005 | Maven 3.9+ 由运行环境安装 | 介质不带 Maven；不自动使用 `mvnw` |
| D-006 | 运行环境允许联网 | 可访问 SVN、Maven 仓库和漏洞数据库；不做完全离线 |
| D-007 | 可再分发工具不入 Git，由锁定版本、官方 URL 和 SHA256 的脚本组装进平台介质 | 仓库保持轻量；`tools/downloads/` 本地保留但 gitignore；发布必须联网或使用已校验缓存 |
| D-008 | 大型运行数据只在本地保存 | 漏洞库、Maven 缓存、任务、报告和 CodeQL CLI 进入 `.gitignore` |
| D-009 | CodeQL 是 V1 Deep 的正式受控能力 | CLI 本地安装、默认按策略检查、Mac/Linux Deep 真测 |
| D-010 | V1 直接提供外部 REST API，不做认证 | 只能部署在个人或可信网络，不能公开匿名暴露 |
| D-011 | 三档扫描，STANDARD 为默认 | QUICK 不依赖构建；DEEP 增加 CodeQL |
| D-012 | Maven 默认 `-DskipTests package` | 编译但不执行项目测试；构建仍可能执行插件代码 |
| D-013 | 并发、超时、磁盘阈值全部外部配置 | 普通默认值 + 高容量服务器示例，重启后生效 |
| D-014 | 高容量示例为 8任务/24引擎/CodeQL 1 | 实际压力测试后可配置放大，不改变程序 |
| D-015 | 默认 ZIP 1 GB、展开项目10 GB、任务工作区20 GB、保留磁盘50 GB | 超限提前停止并给出输入错误 |
| D-016 | 成功任务报告保留30天；失败结果7天；失败工作区24小时 | 定时清理和低磁盘优先清理终态任务 |
| D-017 | SVN 凭据只驻留内存 | 检出前重启后需重新提交，不在日志和 job.json 中保存密码 |
| D-018 | 工具版本锁定，漏洞数据库每日更新 | 工具升级必须跨平台回归；数据库陈旧要告警 |
| D-019 | 问题总数使用去重后的唯一问题数 | 同时展示原始命中数；SBOM 组件不算问题 |
| D-020 | 保存有限代码上下文并强制密钥脱敏 | 默认前后各5行；污点节点可扩展；不归档完整源文件 |
| D-021 | Mac 是首要硬性验收；Linux CI 是第二硬性验收 | 实际 Linux 服务器验收脚本提供但暂不阻塞 V1 |
| D-022 | 日常 Linux CI 跑 Quick/Standard；发布/手工 CI 真跑 Deep | 控制反馈时间，同时验证 Linux CodeQL |
| D-023 | 每个任务只接受一个 Maven Reactor 根 | 多个独立根时返回候选并要求重新打包/检出 |
| D-024 | SVN 只扫 HEAD 或指定单一 revision | 不声称覆盖历史密钥和历史代码 |
| D-025 | API 只允许 Maven Profile 和受控 `-D` 属性 | Goal 固定为 package，不接受任意 Shell/Maven 命令 |
| D-026 | 单个引擎失败时保留部分结果 | 最终状态可为 `COMPLETED_WITH_ERRORS`，失败不等于零问题 |
| D-027 | V1 支持路径排除和规则抑制 | 报告展示抑制数与原因；不做历史基线 |
| D-028 | 报告中文为主并保留英文原文 | 无人工中文模板时回退英文，不使用 AI 临时翻译 |
| D-029 | 单 JAR 模块化单体、本地子进程、无容器和数据库 | 部署简单，但不具备恶意代码隔离和多实例协调 |
| D-030 | Error Prone/NullAway 延后 | 避免引入 JDK 21+ 与强制 Null 注解配置 |

## 已确认默认值

```yaml
audit:
  concurrency:
    max-queued-scan-jobs: 20
    max-concurrent-scan-jobs: 2
    max-concurrent-engines: 4
    max-engines-per-scan: 2
    weighted-permits: 8
    tool-limits:
      maven: 1
      dependency-check: 1
      codeql: 1
  input:
    max-upload-size: 1GB
    max-expanded-project-size: 10GB
    max-single-file-size: 1GB
    max-file-count: 200000
    max-compression-ratio: 100
  storage:
    max-workspace-size-per-job: 20GB
    min-free-space: 50GB
  retention:
    completed-days: 30
    failed-days: 7
    failed-workspace-hours: 24
    cleanup-interval: 1h
```

高容量示例使用：排队100、并发任务8、全局引擎24、每任务引擎4、权重许可32、Maven 4、Dependency-Check 2、CodeQL 1。

## 尚未固定但无需用户决策的工程项

以下项目在相应阶段用 POC 和测试决定，并写入工具清单或 ADR：

- 各扫描器的精确锁定版本和 SHA256；
- SVNKit 与系统 SVN CLI 的选择已由 [ADR-0005](../adr/0005-svnkit-source-intake.md) 固定为 SVNKit 1.10.13；
- Semgrep 自包含 Python 运行时的具体打包方式；
- HTML 模板引擎、JSON/SARIF 库和图表实现；
- 统一指纹算法中的字段权重和规则族映射细节；
- 性能基线数值；
- 本地下载缓存的统一清理/备份操作规程。

这些选择不能改变本登记册的产品行为或验收结果。
