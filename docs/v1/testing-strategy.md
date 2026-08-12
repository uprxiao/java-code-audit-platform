# V1 测试策略

## 1. 验证目标

测试不仅证明“命令能运行”，还要证明：扫描覆盖真实、失败不冒充零问题、并发不泄漏资源、敏感信息不进入报告、Mac/Linux介质可复现。

## 2. 测试层级

### 2.1 单元测试

- ScanJob/EngineTask全部合法和非法状态迁移；
- Profile继承、DAG拓扑排序和环检测；
- 参数验证与命令数组；
- 队列、轮转、公平性、权重和信号量；
- 路径规范化和安全根校验；
- 严重性映射、规则族、指纹和去重；
- suppression、expiry、path exclusion；
- 代码片段边界和多编码失败；
- secret redaction；
- 报告统计不变量；
- 原子文件写入、revision和恢复决策；
- 保留期和清理目标选择。

### 2.2 Parser契约/Golden Fixture

每个逻辑引擎至少具备：

- clean；
- 单一Finding；
- 多Finding和多模块；
- 位置缺失/未知规则；
- partial；
- malformed；
- 当前锁定工具版本；
- expected normalized findings。

升级工具版本必须重新跑全部Fixture并审查差异。

### 2.3 LocalProcessRunner测试

Fake程序覆盖：

| 场景 | 预期 |
| --- | --- |
| exit 0 + 正常报告 | SUCCEEDED |
| 工具定义的 finding exit code | SUCCEEDED且有Finding |
| fatal exit code | FAILED且保留日志 |
| 超时 | TIMED_OUT、进程树终止、许可释放 |
| 主进程生成子进程 | 取消后无孤儿进程 |
| stdout/stderr超大 | 不死锁、日志按策略截断 |
| 无报告/坏JSON | FAILED_INVALID_OUTPUT |
| Parser抛异常 | 原始报告保留、许可释放 |
| 取消竞争 | 最终状态唯一且可恢复 |

### 2.4 组件集成测试

- ZIP/SVN → project manifest；
- plan → scheduler → fake adapter → raw → Finding；
- Maven构建成功/失败 → DAG下游；
- Finding → dedup → suppression → report；
- job.json → restart recovery；
- retention → workspace/report清理；
- DB updater → lock → atomic switch。

## 3. 真实项目 Fixture

所有Fixture必须是仓库自有的小型开源测试项目或明确允许使用的固定commit，不依赖不可控外部HEAD。

```text
fixtures/projects/
├── clean-java17/
├── vulnerable-spring/
├── multi-module/
├── multiple-roots-invalid/
├── build-failure/
├── dependency-vulnerable/
├── secrets/
├── duplicate-code/
├── iac-misconfig/
└── codeql-taint/
```

每个项目有 `expected.yml`，声明预期能力而不是脆弱的全部命中数。例如必须存在规则族、文件和最低数量；工具升级产生额外低危结果不会无理由让测试失效。

## 4. API E2E

对实际启动JAR执行：

1. 健康和档位能力；
2. 上传ZIP并获得202；
3. 轮询直到终态；
4. 查询引擎和Finding；
5. 下载HTML/JSON/SARIF/archive；
6. Schema、统计和SHA256验证；
7. 验证源码工作区已清理；
8. SVN匿名/凭据/revision；
9. 取消、删除、报告过期；
10. 队列满429和低磁盘模拟507。

Quick/Standard/Deep分别有完整E2E。Deep Fixture必须是符合CodeQL使用条件的开源Java项目。

## 5. 并发测试

至少覆盖：

- 一次提交20个任务；
- `maxConcurrentScanJobs`不越界；
- 全局/每任务引擎数不越界；
- weighted permits不越界；
- Maven、Dependency-Check、CodeQL专属上限不越界；
- 大Deep任务不能饿死后到的小Quick任务；
- 取消/超时/Parser失败立即释放全部许可；
- 队列满准确返回429；
- job.json并发更新不损坏且revision单调；
- 不同任务的raw/log/workspace绝不串目录；
- 服务关闭后无遗留子进程；
- 重启后QUEUED恢复、RUNNING变INTERRUPTED。

使用可控Fake耗时和事件栅栏断言并发，不依赖脆弱的 `sleep` 时序猜测。

## 6. 安全测试

### ZIP

- `../`、绝对路径、盘符、NUL；
- symlink/hardlink逃逸；
- zip bomb/高压缩比；
- 超大单文件、超文件数、展开超限；
- 重复文件名、大小写碰撞（Mac默认大小写不敏感）；
- 文件名Unicode规范化；
- HTML/脚本源码进入报告时必须escape。

### 命令与路径

- Maven Profile/property中的空格、分号、换行、反引号、`$()`；
- 禁止 `-f`、settings、goal、JVM Agent；
- 工作/输出路径逃逸；
- 恶意报告中的外部文件引用；
- 下载文件名CRLF和路径注入。

### 敏感信息

- SVN password不在内存外的持久文件；
- canary Token不出现在job、raw归档、日志、HTML、JSON、SARIF和ZIP二进制字符串中；
- Maven敏感属性、URL user-info和代理凭据脱敏；
- Gitleaks Finding只显示掩码。

安全测试不证明Maven恶意代码隔离；该能力明确不在V1。

## 7. 恢复与清理测试

- 在获取、预检、引擎、最终化阶段模拟强制停止；
- job.json.tmp存在时恢复器忽略；
- job.json损坏时隔离，不执行扫描器；
- 有凭据SVN检出前重启后要求重新提交；
- 成功任务立即删工作区；
- 失败工作区24小时、失败结果7天、成功报告30天；
- 低磁盘优先清理最早终态；
- 运行任务不被清理；
- 手工删除运行任务409；
- 删除路径始终位于任务根。

## 8. 报告测试

- unique/raw/suppressed口径；
- severity/category合计一致；
- 同一SQL注入三引擎合并为一组并保留三证据；
- 不同Source路径按规则保持独立；
- 同CVE/PURL跨引擎合并；
- SBOM 428组件不增加问题数；
- 引擎失败在首页和SARIF invocation可见；
- 代码片段行号和highlight正确；
- 中文模板/英文回退；
- archive不含源码、target、CodeQL DB；
- manifest文件哈希正确；
- HTML离线打开且无外部资源。

## 9. 性能与资源

在small/medium/large三个固定Fixture上记录：

- 每Profile总耗时；
- 每引擎等待/运行时间；
- 峰值RSS、CPU、工作区和日志大小；
- Finding归一化/报告耗时；
- 缓存冷/热差异；
- 并发8任务下吞吐和公平性。

V1不先承诺脱离硬件的绝对扫描时长；硬验收是资源上限不越界、无失控增长、无泄漏，并建立可比较的基线报告。

## 10. 平台矩阵

| 环境 | 日常 | 发布/最终 | 要求 |
| --- | --- | --- | --- |
| macOS ARM64本机 | 单元/集成/开发冒烟 | Quick/Standard/Deep真实全量 | V1硬性条件，最高优先 |
| GitHub Actions Ubuntu 22.04 x86_64 | 单元、契约、Quick/Standard真实 | Deep真实、介质和全量E2E | V1硬性条件 |
| 实际Ubuntu 22.04服务器 | 非日常 | 提供acceptance脚本 | 暂不阻塞V1 |

Linux日常CI不下载/运行真实CodeQL，但运行Deep编排和Parser Fixture；发布或手工工作流下载官方CodeQL并执行真实Deep。

## 11. CI分层

### PR工作流

- JDK17 `mvn clean verify`；
- 单元、Schema、Parser、Fake Process；
- Quick/Standard Linux真实冒烟；
- Deep编排/Parser（不真跑CodeQL）；
- 工具组装包/manifest/SHA256一致性；
- Linux介质组装检查；
- Markdown链接和术语检查。

### Release/Manual Deep工作流

- PR工作流全部内容；
- 官方CodeQL Bundle下载和版本校验；
- Linux Deep真实E2E；
- 并发、安全、恢复和性能回归；
- 最终介质SHA256、许可证和工具manifest；
- 报告归档作为CI证据。

## 12. 失败处理

- 测试依赖官方服务短暂不可用时，区分基础设施失败和产品失败；
- 固定Fixture和缓存降低网络不确定性；
- 不通过把断言放宽为“任意命中数”来掩盖Parser变化；
- 真实扫描变化必须审查规则/数据库/工具版本证据；
- 发布工作流任何硬性验收失败都不能宣布V1完成。
