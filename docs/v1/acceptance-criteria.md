# V1 验收标准（Definition of Done）

> 只有下面全部“Must”项有自动或可复核证据时，V1才完成。代码提交、单个扫描器能运行或一次报告生成都不等于完成。

## A. 运行与介质

- [ ] A-01 同一Spring Boot JAR以Java 17编译，class major为61。
- [ ] A-02 Mac ARM64在预装JDK17/Maven3.9+后可用一个脚本启动。
- [ ] A-03 Ubuntu 22.04 x86_64/glibc2.34+介质可组装并启动。
- [ ] A-04 不需要数据库、Redis、MQ、Docker、Podman或Kubernetes。
- [ ] A-05 启动检查JDK、Maven、磁盘、锁、工具版本/SHA256和档位可用性。
- [ ] A-06 Mac/Linux介质只包含目标平台原生工具，公共JAR/配置/Schema一致。
- [ ] A-07 允许再分发工具、许可证、来源、版本和SHA256进入manifest；CodeQL CLI不进入公共仓库/介质。
- [ ] A-08 `data/`、CodeQL、漏洞库、Maven缓存和报告被正确忽略。

## B. 输入与构建

- [ ] B-01 ZIP上传、流式容量限制和安全解压通过。
- [ ] B-02 SVN匿名、用户名/密码、HEAD和指定revision通过。
- [ ] B-03 SVN密码不落盘、不入日志/报告，检出前重启给出凭据过期状态。
- [ ] B-04 Java 17 Maven单模块项目通过。
- [ ] B-05 标准Maven多模块Reactor通过。
- [ ] B-06 多个独立Maven根返回候选并要求重新提交。
- [ ] B-07 Maven固定使用系统`mvn`、JDK17、`-DskipTests package`。
- [ ] B-08 受控Maven Profile和`-D`属性通过；命令注入/任意goal被拒绝。
- [ ] B-09 构建失败时Quick结果保留，字节码下游明确跳过。

## C. 扫描能力

- [ ] C-01 Quick六个逻辑引擎完成真实扫描。
- [ ] C-02 Standard新增八个逻辑引擎和Maven构建完成真实扫描。
- [ ] C-03 Deep新增CodeQL完成真实扫描。
- [ ] C-04 九组用户审计能力均有至少一个真实验收Fixture。
- [ ] C-05 十二类问题映射有单元/Fixture覆盖，SBOM作为资产单列。
- [ ] C-06 Error Prone/NullAway不被配置或文档误列为V1引擎。
- [ ] C-07 每个引擎都有版本、覆盖、耗时、状态、原始产物和失败reason。
- [ ] C-08 单引擎失败不取消独立引擎，最终生成`COMPLETED_WITH_ERRORS`报告。
- [ ] C-09 必需工具缺失不静默跳过；Deep缺少CodeQL明确不可用。
- [ ] C-10 漏洞数据库无可用版本时相关引擎失败，不返回零漏洞。

## D. Finding 与报告

- [ ] D-01 报告同时显示唯一问题数和原始命中数，首页问题总数为唯一问题数。
- [ ] D-02 P0/P1/P2/P3和12类问题合计与唯一有效问题数一致。
- [ ] D-03 同一SQL注入的Semgrep/FindSecBugs/CodeQL证据可合并且不丢原始来源。
- [ ] D-04 不同真实数据流不会被激进去重丢失。
- [ ] D-05 依赖问题提供PURL、路径、CVE/OSV、当前/修复版本。
- [ ] D-06 普通Finding提供路径、行号、有限代码片段、说明、影响和修复建议。
- [ ] D-07 CodeQL Finding显示真实Source/Sink/path；缺失节点不伪造。
- [ ] D-08 密钥、SVN凭据和Maven敏感属性在HTML/JSON/SARIF/raw/log/archive全部脱敏。
- [ ] D-09 路径排除进入coverage；规则抑制单列数量、原因和证据。
- [ ] D-10 生成HTML、JSON、SARIF、manifest、coverage、SBOM、raw和logs下载包。
- [ ] D-11 JSON Schema、SARIF基础校验、文件SHA256和统计不变量通过。
- [ ] D-12 HTML中文为主、保留英文原文、无中文模板时英文回退、无AI依赖。
- [ ] D-13 HTML离线可读且不加载外部脚本/CDN。
- [ ] D-14 下载包不包含完整源码、target、CodeQL DB或Maven缓存。

## E. 并发与稳定性

- [ ] E-01 有界队列满时返回429和Retry-After。
- [ ] E-02 最大并发任务、全局引擎、每任务引擎、权重许可均不越界。
- [ ] E-03 Maven、Dependency-Check、CodeQL工具上限不越界。
- [ ] E-04 20任务测试证明公平性，无明显任务饥饿和死锁。
- [ ] E-05 成功、失败、超时、取消、Parser异常后全部许可释放。
- [ ] E-06 超时/取消后主进程及descendants全部退出。
- [ ] E-07 stdout/stderr大输出不死锁，日志有界且标记截断。
- [ ] E-08 不同任务工作区、raw和logs完全隔离。
- [ ] E-09 所有并发/超时/存储阈值可由YAML和环境变量配置，重启生效。
- [ ] E-10 high-capacity示例配置通过配置验证和并发测试。

## F. 文件状态、恢复与清理

- [ ] F-01 单实例文件锁阻止两个进程共享data目录。
- [ ] F-02 job.json原子写入、revision单调且坏状态不会触发扫描执行。
- [ ] F-03 重启后QUEUED重新入队，RUNNING/PREFLIGHT/FINALIZING标记INTERRUPTED。
- [ ] F-04 终态任务重启后可查询和下载。
- [ ] F-05 成功后立即删除源码、target、CodeQL DB和临时文件。
- [ ] F-06 失败工作区24小时、失败结果7天、成功报告30天策略通过时间测试。
- [ ] F-07 低于50 GB时拒绝新任务并优先清理最早终态。
- [ ] F-08 运行任务不被清理；运行任务删除返回409。
- [ ] F-09 所有递归清理路径限制在验证后的任务根。

## G. 安全回归

- [ ] G-01 Zip Slip、绝对路径、symlink、zip bomb、文件数/单文件/总量限制通过。
- [ ] G-02 Maven Profile/属性和文件名命令注入测试通过。
- [ ] G-03 报告HTML escape和下载文件名/归档路径测试通过。
- [ ] G-04 工具路径、版本、SHA256异常会阻止对应引擎。
- [ ] G-05 canary secret扫描整个任务目录和下载包无明文。
- [ ] G-06 SECURITY明确只支持可信代码和可信网络，不宣称恶意代码隔离。

## H. 跨平台测试

- [ ] H-01 macOS ARM64 Quick真实E2E通过。
- [ ] H-02 macOS ARM64 Standard真实E2E通过。
- [ ] H-03 macOS ARM64 Deep + CodeQL真实开源Fixture通过。
- [ ] H-04 Linux日常CI单元/契约/Fake/Quick/Standard通过。
- [ ] H-05 Linux发布或手工CI真实Deep + CodeQL通过。
- [ ] H-06 Linux介质组装、启动、报告下载和清理通过。
- [ ] H-07 提供实际Ubuntu服务器`acceptance-test.sh`和`--deep`选项。

H-07脚本必须交付，但实际服务器执行结果不阻塞V1。

## I. 工程质量与文档

- [ ] I-01 JDK17 `mvn clean verify`全模块通过。
- [ ] I-02 所有适配器有Golden Fixture和Parser契约测试。
- [ ] I-03 所有真实工具至少在Mac和Linux各有一个冒烟证据。
- [ ] I-04 工具升级流程、许可和Parser Schema文档完整。
- [ ] I-05 README、SECURITY、CONTRIBUTING、Profile配置和V1文档没有架构冲突。
- [ ] I-06 开发计划里程碑有提交和测试证据。
- [ ] I-07 发布包包含版本、SHA256、许可证清单和已知边界。
- [ ] I-08 不存在未说明的P0/P1测试失败、TODO占位或静默禁用引擎。

## 非阻塞但必须记录

- 实际目标Linux服务器的人工验收结果；
- 工具或漏洞数据库导致的非确定性新增低危结果；
- Apple Silicon CodeQL官方Beta状态；
- 当前性能基线和下一步调参建议；
- 未实现的认证、前端、历史基线、完全离线、AI和沙箱能力。

## 最终验收证据包

```text
v1-acceptance-evidence/
├── build/
├── unit-contract/
├── macos-quick-standard-deep/
├── linux-quick-standard/
├── linux-deep/
├── concurrency/
├── security/
├── recovery-retention/
├── reports/
├── performance/
└── release-manifest.json
```

完成声明必须链接到该证据包和对应Git提交。
