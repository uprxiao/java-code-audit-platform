# 并发与资源模型

## 1. 并发不是一个数字

V1 同时控制五层资源：

```text
请求队列
  → 并发 ScanJob
    → 每个 ScanJob 的并发 EngineTask
      → 全局并发 EngineTask
        → 加权资源许可 + 工具专属信号量
```

只设置线程池大小无法阻止8个 CodeQL 或 Maven 同时运行，因此每一层都必须独立可配置和可观测。

## 2. 默认配置

### 2.1 通用安全默认值

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
```

### 2.2 高容量服务器示例

目标服务器：112 CPU、1 TiB内存、可用磁盘约271 GB。

```yaml
audit:
  concurrency:
    max-queued-scan-jobs: 100
    max-concurrent-scan-jobs: 8
    max-concurrent-engines: 24
    max-engines-per-scan: 4
    weighted-permits: 32
    tool-limits:
      maven: 4
      dependency-check: 2
      codeql: 1
```

磁盘和文件句柄比 CPU/内存更早成为瓶颈。Linux 部署建议将 `LimitNOFILE` 提高到至少65535；CodeQL 在真实压力测试完成前保持单并发。

## 3. 资源权重

| 等级 | 默认权重 | 示例 |
| --- | ---: | --- |
| LIGHT | 1 | Gitleaks、Checkstyle |
| MEDIUM | 2 | Semgrep、PMD、CPD、SpotBugs、OSV |
| HEAVY | 4 | Maven、Dependency-Check、Trivy Artifact |
| DEEP | 8 | CodeQL |

获取资源时使用固定顺序，释放时逆序，避免死锁：

```text
global engine slot
→ job engine slot
→ weighted permits
→ tool semaphore
```

拿不到后续许可时不能长期占有前序许可。实现可以一次性尝试并失败回退，或由中央调度器只派发满足全部许可的任务。

## 4. 公平调度

采用 ScanJob 轮转而不是把一个任务的所有就绪引擎一次塞满全局队列：

1. 每个运行任务维护就绪 EngineTask 队列；
2. 调度器轮询任务；
3. 每轮最多从一个任务派发一个满足资源条件的引擎；
4. `max-engines-per-scan` 防止大项目独占；
5. 等待 CodeQL 许可的任务不能阻塞其他轻型引擎；
6. 取消任务从所有等待集合中移除。

验收必须证明两个小任务不会长期排在一个大 Deep 任务后面。

## 5. 队列行为

- 队列有界；
- 满时创建任务返回 `429 Too Many Requests`；
- 返回 `Retry-After` 和当前队列指标；
- 请求尚未成功入队时不留下正式任务；
- 低磁盘时即使队列未满也返回 `507 Insufficient Storage`；
- 服务停止时不再接收任务，排队任务持久化后退出。

## 6. 进程资源控制

应用层控制：

- Java 工具使用配置化 `-Xmx`；
- CodeQL 使用 `--ram`、`--threads` 等官方参数；
- 扫描器内部线程数受限，不能与平台全局并发相乘失控；
- stdout/stderr 异步排空到有界滚动文件；
- 超过日志上限时截断展示但保留“已截断”元数据；
- 每个进程有 wall-clock 超时；
- `ProcessHandle.descendants()` 终止完整进程树；
- 任务目录计算实际大小，超过20 GB终止任务。

Linux 可选但推荐的 systemd 硬限制：

```ini
[Service]
LimitNOFILE=65535
TasksMax=4096
MemoryMax=按服务器策略配置
CPUQuota=按服务器策略配置
```

V1 不依赖 systemd 才能运行，但没有容器时 OS/cgroup 是最后一道硬资源边界。

## 7. Maven 与缓存并发

- Maven 可并发到配置上限；
- 所有任务使用平台指定的 Maven 本地仓库目录，默认 `data/cache/maven/repository`；
- 使用 Maven Resolver 自身锁机制，并监控 `.lastUpdated`/损坏下载；
- 配置允许切换为每任务独立仓库用于故障排查，代价是磁盘和下载量；
- Maven `settings.xml` 路径由服务配置提供；
- 不允许项目 API 指定任意宿主路径。

## 8. 漏洞库更新并发

- 数据更新与扫描使用不同许可；
- 更新者获取跨进程文件锁；
- 扫描只读取活动版本；
- 更新在临时目录完成校验后原子切换；
- Dependency-Check 和 Trivy 分别设置更新锁和扫描信号量；
- 更新失败不能破坏当前活动数据库。

## 9. 取消、超时与许可释放

所有路径都必须满足：

```text
进程退出或被杀死
→ stdout/stderr读取线程结束
→ 产物状态落盘
→ 工具信号量释放
→ 权重许可释放
→ 任务/全局槽位释放
```

Parser 异常、磁盘写失败和服务关闭也必须走同一释放路径。测试必须在每种异常后立刻提交新任务，证明没有许可泄漏。

## 10. 可观测指标

至少提供：

- 队列长度和容量；
- 运行/等待 ScanJob 数；
- 全局和每任务运行 EngineTask 数；
- 权重许可已用/总量；
- Maven/Dependency-Check/CodeQL 信号量占用；
- 各引擎等待时间、运行时间和超时数；
- 工作区总占用和剩余磁盘；
- 子进程数、退出码分布和强杀次数。

V1 可通过健康/指标 API 和结构化日志暴露，不要求引入 Prometheus 服务端。

## 11. 配置生效

所有参数来自外部 YAML，并支持 Spring Boot 环境变量覆盖。V1 修改后重启生效，不实现运行时热调节。启动时验证关系：

- `max-engines-per-scan <= max-concurrent-engines`；
- 工具上限不超过全局引擎槽位；
- 最大单项权重不超过总权重许可；
- 队列、并发和超时必须为正数；
- 存储阈值可由当前文件系统满足。
