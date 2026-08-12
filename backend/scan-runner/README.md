# Local Process Runner（目标模块）

执行层已实现在 `backend/local-process-runner`。该历史目录仅保留迁移说明，不参与构建或运行。

`local-process-runner` 使用 Java `ProcessBuilder` 和参数数组执行系统 Maven 与扫描器，已覆盖并发排空 stdout/stderr、有界日志、超时、取消和子进程树终止。

V1不实现容器或远程Runner。详细契约见：

- [`docs/v1/architecture.md`](../../docs/v1/architecture.md)
- [`docs/v1/scanner-adapter.md`](../../docs/v1/scanner-adapter.md)
- [`docs/v1/concurrency.md`](../../docs/v1/concurrency.md)
