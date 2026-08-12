# Local Process Runner（目标模块）

该占位目录将在V1中演进为`local-process-runner`：负责使用Java `ProcessBuilder`执行本机Maven和扫描器，处理日志、超时、取消、进程树和资源许可。

V1不实现容器或远程Runner。详细契约见：

- [`docs/v1/architecture.md`](../../docs/v1/architecture.md)
- [`docs/v1/scanner-adapter.md`](../../docs/v1/scanner-adapter.md)
- [`docs/v1/concurrency.md`](../../docs/v1/concurrency.md)
