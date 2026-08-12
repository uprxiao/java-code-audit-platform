# 系统架构

V1 的权威架构已经迁移到：

- [V1 总体架构](v1/architecture.md)
- [跨平台工具包](v1/tool-pack.md)
- [扫描生命周期](v1/scan-lifecycle.md)
- [并发与资源模型](v1/concurrency.md)

## 当前结论

平台采用单 Spring Boot JAR 的模块化单体：API、源码接入、调度、扫描适配、Finding、文件存储和报告在一个进程；Maven及扫描器作为本地子进程按任务执行。V1 不使用容器、远程 Runner、数据库或消息队列。

旧版“控制面 + Isolated Runner + 多JDK容器”的设计已经被 [ADR-0002](adr/0002-local-tool-pack-architecture.md) 取代。
