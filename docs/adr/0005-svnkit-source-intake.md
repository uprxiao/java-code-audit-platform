# ADR-0005：使用 SVNKit 获取 SVN 单快照

- 状态：Accepted
- 日期：2026-08-12

## 背景

V1 接收匿名或用户名/密码 SVN 地址，并且要求密码不进入进程列表、任务状态、日志和报告。目标运行环境只有 JDK 17 和 Maven 是前置条件，不能要求额外安装系统 `svn`。

## 决策

采用 SVNKit 1.10.13 的仓库 API，在 Java 进程内流式读取 `http`、`https`、`svn` 的 HEAD 或一个数字 revision。实现不创建工作副本，不执行系统命令，也不读取历史 revision。

- 密码从 JSON `char[]` 转交给一次性 `SourceCredential`，检出结束、取消或排队失败后立即清零引用；
- SVNKit 使用不落磁盘缓存的内存认证管理器；
- Maven 依赖显式排除 V1 禁用的 SSH/agent/JNA 传递依赖，应用不打包 SSH 客户端或本地凭据库能力；
- 排除 SVNKit 声明的旧版 `org.lz4:lz4-java`，以包兼容的维护分支 `at.yawk.lz4:lz4-java:1.11.2` 替换，避免将已知有漏洞版本带入介质包；
- HTTPS 使用 JVM truststore 校验证书链，并额外校验证书 DNS/IP 主机名；跨主机认证失败关闭；
- 禁止 `file`、`svn+ssh`、URL user-info、query、fragment、客户端证书和 SSH 私钥；
- 不展开 `svn:externals`，拒绝 `svn:special`，限制条目数、路径长度、单文件大小和总大小；
- 输出先写同父目录随机 staging，成功后移动成最终源码快照；失败时清理 staging；
- 报告只保存脱敏 origin、URL SHA-256 和最终 revision，不保存完整 URL；
- 有凭据任务在源码获取前重启时标记 `SOURCE_CREDENTIALS_EXPIRED`，要求重新提交。

## 后果

同一应用 JAR 可以在 Mac ARM64 和 Linux x86_64 运行，不依赖平台 SVN 二进制，密码也不会出现在子进程命令行。代价是 SVNKit 成为应用依赖；代理、客户端证书、SSH 与历史遍历不属于 V1。如需内网 CA，由部署者配置 JDK truststore，程序不提供 trust-all 开关。

## 验证

- URL/revision/凭据生命周期单元测试；
- fake SVN 获取到 REST、任务状态、Semgrep 和最终报告的 E2E，并扫描任务目录验证 canary 密码不存在；
- 可选 `audit.svn.smoke-url` 真实测试对同一公共 SVN 目录执行 HEAD 和固定 revision，验证 revision 与内容摘要一致。
