# V1 发布介质

本目录保存进入 Mac ARM64 / Linux x86_64 发布 ZIP 的静态内容；构建产物仍写入被忽略的 `dist/`。

- `bin/run.sh`：前台运行，适合 systemd；严格检查 JDK 17 与 Maven 3.9+。
- `bin/start.sh` / `stop.sh` / `status.sh` / `health.sh`：单机后台管理脚本。
- `bin/acceptance-test.sh`：从 Web API 上传固定 Java 17 Maven Fixture，支持 `--quick`、`--standard`、`--deep`，验证终态、报告 ZIP、敏感 canary 和禁止目录。
- `bin/update-vulnerability-data.sh`：联网初始化或原子更新 Dependency-Check、Trivy 通用库和 Trivy Java 库；Standard 首次验收前必须先运行。
- `bin/install-codeql-local.sh`：按锁定版本和 SHA256 把 CodeQL 安装到介质的本机忽略目录；CLI 不进入发布 ZIP。
- `fixtures/maven17`：包含已知 Log4j 2.14.1 依赖的许可内自有最小项目，用于供应链和 Deep 验收，不作为生产样例。
- `systemd/java-code-audit.service`：Ubuntu 22.04 示例；部署方须先创建低权限用户并按实际路径调整环境文件。

组装命令：

```bash
./scripts/build-distribution.sh darwin-arm64 0.1.0
./scripts/build-distribution.sh linux-x86_64 0.1.0
```

解压后的首次 Standard / Deep 验收：

```bash
./bin/update-vulnerability-data.sh
./bin/start.sh
./bin/acceptance-test.sh --standard

# 仅在符合 GitHub CodeQL 使用条款并明确启用 Deep 时：
./bin/install-codeql-local.sh
./bin/acceptance-test.sh --deep
```

发布 ZIP 不包含 CodeQL CLI、漏洞数据库、Maven 缓存、任务或报告。CodeQL 继续由用户使用受控安装脚本放入本机 `tools/local`，Deep 不得在缺失时静默降级。
