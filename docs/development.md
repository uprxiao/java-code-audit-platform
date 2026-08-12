# 本地开发

## 依赖

- JDK 17；
- Maven 3.9+；
- Git；
- 后续接入 Runner 时需要 rootless Podman、Kubernetes 或独立隔离环境。

## 构建

```bash
mvn verify
```

## 启动 API

```bash
mvn -pl backend/audit-api -am spring-boot:run
```

## 示例请求

```bash
curl http://localhost:8080/api/v1/health

curl -X POST http://localhost:8080/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"sourceType":"ZIP","profile":"STANDARD"}'
```

当前 API 只是领域骨架，不接受真实文件，也不会启动扫描器。

平台主服务以 JDK 17 编译和运行。被扫描项目的 JDK 版本由 Runner 独立选择；例如旧项目可使用 JDK 8/11，最新版 Error Prone 则需要单独的 JDK 21+ 扫描镜像。这两类运行时不得与平台 JDK 混用。

## 下一步开发顺序

1. 持久化 ScanJob 状态机；
2. 实现 ZIP 安全上传和 SVN 获取；
3. 建立 Runner 协议和一次性工作区；
4. 接入第一批无构建扫描器；
5. 实现 SARIF/JSON/XML 统一转换；
6. 加入报告下载。
