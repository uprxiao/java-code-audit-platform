# 本地开发

## 依赖

- JDK 21；
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

## 下一步开发顺序

1. 持久化 ScanJob 状态机；
2. 实现 ZIP 安全上传和 SVN 获取；
3. 建立 Runner 协议和一次性工作区；
4. 接入第一批无构建扫描器；
5. 实现 SARIF/JSON/XML 统一转换；
6. 加入报告下载。
