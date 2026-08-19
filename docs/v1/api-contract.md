# REST API 契约

## 1. 边界

V1 提供 REST API，并在 `/` 提供一个与后端同源的轻量操作页面；不实现认证。默认部署在个人或可信网络；生产暴露范围由防火墙或反向代理控制。API 基础路径：`/api/v1`。

所有响应使用 UTF-8 JSON，下载接口除外。时间使用 ISO-8601 UTC。ID 使用不可猜测的 UUID/ULID。

## 2. 创建 ZIP 扫描

```http
POST /api/v1/scans/zip
Content-Type: multipart/form-data
```

Parts：

- `source`：ZIP 文件，必需；
- `request`：`application/json`，可选。

```json
{
  "displayName": "order-service",
  "profile": "STANDARD",
  "mavenProfiles": ["opensource"],
  "mavenProperties": {
    "revision": "1.0.0"
  }
}
```

成功：

```http
202 Accepted
Location: /api/v1/scans/01J...
```

```json
{
  "scanId": "01J...",
  "status": "QUEUED",
  "profile": "STANDARD",
  "createdAt": "2026-08-12T08:00:00Z"
}
```

## 3. 创建 SVN 扫描

```http
POST /api/v1/scans/svn
Content-Type: application/json
```

```json
{
  "repositoryUrl": "https://svn.example.com/repos/order-service/trunk",
  "revision": "12345",
  "username": "optional",
  "password": "optional",
  "displayName": "order-service",
  "profile": "DEEP",
  "mavenProfiles": [],
  "mavenProperties": {}
}
```

- `revision` 省略时使用 HEAD；
- `revision` 只接受 `HEAD` 或非负十进制整数，不接受范围、日期和历史遍历；
- 不提供 `projectPath`；URL 必须直接指向要扫描的单一项目；
- URL 不得包含 user-info、query 或 fragment；可用 `AUDIT_SVN_ALLOWED_HOSTS` 设置可选主机白名单；
- 用户名/密码不进入响应、`request.json`、job.json、日志或报告；`request.json` 只保留规范化 URL、revision 和“凭据已省略”标志以执行安全恢复决策；
- 有凭据的排队任务在服务重启后变为 `INTERRUPTED/SOURCE_CREDENTIALS_EXPIRED`；匿名任务可按原 URL 和 revision 重新排队；
- 不支持 `file://`、`svn+ssh`、SSH私钥、客户端证书和验证码。
- V1 使用 SVNKit 1.10.13 在 Java 进程内流式取回单一快照，不启动 `svn` 子进程、不创建 `.svn` 工作副本、不展开 `svn:externals`。

## 4. Maven 参数校验

- Profile 名称只允许安全字符集合并作为单独参数；
- property key 使用 Maven 属性名允许集合；
- value 有长度限制并作为单独参数；
- 禁止 goal、`-f/--file`、`-s/--settings`、本地仓库路径、工作目录、Shell重定向和 JVM Agent；
- 敏感 key（password/token/secret/key等）在日志和报告中只显示 `***`；
- 最终 Goal 固定 `package`，始终加入 `-DskipTests`。

## 5. 查询任务

```http
GET /api/v1/scans/{scanId}
```

```json
{
  "scanId": "01J...",
  "status": "RUNNING",
  "profile": "STANDARD",
  "phase": "ENGINES",
  "progress": {
    "enginesTotal": 14,
    "enginesTerminal": 8,
    "enginesRunning": 3,
    "enginesWaiting": 3
  },
  "summary": {
    "uniqueFindingCount": 23,
    "rawHitCount": 31,
    "partial": true
  },
  "createdAt": "...",
  "startedAt": "...",
  "updatedAt": "...",
  "links": {}
}
```

运行期间的统计是临时值，必须标记 `partial: true`；最终去重完成前不能当作最终总数。

## 6. 查询引擎

```http
GET /api/v1/scans/{scanId}/engines
GET /api/v1/scans/{scanId}/engines/{engineId}
```

返回状态、前置依赖、等待/运行时间、覆盖、失败 reason、原始产物和日志可用性。日志下载必须是脱敏版本。

## 7. 查询 Finding

```http
GET /api/v1/scans/{scanId}/findings?severity=P1&disposition=ACTIONABLE&page=0&size=50
```

- 仅终态任务保证稳定分页；
- size 有上限；
- 支持 severity、category、engine、module、disposition、applicability、suppressed 和 text 过滤；
- 默认不返回 suppressed；
- 详情：`GET /api/v1/scans/{scanId}/findings/{findingId}`。

## 8. 取消

```http
POST /api/v1/scans/{scanId}/cancel
```

返回 `202` 表示取消已请求；已终态返回 `200` 和当前状态。接口幂等。

## 9. 删除

```http
DELETE /api/v1/scans/{scanId}
```

- 运行/取消中的任务返回 `409`；
- 终态任务删除源码残留、报告、日志和状态文件；
- 删除成功 `204 No Content`；
- 对不存在任务返回 `404`；
- 删除后保留不含源码/问题内容的最小服务日志。

## 10. 报告与归档

```http
GET /api/v1/scans/{scanId}/reports/html
GET /api/v1/scans/{scanId}/reports/json
GET /api/v1/scans/{scanId}/reports/sarif
GET /api/v1/scans/{scanId}/reports/archive
```

报告尚未生成返回 `409 REPORT_NOT_READY`。已过期清理返回 `410 REPORT_EXPIRED`。下载文件名必须安全生成，不能直接使用用户 displayName。

## 11. 健康与能力

```http
GET /api/v1/health
GET /api/v1/tools
GET /api/v1/profiles
```

健康状态：

- `UP`：核心和所有配置必需工具可用；
- `DEGRADED`：服务可运行，但至少一个档位/引擎不可用或漏洞库陈旧；
- `DOWN`：JDK/Maven、数据目录、单实例锁等核心条件失败。

`profiles` 返回当前可用性和不可用 reason，例如 CodeQL 未安装导致 Deep unavailable。

## 12. 错误格式

```json
{
  "timestamp": "2026-08-12T08:00:00Z",
  "status": 422,
  "code": "MULTIPLE_MAVEN_ROOTS",
  "message": "压缩包包含多个独立 Maven 根项目，请重新打包一个项目。",
  "details": {
    "candidates": ["project-a/pom.xml", "project-b/pom.xml"]
  },
  "requestId": "..."
}
```

主要状态码：

- 400：请求结构/参数非法；
- 404：任务/资源不存在；
- 409：当前状态不允许操作；
- 410：报告已过期；
- 413：上传或展开容量超限；
- 422：源码或项目结构无法扫描；
- 429：队列已满；
- 507：磁盘低于阈值；
- 500：平台内部错误。

ZIP 解压和 Maven 根识别属于异步 `PREFLIGHT`。因此这两类校验在任务已返回
`202 Accepted` 后发生时，任务会进入 `FAILED`，并在 `GET /api/v1/scans/{scanId}`
的 `failure.code/details` 中返回同一错误码（例如 `UNSAFE_ARCHIVE_ENTRY`、
`MULTIPLE_MAVEN_ROOTS`）；不会为已经创建的异步任务再补发一个 HTTP 422。

## 13. 上传流与服务器配置

HTTP 层、临时文件层和解压层都设置限制。不能只依赖 Spring multipart 最大值，因为 SVN和解压后的体积不受它覆盖。反向代理使用时，其 body size、timeout 和 buffering 也必须与应用配置一致。
