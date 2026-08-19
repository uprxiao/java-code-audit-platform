# Web UI

当前 Web 页面与 Spring Boot JAR 一起打包，源码位于：

```text
backend/audit-api/src/main/resources/static/
├── index.html
├── app.css
└── app.js
```

启动服务后访问 `http://localhost:8080/`。页面直接调用同源
`/api/v1` 接口，无 Node.js 依赖，无独立部署步骤。

已实现：

- 拖放或选择 ZIP，提交单一 Java/Maven 根项目；
- 根据后端健康状态选择 Quick、Standard 或 Deep；
- 可选 Maven profiles 和 properties；
- 任务状态、扫描阶段、问题统计和引擎进度轮询；
- 取消任务，刷新或恢复本浏览器上次查看的任务；
- 终态 Finding 预览；
- HTML、JSON、SARIF 和完整 ZIP 报告下载。

V1 页面暂不包含 SVN 表单、登录、任务历史列表和在线规则编辑。
