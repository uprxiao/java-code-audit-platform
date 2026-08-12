# 文件存储、恢复与保留

## 1. 原则

- 不使用数据库；
- V1 单实例；
- 每个任务目录自包含；
- 状态和产物先写临时文件再原子替换；
- 共享工具只读，共享缓存有锁；
- 终态报告不可变；
- 大型临时数据到期自动清理。

## 2. 目录结构

```text
data/
├── instance.lock
├── health/
│   └── startup.json
├── jobs/
│   └── {scanId}/
│       ├── job.json
│       ├── request.json
│       ├── project-manifest.json
│       ├── scan-plan.json
│       ├── source/               # 临时
│       ├── workspace/            # 临时
│       ├── build/                # 临时
│       ├── codeql-db/            # Deep临时
│       ├── raw/
│       │   └── {engineId}/
│       ├── normalized/
│       │   ├── candidates.ndjson
│       │   └── findings.json
│       ├── logs/
│       ├── report/
│       └── archive/
├── cache/
│   ├── maven/repository/
│   ├── dependency-check/
│   ├── trivy/
│   └── osv/
├── update-locks/
└── tmp/
```

`request.json` 是脱敏请求；SVN password 永不写入。原 ZIP 成功展开后删除。

## 3. `job.json`

至少包含：

```json
{
  "schemaVersion": 1,
  "scanId": "01J...",
  "revision": 12,
  "status": "RUNNING",
  "phase": "ENGINES",
  "profile": "STANDARD",
  "createdAt": "...",
  "updatedAt": "...",
  "terminal": false,
  "engines": {},
  "artifacts": {},
  "failure": null
}
```

`revision` 每次状态写入递增，防止旧异步回调覆盖新状态。写入流程：

```text
serialize → job.json.tmp-{uuid} → fsync（支持时） → atomic move → directory sync（支持时）
```

临时文件不得被恢复器当成正式状态。恢复时发现 JSON 损坏，将任务隔离为 `CORRUPTED_STATE`，不能启动扫描器猜测执行。

## 4. 进程内索引

启动后从文件恢复到内存索引，以支持快速查询和调度。内存不是事实源：每次关键状态变化必须先持久化或与产物同一事务顺序写入。

V1 不支持两个进程同时更新同一任务，也不支持共享 NFS 上的多实例。

## 5. 单实例锁

- 启动打开 `data/instance.lock` 并尝试独占文件锁；
- 获取失败时拒绝启动并提示可能已有实例；
- 锁持有整个进程生命周期；
- 进程崩溃后 OS 释放锁；
- 锁文件存在本身不等于被占用，不能只判断文件是否存在。

## 6. 共享缓存

### Maven

- 默认 `data/cache/maven/repository`；
- Maven 调用显式指定本地仓库；
- 使用 Maven 自身的并发下载锁；
- 缓存损坏时提供受控重建命令，不能自动删除整个 data 根；
- `.m2/settings.xml` 可由配置引用，但不复制凭据到任务目录。

### 漏洞数据库

- 活动数据与下载临时数据分开；
- 工具级文件锁；
- 更新校验后原子切换；
- 保存版本、更新时间、来源和更新错误；
- 清理旧版本时至少保留当前版本，必要时保留一个回滚版本。

## 7. 保留策略

| 数据 | 成功任务 | 失败/取消/超时 |
| --- | --- | --- |
| 原始 ZIP | 展开成功立即删除 | 接收/展开失败后清理 |
| SVN凭据 | 检出完成立即释放 | 不落盘 |
| 源码/工作区 | 报告完成立即删除 | 最多24小时 |
| Maven target | 报告完成立即删除 | 最多24小时 |
| CodeQL数据库 | 报告完成立即删除 | 最多24小时 |
| job/manifest/coverage | 30天 | 7天 |
| 报告/原始结果/日志 | 30天 | 已有内容保留7天 |

所有值外部配置化。

## 8. 清理算法

每小时和服务启动时：

1. 读取终态任务索引；
2. 清理超过24小时的失败工作区；
3. 删除超过保留期的任务内容；
4. 低磁盘时按“最早终态优先”继续清理；
5. 每次删除前重新确认任务终态和目录位于 `data/jobs`；
6. 删除后更新内存索引；
7. 记录 scanId、删除范围、时间和是否可恢复。

禁止对未解析变量、glob、`~`、根目录或 workspace 根执行递归删除。任务删除路径必须由受信任的 scanId 解析并经过 `normalize/startsWith` 校验。

## 9. 磁盘保护

- 接收请求前检查50 GB最低余量；
- ZIP/SVN获取、Maven、CodeQL和报告阶段持续检查任务/文件系统占用；
- 单任务工作区超过20 GB时取消该任务；
- 低水位停止接收新任务并触发终态清理；
- 紧急低水位不能删除运行任务，但可以请求取消最耗磁盘任务（V1默认仅告警，不自动取消）；
- 报告记录因磁盘导致的失败，不能显示为扫描器零问题。

## 10. 备份与迁移

V1 不自动备份。要迁移：停止服务，确认无子进程，复制 `config/`、`tools/manifest/`、需要保留的 `data/jobs/*/report|raw|logs|job.json`；动态缓存可以重新下载。不要在服务运行时复制可变任务目录并当作一致备份。
