# V1 本机生产就绪验证报告（2026-08-12）

## 1. 结论

本轮验证对象是最终 macOS ARM64 发布介质，而不是 IDE、Mock 扫描器或仅在 Maven
测试进程内运行的组件。结论如下：

- Dependency-Check 的完整生产 NVD 数据、Trivy 通用库和 Java 库已经下载到本机，
  并由启动健康检查验证来源、版本、时间和完整性；
- 从最终发布 ZIP 解压并启动的同一个 Spring Boot JAR，已使用真实 Java 17 Maven
  项目完成 Quick、Standard、Deep 三档扫描，15 个引擎全部成功；
- ZIP、匿名 SVN、带用户名密码的 SVN、HEAD 和固定 revision 均已真实验证；
- REST API 的正常、非法输入、异步失败、分页过滤、报告、安全、限流、低磁盘、
  过期、取消、并发、崩溃恢复和单实例边界均已覆盖；
- 本轮真实测试发现了若干只有完整数据、真实多模块项目和真实 CodeQL 才能暴露的
  问题。问题均已定位根因、修改实现、补充回归测试，并重新执行发布介质验收；
- 最终全仓 JDK 17 回归为 60 个测试套件、200 个测试、0 failure、0 error、
  18 个按环境条件跳过的 opt-in 真实测试。

因此，V1 在已经冻结的边界内可以判定为“本机生产就绪”。这里的生产就绪不改变
安全模型：扫描器和 Maven 在宿主机直接执行，只能接收维护者信任且有权审计的代码，
不能作为面向任意公网恶意上传的隔离沙箱。

## 2. 最终验证对象

| 项目 | 最终值 |
| --- | --- |
| 操作系统 | macOS ARM64 |
| Java | JDK 17.0.18，class major 61 |
| Maven | 3.9.12，服务器预装 `/opt/homebrew/bin/mvn` |
| 发布 ZIP | `dist/production-readiness/java-code-audit-platform-production-ready-final-v4-darwin-arm64.zip` |
| 发布 ZIP SHA256 | `7d5d7f93de3790cfd2d4e0dd26a8db1dc652a9dfe7d01d98f7cffdce37bf9af9` |
| 发布 ZIP 大小 | 315 MB |
| 介质完整性清单 | 6,163 项；启动后再次校验通过 |
| 应用形态 | 一个 Spring Boot fat JAR + 固定版本工具包 + 配置/规则 |
| 状态存储 | 本地文件系统；无数据库服务 |

发布包内的工具文件在组装时移除 owner write 权限，启动校验除 SHA256 外也拒绝可写
的内置工具文件。运行数据、缓存、报告和动态漏洞库不属于不可变工具目录。

## 3. 本机生产漏洞数据

### 3.1 Dependency-Check / NVD

生产数据目录为 `tools/downloads/databases/dependency-check/`，由 `.gitignore` 排除，
不会把约 239 MB 的动态数据提交到 Git。

| 属性 | 值 |
| --- | --- |
| Dependency-Check | 12.2.2 |
| NVD 来源 | NIST/NVD 官方 JSON 2.0 data feed |
| 范围 | 2002 至 2026 年年度 feed + modified feed；同时完成 CPE/KEV 维护数据更新 |
| H2 文件 | `odc.mv.db` |
| 文件大小 | 247,476,224 bytes |
| SHA256 | `68849405b08106d0548b396ec65b9ee95c08a4a29898840c15779179843df256` |
| 更新时间 | `2026-08-12T11:39:38Z` |
| 元数据模式 | `production-full` |
| `productionUseProhibited` | `false` |

启动门禁不再把“存在任意 `odc*.mv.db`”当作可用，而是同时检查：

1. 固定 Dependency-Check 版本；
2. `database-metadata.json` 的 schema、数据源和 `production-full` 标记；
3. 禁止 `ACCEPTANCE-ONLY.txt` 和 `productionUseProhibited=true`；
4. 数据库文件名、大小和 SHA256 必须与元数据一致；
5. `updatedAt` 合法并计算陈旧状态。

除启动健康检查外，还用生产库直接扫描了两个跨年代的 Maven 组件：
`commons-fileupload:commons-fileupload:1.3.1` 与
`org.apache.logging.log4j:log4j-core:2.14.1`。报告成功产生精确 Maven PURL，
并命中 `CVE-2021-44228` 等 Log4Shell 漏洞。证据位于
`dist/production-readiness/dependency-check-production.EpkiFX/report/`。

### 3.2 Trivy

生产缓存位于 `tools/downloads/databases/trivy/`，约 2.5 GB，同样不提交 Git。

| 数据 | 文件 | 数据时间 |
| --- | --- | --- |
| 通用漏洞库 | `db/trivy.db` | `2026-08-12T07:34:54Z` |
| Java 漏洞库 | `java-db/trivy-java.db` | `2026-08-12T01:10:41Z` |
| 本地分析缓存 | `fanal/fanal.db` | 随扫描维护 |

Standard/Deep 必须同时具备通用库和 Java 库；缺少任意一个都会显示
`VULNERABILITY_DATABASE_UNAVAILABLE`，不会返回“零漏洞”。扫描执行使用本地库和
`--offline-scan`，不会在任务过程中偷偷更新数据库或因网络结果变化而漂移。

### 3.3 CodeQL

CodeQL 是 Deep 的本机可选能力，不进入公开发布包：

- CLI：2.26.2，约 2.8 GB；
- Java query pack：`codeql/java-queries` 1.11.7，约 109 MB；
- suite：`java-security-and-quality.qls`；
- 必须同时设置 `AUDIT_CODEQL_ENABLED=true` 和
  `AUDIT_CODEQL_TERMS_ACCEPTED=true`。

“不进入公开包”是许可/使用条款边界，不等于没有安装。本轮 Deep 验收实际调用了
本机 CodeQL，并真实完成数据库初始化、受控 Maven 构建跟踪、数据库 finalize、SARIF
分析与数据库清理。

### 3.4 数据更新方式

源码树使用：

```bash
scripts/update-standard-vulnerability-data.sh
```

发布介质使用：

```bash
bin/update-vulnerability-data.sh
```

有 `NVD_API_KEY` 时使用 NVD API；无 Key 时默认使用 NVD 官方 JSON 2.0 feed；内网也
可以用 `NVD_DATAFEED_URL` 指向受控镜像。更新在临时目录完成，校验成功后原子切换，
避免半成品成为活动生产库。

## 4. 三档真实扫描结果

### 4.1 小型验收项目

该 Fixture 是真实 Java 17 Maven 项目，包含 Log4j 2.14.1 和可被 CodeQL 命中的命令
注入数据流。扫描由最终发布 JAR 的 Web API 发起。

| Profile | Scan ID | 引擎 | 终态 | 耗时 | unique/raw | 关键断言 |
| --- | --- | ---: | --- | ---: | --- | --- |
| Quick | `129d188d-608e-4ee9-9f94-909a8f550661` | 6 | COMPLETED | 6.448 s | 0/0 | 6 个引擎全成功，归档安全 |
| Standard | `b073b200-0564-4f9a-b4d0-ae679c041f51` | 14 | COMPLETED | 39.621 s | 29/29 | D-C/OSV/Trivy 均命中 Log4j；SBOM 存在 |
| Deep | `165b5c13-aae0-47f3-8116-1622d470cea8` | 15 | COMPLETED | 42.768 s | 30/30 | CodeQL 命中 `COMMAND_INJECTION` |

每档都下载并解压校验 report ZIP，确认 canary/凭据不在报告中，且归档不含 workspace、
源码、`target`、`.m2`、CodeQL database 或工具 HOME/cache。

### 4.2 对平台自身的真实扫描

把当前项目收敛成单个根 Maven 项目的源码 ZIP 后，再通过 Web API 扫描平台自身：

| Profile | Scan ID | 终态 | 耗时 | unique/raw |
| --- | --- | --- | ---: | --- |
| Quick | `a49e22cf-ef9c-4e8e-bccd-e1e5b2931f2a` | COMPLETED | 11.108 s | 1,672/1,803 |
| Standard | `ce065207-fb74-4e7b-a49c-2d36421bcabc` | COMPLETED | 30.798 s | 1,788/2,066 |
| Deep | `8d8c1be1-f645-46e1-a9ad-bd251d9ba699` | COMPLETED | 101.424 s | 1,814/2,093 |

Standard 的 14 个引擎和 Deep 的 15 个引擎均为 `SUCCEEDED`，没有把 partial、解析失败
或缺库伪装成成功。Deep 中 CodeQL 产生 27 个 raw finding，完整工作流耗时约 70.8 秒，
成功后临时数据库不存在。

## 5. REST API 覆盖

### 5.1 正常主链路

| API | 已验证行为 |
| --- | --- |
| `GET /api/v1/health` | JDK/Maven/平台/磁盘/工具/数据库总体健康 |
| `GET /api/v1/tools` | 15 个引擎版本、入口 SHA、原因码和数据库状态 |
| `GET /api/v1/profiles` | Quick/Standard/Deep 可用性及档位别名 |
| `POST /api/v1/scans/zip` | 三档创建、Location、异步 QUEUED、真实扫描 |
| `POST /api/v1/scans/svn` | 匿名/认证、HEAD/固定 revision、URL 脱敏 |
| `GET /api/v1/scans/{id}` | 全生命周期、进度、build、summary、下载链接 |
| `GET .../engines`、`.../engines/{engine}` | 引擎状态、版本、覆盖、raw/log 可用性 |
| `GET .../findings` | 分页及 severity/category/engine/module/text/suppressed 过滤 |
| `GET .../findings/{id}` | 单 Finding 与未知 ID 错误 |
| `GET .../reports/{html,json,sarif,archive}` | 四种报告、Content-Type、归档哈希与安全校验 |
| `POST .../cancel` | 运行中取消、重复取消、终态取消幂等语义 |
| `DELETE /api/v1/scans/{id}` | 终态删除及后续不可查询 |

### 5.2 输入和异步失败

真实 HTTP 测试覆盖：空文件、错误 JSON、错误 profile、不允许的 Maven 参数、ZIP 路径
穿越、没有 Maven 根、多个 Maven 根、Java 21 项目、未知任务、非法 UUID、报告尚未
生成、未知 Finding/引擎、非法分页和过滤条件。异步输入失败会落明确 failure code，
不会生成虚假报告。

### 5.3 HTTP/资源边界

| 场景 | 最终结果 |
| --- | --- |
| 上传超过配置上限 | `413 ARCHIVE_LIMIT_EXCEEDED` |
| 队列容量 1、并发 1，同时提交 6 个任务 | 2 接收、4 返回 `429`，四个 `Retry-After=30` |
| 可用磁盘低于门限 | `507 DISK_SPACE_LOW` |
| 成功报告保留 5 秒 | 到期前 200 且 ZIP 可解；清理后 `410 REPORT_EXPIRED` |
| 同一 data root 启动第二实例 | 启动失败，`InstanceAlreadyRunningException` |

## 6. 并发、取消与恢复

| 验证 | 结果 |
| --- | --- |
| 20 个真实 Quick 任务 | 全部接收并 COMPLETED；配置并发 2，观察峰值 2 |
| 2 个真实 Deep 任务 | 两个均 COMPLETED；观察峰值 2，无 Maven/CodeQL permit 死锁 |
| 运行中取消 | 首次和重复请求均安全；最终 CANCELLED；其他并发任务完成 |
| 运行中进程被 `SIGKILL` | 第一次重启即可查询为 INTERRUPTED |
| 已完成任务跨重启 | 报告仍为 200 且 ZIP 校验通过 |
| 排队任务跨崩溃 | 自动重新入队，由 RUNNING 进入 COMPLETED，报告可下载 |

CodeQL 现在需要同时占用 `maven` 和 `codeql` 工具许可。许可按固定顺序原子获取，
释放覆盖成功、异常、取消和调度关闭；真实双 Deep 验证没有发生循环等待。

## 7. SVN 与凭据安全

本地真实 `svn://` 仓库分别建立匿名目录和用户名密码目录，导入去除额外 Maven 根的
当前源码快照。四次 Quick 扫描分别覆盖两种认证方式下的 HEAD 与数字 revision：

- 匿名：`1f22ae41-...`、`624c135e-...`；
- 认证：`ef656ecf-...`、`52c57c8f-...`；
- 四者固定 revision 均为 `svn:2`，snapshot SHA256 一致；
- API/报告只保存掩码 URL、URL SHA、最终 revision 与 snapshot SHA；
- 测试密码在 API 证据、任务目录、报告和归档中的精确值扫描均为零命中。

另有 Apache 官方 HTTPS SVN 的 HEAD 和固定 revision 真实 smoke。`svn+ssh`、`file`、
URL user-info/query/fragment、externals 和特殊链接按 V1 输入策略拒绝。

## 8. 真实测试发现的问题与修复

| 问题 | 真实表现 | 根因 | 修复和回归 |
| --- | --- | --- | --- |
| 生产 NVD 与验收库无法区分 | 小型 2021 smoke 库也可能让 Standard 显示可用 | 只检查任意 H2 文件存在 | 引入生产来源元数据、SHA/大小/版本/模式门禁；验收库明确拒绝 |
| 首次 NVD 初始化极慢 | 无 Key 的 NVD API 初始化长时间等待 | 未设置无 Key 的批量 feed 策略 | 无 Key 默认官方年度 JSON 2.0 feed；原子激活并落 SHA 元数据 |
| Dependency-Check 对真实多模块项目 partial | 重复扫描 reactor JAR/Spring Boot 嵌套 JAR，部分依赖缺 PURL | 对整个 workspace 递归扫描 | Maven 同一 reactor 生成受控 runtime classpath；D-C 仅扫描外部 Maven JAR，精确 PURL 回归 |
| Maven classpath 二次调用失败 | sibling reactor module 未 install 时无法解析 | package 和 dependency:build-classpath 分成两个 Maven 会话 | 合并到同一固定 Maven invocation，保留无 shell/无用户 goal 约束 |
| CodeQL buildless partial | 前端依赖推断不一致，出现 Java 编译/解析错误 | `--build-mode=none` 不适合真实自定义 Maven reactor | 改为 init → 固定 Maven trace → finalize → analyze 四阶段手工构建跟踪 |
| CodeQL 与其他 Maven 引擎竞态 | Deep 可在继承引擎未结束时 `clean` target | DAG 只依赖统一 Maven build，不依赖全部 Standard 引擎 | CodeQL 等待 14 个继承引擎，并同时持有 Maven/CodeQL permits |
| CodeQL 成功后偶发变失败 | 清理数据库时某个动态 cache 路径已消失 | `Files.walk` 快照后逐项 `Files.delete` 存在 TOCTOU | 受限目录 `walkFileTree + deleteIfExists`，忽略 `NoSuchFileException`；嵌套 cache 回归 |
| 报告脱敏二次校验误报 | 已掩码值和转义 JSON/HTML 可能再次被判敏感 | `containsSensitiveData` 等同再次执行会修改文本的 redact | 独立只读检测、识别掩码、覆盖 JSON/HTML 引号；幂等与 canary 回归 |
| 扫描阶段存在外部网络漂移 | D-C Central analyzer、Trivy 在线分支可能访问网络 | 离线意图没有固定到 CLI 参数 | D-C `--disableCentral`，Trivy Repository `--offline-scan`；命令契约测试 |
| 发布目录可被误改 | 单纯 SHA 校验只在启动时发现，且工具可写 | 介质工具权限未冻结 | 组装时工具目录只读，验证器拒绝可写文件，启动前后校验 |
| Standard/Deep 运行中 build 状态显示 NOT_REQUIRED | API 在报告生成前固定返回 NOT_REQUIRED | 临时 DTO 未按 profile/job 状态派生 | Quick 保持 NOT_REQUIRED，Standard/Deep 映射 PENDING/RUNNING/终态并回归 |

这些修复不是为“让测试变绿”而放宽判定。相反，缺库、数据来源不可信、解析不完整、
工具输出损坏和工作区变化都会明确失败或 partial，不会冒充零问题。

## 9. 自动化回归

最终命令：

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@17 \
  ./mvnw -q clean verify \
  -Daudit.maven.executable=/opt/homebrew/bin/mvn
```

结果：60 个测试套件，200 tests，0 failures，0 errors，18 skipped。跳过项是默认关闭的
真实外部工具/网络 smoke；本报告所列的 Semgrep、Quick 五引擎、Standard 八引擎、
Dependency-Check 生产库、CodeQL、SVN 和发布 JAR 均已另行显式真实执行。

额外完成：

- 发布包 SHA256 全量验证和解压后启动验证；
- Shell 脚本 `bash -n`；
- 三个生产验收 Python 驱动的 `--help`/实际执行；
- `git diff --check`；
- 所有临时 Web/SVN 服务已停止，无遗留扫描子进程。

## 10. 证据位置与复现

大体积证据和动态库位于 `.gitignore` 覆盖的本机目录。核心目录：

- `dist/production-readiness/evidence/final-v4-api-all-profiles/`
- `dist/production-readiness/evidence/final-v4-release-acceptance/`
- `dist/production-readiness/evidence/final-v4-concurrency-20-quick/`
- `dist/production-readiness/evidence/final-v4-concurrency-2-deep/`
- `dist/production-readiness/evidence/final-v4-cancel-running/`
- `dist/production-readiness/evidence/final-v4-svn-anonymous-sanitized/`
- `dist/production-readiness/evidence/final-v4-svn-authenticated-sanitized/`
- `dist/production-readiness/evidence/final-v4-upload-limit-413/`
- `dist/production-readiness/evidence/final-v4-queue-full-429/`
- `dist/production-readiness/evidence/final-v4-low-disk-507/`
- `dist/production-readiness/evidence/final-v4-retention-410-final/`
- `dist/production-readiness/evidence/final-v4-crash-recovery-active-final/`
- `dist/production-readiness/evidence/final-v4-queued-recovery/`
- `dist/production-readiness/evidence/final-v4-instance-lock/`

可重复驱动：

- `scripts/production-readiness-api.py`
- `scripts/production-readiness-concurrency.py`
- `scripts/production-readiness-svn.py`
- 发布介质 `bin/acceptance-test.sh`

## 11. 保留边界

- Linux Ubuntu 22.04 x86_64 已有 GitHub Actions 的 Quick/Standard/Deep 原生介质验收；
  本轮生产全量数据库下载和详尽接口压力验证是在本机 macOS ARM64 完成的；
- 动态漏洞库不嵌入 315 MB 发布 ZIP，需要部署后运行更新脚本或复制已验证的数据目录；
- CodeQL 不随公开介质分发，需要部署机器自行安装并显式确认适用条款；
- V1 没有认证、前端、数据库服务、AI 复核和历史基线；
- Maven 构建会执行项目插件/生命周期，因此当前只面向可信项目，不是恶意代码沙箱；
- NVD/Trivy 数据会随时间陈旧，应周期更新，并以 `/health` 的 database 状态作为调度门禁。
