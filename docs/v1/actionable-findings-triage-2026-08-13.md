# 48 条 P1/P2 Finding 逐项真实性复核（2026-08-13）

## 1. 最终结论

本报告复核任务 `c6d3b4ff-c4ea-478b-9c40-607a9ab091d4` 的全部 48 条 P1/P2，
不是抽样。

| 类型 | 报告条数 | 逐项复核结论 |
| --- | ---: | --- |
| 依赖漏洞 | 15 | 15 条均真实命中受影响组件版本；其中 1 条是两个扫描器对同一漏洞的重复证据，因此是 14 个唯一“漏洞 + 组件版本”组合。当前项目源码、配置和运行 JAR 中没有发现相应触发条件，不能据此认定 14 个漏洞当前均可利用 |
| SpotBugs 空指针 | 33 | 25 条属于分析器不知道项目内部路径约束产生的误报；8 条是代码真实存在的边界健壮性缺陷，但当前正常 Web 调用链不会传入相应极端路径 |
| **合计** | **48** | **没有发现一条可直接认定为“当前 Web 服务可被正常用户触发的已确认漏洞/崩溃”**；但 15 条依赖应升级，8 条边界缺陷应修复，不能简单关闭扫描规则 |

这里要区分三个问题：

1. 组件版本是否落在上游公告的受影响范围；
2. 当前应用是否使用了漏洞对应的功能；
3. 外部用户是否能把不可信输入送到该功能。

SCA 工具主要回答第一个问题，SpotBugs 主要回答“是否存在一条理论数据流”。它们都不能单独
证明漏洞已经可利用。

## 2. 复核证据与方法

本次使用了以下证据，而不是只阅读报告标题：

- 逐条读取 `report.json` 中 48 条 Finding、原始引擎、规则、组件 PURL、定位和证据；
- 检查 Maven 依赖关系和 CycloneDX SBOM；
- 检查最终 Spring Boot JAR，确认四个受影响组件确实随服务发布；
- 对每个依赖漏洞查询组件官方安全公告和精确触发条件；
- 在 `backend/`、配置、POM、脚本中检索触发 API、注解和配置；
- 对 33 个 SpotBugs 定位逐个阅读上下文和上游参数来源；
- 使用 JDK 17 对三个可疑路径进行最小运行复现，而不是只靠静态推断。

最终 JAR 中确实存在：

```text
jackson-databind-3.1.4.jar
tomcat-embed-core-11.0.22.jar
jackson-databind-2.21.4.jar
log4j-api-2.25.4.jar
```

在业务源码和运行配置中没有找到以下触发项：

```text
RewriteValve / EncryptInterceptor / FFM Connector + CRL
Tomcat WebSocket chat example / numberguess example
JsonTemplateLayout / MapMessage
@JsonView / @JsonUnwrapped / @JsonIgnoreProperties
ACCEPT_CASE_INSENSITIVE_PROPERTIES / JsonTypeInfo.As.EXTERNAL_PROPERTY
```

“没有找到”是对当前提交、当前配置和当前运行介质的静态结论，不是对未来配置和未来代码的
永久安全承诺。

## 3. 15 条依赖漏洞逐项复核

判定字段说明：

- **版本真实**：最终运行 JAR 中的组件版本处于官方受影响区间；
- **当前条件未发现**：没有发现公告要求的功能、注解或配置；
- **强不适用**：漏洞只属于未随服务发布的示例应用；
- **重复证据**：同一漏洞和组件被两个引擎分别发现，不应算两个独立漏洞。

| Finding | 组件 / 漏洞 | 官方触发条件 | 当前项目证据 | 判定 |
| --- | --- | --- | --- | --- |
| `F-6e419303...` | Tomcat 11.0.22 / CVE-2026-59083 | 使用 RewriteValve，重写 URI 中 `+` 解码可影响特定安全约束 | 无 RewriteValve、重写规则或相关安全约束配置 | 版本真实；当前条件未发现 |
| `F-97df82d8...` | Tomcat 11.0.22 / CVE-2026-59084 | 使用 Tomcat 集群 EncryptInterceptor，并依赖原先不完整的安全配置说明 | 无 Tribes/集群/EncryptInterceptor 配置 | 版本真实；当前条件未发现 |
| `F-a872acd4...` | Tomcat 11.0.22 / CVE-2026-53404 | RewriteValve 的 `ornext` 条件链处理错误 | 无 RewriteValve 配置 | 版本真实；当前条件未发现 |
| `F-ac47329c...` | Tomcat 11.0.22 / CVE-2026-53434 | FFM/OpenSSL Connector 配置了无效 CRL | 无 FFM、自定义 Connector、CRL 配置 | 版本真实；当前条件未发现 |
| `F-b4794ce9...` | Tomcat 11.0.22 / CVE-2026-55276 | 运维或审计依赖 Tomcat 输出的 effective `web.xml`，其中部分授权约束日志不完整 | 项目无 `web.xml`，也未把该日志作为安全控制依据 | 版本真实；当前影响条件未发现，仍需部署配置确认 |
| `F-e7f11027...` | Tomcat 11.0.22 / CVE-2026-66299 | Tomcat WebSocket chat 示例应用的未送达消息缓冲无界 | 最终嵌入式 JAR 不含 examples Web 应用 | 版本真实；**强不适用** |
| `F-30b94010...` | Tomcat 11.0.22 / CVE-2026-50229 | Tomcat number guess 示例应用的通配属性映射造成 XSS | 最终嵌入式 JAR 不含 numberguess/examples | 版本真实；**强不适用** |
| `F-3e1566dd...` | Tomcat 11.0.22 / CVE-2026-55956 | 对 default servlet 配置方法级 security constraint | 无 `web.xml`、default servlet 自定义约束或 Spring Security 约束配置 | 版本真实；当前条件未发现 |
| `F-9271d800...` | Tomcat 11.0.22 / CVE-2026-55955 | 使用集群 EncryptInterceptor 时可遭重放 | 无 Tribes/集群/EncryptInterceptor 配置 | 版本真实；当前条件未发现 |
| `F-e1878797...` | Log4j API 2.25.4 / CVE-2026-49844 | 同时使用依赖 `MapMessage.asJson()` 的 JSON Layout，并记录攻击者可控的 NaN/Infinity 浮点值 | 无 `MapMessage`、`JsonTemplateLayout` 或相应 Log4j 配置；应用使用 SLF4J/默认日志链 | 版本真实；当前条件未发现 |
| `F-4e9d8c87...` | Jackson 3.1.4 / CVE-2026-59889 | 反序列化模型同时使用受限 `@JsonView` 和 `@JsonUnwrapped` 容器属性 | Web 请求 DTO 和代码中均无这两个注解 | 版本真实；当前条件未发现 |
| `F-523ece38...` | Jackson 2.21.4 / CVE-2026-54515 | 同一属性组合使用 `@JsonIgnoreProperties` 和大小写不敏感反序列化 | 无相关注解或 `ACCEPT_CASE_INSENSITIVE_PROPERTIES` | 版本真实；当前条件未发现；与下方 D-C 结果重复 |
| `F-a13f977c...` | Jackson 2.21.4 / GHSA-mhm7-754m-9p8w | `@JsonCreator` 参数同时受 `@JsonView` 限制并使用 `JsonTypeInfo.As.EXTERNAL_PROPERTY` | 无 `@JsonView`、`@JsonCreator`/`EXTERNAL_PROPERTY` 组合 | 版本真实；当前条件未发现 |
| `F-cac00c29...` | Jackson 2.21.4 / CVE-2026-59889 | 反序列化模型同时使用受限 `@JsonView` 和 `@JsonUnwrapped` 容器属性 | 无这两个注解组合；Jackson 2 主要用于内部扫描结果解析 | 版本真实；当前条件未发现 |
| `F-d75468cb...` | Jackson 2.21.4 / CVE-2026-54515 | 与 `F-523ece38...` 相同 | Dependency-Check 的 PURL 少了 Trivy 的 `?type=jar` qualifier，当前去重器未合并 | **重复证据**，不是第 15 个独立漏洞 |

### 3.1 依赖漏洞不是误报，但当前优先级映射偏严

六个 P1 都来自 Tomcat，平台依据 NVD CVSS 把它们映射成了 P1；Apache Tomcat 安全团队对
这六个问题均标为 **Low**。这不是 Dependency-Check 错误，而是平台当前只依据通用 CVSS、
没有把供应商严重度和实际配置纳入优先级的结果。

因此建议：

1. 扫描结果继续保留“受影响版本”事实；
2. 优先升级 Spring Boot/Tomcat、Jackson 和 Log4j BOM，升级比长期豁免更可靠；
3. 升级前为每个漏洞生成精确 VEX，记录 `not_affected` 或 `under_investigation`、理由、证据、
   责任人和到期时间；
4. 报告优先级综合上游供应商等级、可达条件、组件 scope、外部暴露和 KEV，而不是直接把
   NVD 高分等同于当前 P1；
5. 规范化 PURL qualifier，再把同一 CVE/组件合并为一条 Finding，同时保留 D-C 和 Trivy
   两份 evidence。

## 4. 33 条 SpotBugs 逐项复核

这 33 条全部是 `NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE`。SpotBugs 看到的是：
`Path.getParent()`、`Path.getFileName()` 按 Java API 契约“可能返回 null”；它无法天然知道
本项目的任务目录永远形如 `<data>/jobs/<uuid>/...`，也无法跨越所有 Spring Bean 装配证明
工具路径已绝对化并通过健康检查。

判定：

- **FP-INV**：当前生产调用链有可验证的不变量，SpotBugs 未能理解；
- **REAL-COND**：代码对某种合法但极端的 `Path` 确实会 NPE，属于真实边界健壮性缺陷，
  只是当前 Web/API 装配不会传入该值。

| # | Finding / 位置 | SpotBugs 关注点 | 逐项证据 | 判定 |
| ---: | --- | --- | --- | --- |
| 1 | `F-defd81aa...` `CodeqlToolIntegrityChecker:66` | `executable.getParent()` | 运行配置统一转为绝对路径，CodeQL 入口还先通过文件/可执行检查 | FP-INV |
| 2 | `F-79bce58c...` `QuickToolIntegrityChecker:113` | 版本命令首项 `getParent()` | 五个调用点均传入运行路径对象生成的绝对 `java`/工具入口 | FP-INV |
| 3 | `F-1aa9fd61...` `ScanService:1363` | SBOM 目标 `getParent()` | 目标固定由任务布局 `safeResolve("sbom/bom.json")` 生成 | FP-INV |
| 4 | `F-4398ee44...` `SemgrepIntegrityChecker:51` | 连续三次 `getParent()` | 若配置成层级过浅的绝对文件路径，第三次 parent 可为空；当前介质路径层级足够 | **REAL-COND** |
| 5 | `F-327bdb16...` `StandardAnalysisToolIntegrityChecker:195` | 三元表达式重复调用 `getParent()` | `Path` 不可变，同一对象第一次非空后第二次不会变为空 | FP-INV |
| 6 | `F-3b2e6285...` `FileJobStore:49` | `job.json` 的 parent | 路径固定为 `<data>/jobs/<uuid>/job.json` | FP-INV |
| 7 | `F-9689b7dc...` `FileJobStore:66` | 目录 `getFileName()` | 对 `<data>/jobs` 的直接子目录遍历，子目录名必存在 | FP-INV |
| 8 | `F-ccd9bf0b...` `JobRecoveryService:42` | 同上 | 同一目录布局和直接子目录约束 | FP-INV |
| 9 | `F-85428318...` `JobTemporaryFileCleaner:29` | `layout.root().getParent()` | root 固定为绝对 `<data>/jobs/<uuid>` | FP-INV |
| 10 | `F-a588483f...` `BoundedRedactingLogCapture:33` | 日志目标 parent | 仅由执行后端传入工作目录下的 stdout/stderr 文件 | FP-INV |
| 11 | `F-e4eba687...` `LocalProcessExecutionBackend:166` | 命令 `/` 的 `getFileName()` | `Path.of("/").getFileName()` 确实为 null；最小运行已复现 NPE | **REAL-COND** |
| 12 | `F-3ff36108...` `MavenProcessConfiguration:19` | Maven 可执行路径 `/` 的文件名 | `new MavenProcessConfiguration("/", ...)` 已复现 NPE | **REAL-COND** |
| 13 | `F-7b7ddaec...` `ReportArchiveBuilder:31` | archive parent | 最终目标固定在任务 root 下 `report/...`，并先验证不逃逸 | FP-INV |
| 14 | `F-2134ba65...` `ReportArchiveBuilder:34` | 同上 | 同一受控目标 | FP-INV |
| 15 | `F-8fcd8fd9...` `ReportArchiveBuilder:35` | parent/fileName | 同一受控目标必有目录和文件名 | FP-INV |
| 16 | `F-9ed13119...` `CodeqlAdapter:124` | Maven 路径 `/` 在可执行检查后取文件名 | Unix 根目录可能通过 `Files.isExecutable` 后 NPE；生产 resolver 只接受真实 Maven 文件 | **REAL-COND** |
| 17 | `F-d5bbe385...` `CodeqlAdapter:132` | query suite 文件名 | `!Files.isRegularFile(...) || ...` 短路；只有普通文件才取文件名，普通文件不可能是根路径 | FP-INV |
| 18 | `F-a0e87554...` `CodeqlAdapter:265` | 临时数据库路径 `/` 的文件名 | 若 Adapter 被外部调用并把根路径作为临时目录会 NPE；生产固定为 `<job>/codeql-db/database` | **REAL-COND** |
| 19 | `F-3a74dbc6...` `CodeqlAdapter:559` | CodeQL 入口 parent | 自定义构造器若传单段/根路径可能为空；生产 ToolContext 传绝对真实入口 | **REAL-COND** |
| 20 | `F-e33d903f...` `CodeqlAdapter:560` | Maven 入口 parent | 能通过前面的“普通 Maven 文件且文件名为 mvn”检查后 parent 必存在 | FP-INV |
| 21 | `F-775aa2f4...` `CodeqlWorkflow:97` | 删除 DB 时文件名 | 前一个 OR 条件已经检查 parent 为 null；Java 短路保证 null 时不执行文件名比较 | FP-INV |
| 22 | `F-183c725d...` `DependencyCheckAdapter:276` | artifact 文件名 | 只有 `Files.isRegularFile` 为 true 后才取文件名；根目录不是普通文件 | FP-INV |
| 23 | `F-84e0fb50...` `DependencyCheckAdapter:281` | artifact directory 文件名 | 277-279 行已逐级检查 parent 非空 | FP-INV |
| 24 | `F-4a338daa...` `DependencyCheckAdapter:282` | artifact 文件名 | 同第 22 条 | FP-INV |
| 25 | `F-fbd9093d...` `DependencyCheckAdapter:284` | 向上遍历到 `/` 后取文件名 | 若外部 JAR 不在名为 `repository` 的祖先下，循环到根路径会 NPE；生产仓库固定为 `<data>/cache/maven/repository` | **REAL-COND** |
| 26 | `F-e81d5fa6...` `DependencyCheckAdapter:285` | artifact directory parent | 279 行已检查非空 | FP-INV |
| 27 | `F-195d8a2c...` `SpotBugsExecutionSupport:126` | classpath 项文件名 | 只有普通文件才检查 `.jar`；根路径不是普通文件 | FP-INV |
| 28 | `F-c2aefe2c...` `MavenProjectInspector:49` | 根 `pom.xml` parent | 候选来自实际 `pom.xml` 文件，且输入根已绝对化 | FP-INV |
| 29 | `F-9af4c3f9...` `MavenProjectInspector:97` | 模块 POM parent | 遍历结果都是名为 `pom.xml` 的实际文件 | FP-INV |
| 30 | `F-8402294b...` `MavenProjectInspector:122` | moduleRoot | 绝对 `pom.xml` 的 parent，且前面已校验在项目根下 | FP-INV |
| 31 | `F-76f27d32...` `SafeZipExtractor:58` | ZIP 条目目标 parent | 条目经校验后解析到抽取根目录内，文件条目不可能等于文件系统根 | FP-INV |
| 32 | `F-6f178cff...` `SvnKitSourceCheckout:242` | SVN 文件目标 parent | 仓库相对路径解析到任务工作区内，且根条目不是文件输出目标 | FP-INV |
| 33 | `F-e58d7837...` `UploadStager:23` | 上传目标 `/` 的 parent | 公开方法允许传根路径；最小运行已复现 `createDirectories(null)` NPE；生产传任务目录内的 upload 文件 | **REAL-COND** |

### 4.1 运行复现结果

在 JDK 17 中对三类边界输入执行了最小复现：

```text
MAVEN_ROOT=NullPointerException: Path.getFileName() is null
UPLOAD_ROOT=NullPointerException: Files.createDirectories path is null
PROCESS_ROOT=NullPointerException: Path.getFileName() is null
```

这证明不能把 33 条都称为 SpotBugs 误报。正确说法是：

- 25 条在当前项目不变量下不成立；
- 8 条确实缺少边界校验；
- 8 条目前不构成正常 Web 用户可触发的问题，但值得修复，因为未来重构、测试工具或配置变化
  可能打破现有不变量。

## 5. 应该改规则，还是改代码

不应降低 SpotBugs 全局 level，也不应关闭 `NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE`。

推荐顺序：

1. **修复 8 条 REAL-COND**：配置和方法入口统一要求工具为普通可执行文件、目标必须有
   parent/fileName；Dependency-Check 遍历根目录时显式处理 `getFileName()==null`；
2. **让 25 条不变量在代码里显式可见**：把 parent/fileName 保存为局部变量，使用统一的
   `requireParent`/`requireFileName` 帮助方法，并增加不变量测试；这样通常能自然消除告警；
3. 若仍有 SpotBugs 命中，只对精确的 class + method + bug pattern 做过滤，并在 filter 旁写明
   不变量和测试，不做包级/规则级全局排除；
4. 把真实边界测试加入回归：根路径、单段相对工具名、过浅工具目录、非 Maven repository 的
   外部 JAR；
5. SCA 不改“版本匹配”规则，增加的是其后的上下文治理：VEX、可达条件、供应商严重度、
   PURL 归一化和豁免到期检查。

## 6. 建议的处置结果

| 结果组 | 数量 | 建议状态 | 动作 |
| --- | ---: | --- | --- |
| Tomcat 示例应用漏洞 | 2 | `NOT_AFFECTED` | 写入精确 VEX，依据是受影响示例未随嵌入式服务发布；仍随 BOM 升级 |
| Tomcat 配置型漏洞 | 7 | `NOT_AFFECTED` 或 `UNDER_INVESTIGATION` | 由部署配置再确认 RewriteValve、集群、FFM、default servlet/security constraint；设置 VEX 到期时间 |
| Jackson 条件型漏洞 | 4 个唯一组合 / 5 条证据 | `NOT_AFFECTED`（当前提交） | 以注解/API 搜索和 DTO 检查为证据；升级 Jackson；合并重复 CVE-2026-54515 |
| Log4j 条件型漏洞 | 1 | `NOT_AFFECTED`（当前提交） | 以没有 MapMessage/JSON Layout 为证据；升级到 2.25.5+ |
| SpotBugs 真实边界缺陷 | 8 | `CONFIRMED`，但当前不可达 | 修代码和负例测试，不 suppress |
| SpotBugs 项目不变量误报 | 25 | `FALSE_POSITIVE` | 优先重构为显式校验；仍命中时做精确 filter，并绑定回归测试 |

完成依赖升级、8 条边界修复和 25 条显式不变量治理后，再执行同一 Deep Web 扫描。验收目标
不是“强行把 48 变成 0”，而是：

- 依赖版本命中因真实升级而消失，或以有证据、会过期的 VEX 明确展示；
- SpotBugs NP 队列归零，规则本身仍保持开启；
- 新增代码若引入同类问题仍能被发现；
- 报告同时显示“组件受影响事实”和“当前项目可达性结论”，避免把两者混成一个严重度。

## 7. 官方参考

- [Apache Tomcat 11 官方漏洞列表](https://tomcat.apache.org/security-11)
- [Apache Log4j 官方安全公告](https://logging.apache.org/security.html)
- [Jackson CVE-2026-54515 / GHSA-5jmj-h7xm-6q6v](https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-5jmj-h7xm-6q6v)
- [Jackson CVE-2026-59889 / GHSA-5gvw-p9qm-jgwh](https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-5gvw-p9qm-jgwh)
- [Jackson GHSA-mhm7-754m-9p8w](https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-mhm7-754m-9p8w)
