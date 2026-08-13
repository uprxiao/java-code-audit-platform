# 规则治理优化真实复验报告（2026-08-13）

## 1. 结论

本轮优化是合理的，并且已经通过真实发布介质、真实工具和 Web API 复验。

- Deep 档 15/15 引擎成功，没有失败、跳过、超时或 PARTIAL；
- Maven 真实构建 10/10 模块成功；
- 原始命中从 2,093 降到 652，去重 Finding 从 1,814 降到 575；
- 默认待复核队列从 891 条降到 48 条，527 条规范/质量结果明确作为 P3 建议项；
- 高价值能力没有被关闭：依赖漏洞、空指针、注入、密钥、构建治理、SBOM 和 CodeQL 仍全部运行；
- 真实黑盒测试发现的 SpotBugs 定位、OSV 空结果、扫描包缓存污染和测试夹具噪声均已修复。

575 不是 575 个已确认 Bug。正确阅读方式是：先处理 48 个 P1/P2 待复核项，再按团队
计划治理 527 个 P3 建议项。

## 2. 复验对象与证据

| 项目 | 值 |
| --- | --- |
| 扫描任务 | `c6d3b4ff-c4ea-478b-9c40-607a9ab091d4` |
| 档位 | Deep |
| 运行平台 | macOS ARM64，JDK 17，Maven 3.9.12 |
| 发布介质 | `dist/rule-governance/java-code-audit-platform-rule-governance-v7-darwin-arm64.zip` |
| 发布介质 SHA-256 | `47e82aff56cfeed7e1a31acfc9ece3a3068a124bba8086e35a4161fbba36e532` |
| 被扫源码包 | `dist/rule-governance/fixtures/java-code-audit-platform-source-v6.zip` |
| 源码包 SHA-256 | `ddd08e4087e95529df8dce0904e0ba67e020470692ae25a1fd7c1f9d95862751` |
| HTML SHA-256 | `48e18d0e563ff14718391e743eba7a821b6c849b63d6deeb86fd0bfe3dfcaf43` |
| JSON SHA-256 | `0b80c4ddbb18949f2002f642184c2d1d6941a8a74b8af333e5c803de3d8a3866` |
| SARIF SHA-256 | `6023f7a6a057fc6be828e03605ab46cf36ca843cb0ee41b680a3bd2a3dbb9d0a` |
| 报告 ZIP SHA-256 | `67163ac7bab3b45b33bf4868063aa704f966a7c817cb09e3df5401aa76ef039b` |

动态漏洞库未打进 Git 或发布 ZIP，但本次运行使用的是本机生产库：Dependency-Check
元数据标记 `productionUseProhibited=false`、`stale=false`，Trivy 通用库和 Java 库均为
非过期状态。

## 3. 测试范围

### 3.1 自动化回归

JDK 17 全仓执行 `clean verify`：202 tests，0 failures，0 errors，18 skipped。跳过项是需要
显式提供真实外部工具或网络条件的 opt-in smoke；这些能力随后由真实发布介质黑盒扫描覆盖。

### 3.2 真实 Web API 黑盒

从发布 ZIP 中的 JAR 启动服务，经 HTTP 完成 309 次调用（含终态轮询），覆盖：

- health、tools、profiles；
- ZIP 上传和 Deep 扫描；
- 空上传、错误 JSON、非法 profile、非法 Maven 参数；
- ZIP 路径穿越、无 Maven 根、多 Maven 根、JDK 不兼容；
- 任务轮询、15 个引擎列表与单引擎详情；
- Findings 分页、严重度/类别/引擎/模块/文本/抑制状态过滤；
- 单 Finding 详情、未知任务/引擎/Finding 和非法分页；
- HTML、JSON、SARIF、ZIP 四种报告下载；
- 已终态任务取消的错误契约。

### 3.3 引擎终态

| 引擎 | 状态 | Raw hits | 说明 |
| --- | --- | ---: | --- |
| Gitleaks | SUCCEEDED | 0 | 未发现内置高精度密钥模式 |
| Semgrep | SUCCEEDED | 0 | 未发现当前 Java/Spring 安全规则命中 |
| PMD | SUCCEEDED | 35 | 全部归入 P3 质量建议 |
| PMD CPD | SUCCEEDED | 33 | 去重后 24 组重复代码建议 |
| Checkstyle | SUCCEEDED | 440 | 去重后 436 条规范建议 |
| Trivy Repository | SUCCEEDED | 0 | 无仓库密钥、配置和许可证 Finding |
| SpotBugs | SUCCEEDED | 94 | 去重后 53 条，其中 33 条 P2 空值候选 |
| FindSecBugs | SUCCEEDED | 0 | 精确复核并抑制平台自身 7 类已证伪候选后无命中 |
| Dependency-Check | SUCCEEDED | 11 | 使用完整 NVD 生产数据 |
| OSV-Scanner | SUCCEEDED | 0 | 项目无受支持 lockfile；显式成功而非伪装零漏洞 |
| Maven Dependency Analysis | SUCCEEDED | 35 | 去重后 12 条声明治理建议 |
| Maven Enforcer | SUCCEEDED | 0 | dependency convergence 通过 |
| CycloneDX | SUCCEEDED | 0 | 生成 63 组件 SBOM，资产不计 Finding |
| Trivy Artifact | SUCCEEDED | 4 | 从 SBOM 识别 4 条依赖漏洞证据 |
| CodeQL | SUCCEEDED | 0 | 80-query code-scanning suite，无高精度结果 |

## 4. 优化前后对比

| 指标 | 优化前 | 优化后 | 判断 |
| --- | ---: | ---: | --- |
| Raw hits | 2,093 | 652 | 降 68.8%，主要移除宽泛规则和短重复片段 |
| Unique Finding | 1,814 | 575 | 降 68.3% |
| P0 | 0 | 0 | 静态工具不再自动产生“已确认灾难级”结论 |
| P1 | 9 | 6 | 均为需优先复核的依赖漏洞候选 |
| P2 | 882 | 42 | 33 个空值点 + 9 条依赖漏洞证据 |
| P3 | 923 | 527 | 规范、质量、重复、依赖声明治理建议 |
| P0-P2 待复核 | 891 | 48 | 降 94.6%，审计入口从“问题海洋”变为可复核队列 |
| 引擎成功 | 15/15 | 15/15 | 覆盖没有缩水 |

主要引擎变化：PMD 828→35、CPD 414→24、FindSecBugs 35→0、CodeQL 26→0、
Gitleaks 2→0。Checkstyle 428→436 是代码规模和本轮新增测试变化，不是风险变高；它们均为 P3。

## 5. 剩余结果怎么判断

全部 48 条 P1/P2 的逐项源码、配置、官方公告和边界运行复核见
[48 条 P1/P2 Finding 逐项真实性复核](actionable-findings-triage-2026-08-13.md)。

复核结论已实现为可审计、可过期的项目规则治理层，最终介质和三档黑盒结果见
[规则治理优化实施与真实复验报告](rule-governance-implementation-report-2026-08-13.md)。

### 5.1 依赖漏洞：版本命中真实，利用条件需要上下文

报告有 15 条依赖 Finding，对应 14 个唯一“漏洞 + 组件版本”组合；
`CVE-2026-54515` 被 Dependency-Check 和 Trivy 各提供一次证据，目前因 PURL qualifier
不同未合并，这是去重层的后续优化项。

| 组件 | 当前版本 | 结果 | 当前判断与动作 |
| --- | --- | --- | --- |
| Tomcat Embedded | 11.0.22 | 9 个 CVE，其中 6 个映射 P1 | 版本确实受影响；多数仅在 RewriteValve、EncryptInterceptor、FFM、default servlet 特定配置或示例应用下可利用。优先升级到 Spring Boot 提供的更新 Tomcat BOM；`CVE-2026-66299` 只影响 examples webapp，嵌入式服务确认未携带后可做精确 VEX/豁免 |
| Log4j API | 2.25.4 | `CVE-2026-49844` | 官方说明只有 `MapMessage` 非有限浮点值配合 JSON 布局等条件才可达；升级到 2.25.5 或 2.26.1 |
| Jackson 2 | 2.21.4 | `CVE-2026-54515`、`CVE-2026-59889`、`GHSA-mhm7-754m-9p8w` | 与 `@JsonIgnoreProperties` 大小写、`@JsonView`/`@JsonUnwrapped` 等特定反序列化语义有关；升级到 2.21.5 或上游 BOM 的已修版本 |
| Jackson 3 | 3.1.4 | `CVE-2026-59889` | `@JsonView` + `@JsonUnwrapped` 条件性风险；升级到 3.1.5/3.2.1 或更新 Spring Boot BOM |

参考：

- [Apache Tomcat 11 官方安全公告](https://tomcat.apache.org/security-11)
- [Apache Log4j 官方安全公告](https://logging.apache.org/security.html)
- [FasterXML GHSA-5jmj-h7xm-6q6v](https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-5jmj-h7xm-6q6v)
- [FasterXML GHSA-5gvw-p9qm-jgwh](https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-5gvw-p9qm-jgwh)
- [FasterXML GHSA-mhm7-754m-9p8w](https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-mhm7-754m-9p8w)

### 5.2 SpotBugs 空指针：不宜关规则，宜修边界或精确豁免

33 条 P2 都是 `NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE`，集中在
`Path.getParent()`、`getFileName()` 等 Java API 返回值。

抽查结论：大部分路径来自平台内部 `resolve()`、绝对化或任务目录布局，实际为空的概率低；
少量位于工具可执行路径、上传路径、归档目标等边界，增加显式 `requireNonNull` 或输入校验会更稳。

因此不能把 NP 规则全局关闭。建议按以下顺序处理：

1. 对外部输入和配置路径显式校验并返回可理解的错误；
2. 对内部路径先保存 `parent/fileName` 局部变量，再校验一次，既提高可读性也让分析器理解；
3. 只有能写出“不可能为空”证明和回归测试时，才对具体类/方法/规则做精确抑制；
4. 修复后把 33 条作为基线，要求新增代码不增加该规则数量。

### 5.3 P3 建议项：不是 Bug，不阻断安全发布

527 条建议项由 Checkstyle 436、PMD 35、CPD 24、SpotBugs 20、Maven 依赖治理 12 组成。
主要规则是 `NeedBraces` 211、`LineLength` 181、`AvoidStarImport` 22、
`PreserveStackTrace` 18 和重复代码 24 组。

这些适合作为代码整洁度 backlog 或“只检查新增代码”的质量门禁，不应与 P1/P2 一起阻断。
阿里 Java 规范可以增加，但应作为独立可选 profile，不能把全部规范结果重新升级成 Bug。

## 6. 真实测试发现并修复的问题

| 问题 | 根因 | 修复 |
| --- | --- | --- |
| SpotBugs/FindSecBugs 过滤器无法解析 | XML 注释中包含非法的连续连字符 | 改为合法注释，并在真实 smoke 中强制 coverage=SUCCEEDED、warnings 为空 |
| OSV 扫到大量本机缓存 POM | 自审 ZIP 意外包含运行数据和 Maven cache | 源码包改为受控文件清单，严格排除 data/cache/target/下载目录和嵌套 fixture POM |
| 无 lockfile 项目 OSV exit 128 | OSV 默认把无包源当失败 | 固定 `--allow-no-lockfiles`，同时排除构建和缓存目录 |
| OSV 合法空结果被拒绝 | 2.3.8 输出 `results: null`，校验器只接受数组 | 允许“数组或显式 null”，缺失字段/错误类型仍失败 |
| SpotBugs 报告定位到类起始行 | 归一化器取了第一个 SourceLine，而不是 `SOURCE_LINE_DEREF` | 优先使用真实解引用行并增加回归 fixture |
| 测试 Dockerfile 产生自审建议 | 健康 fixture 缺 HEALTHCHECK | 增加 `HEALTHCHECK NONE`，真实 Trivy 0.73.0 验证 0 failure |
| 测试密钥/坏代码进入自审 | 负例长期存放在仓库源码 | 真实测试运行时动态生成坏样本，仓库 fixture 保持无命中 |

这说明真实黑盒复验有价值：只看 Adapter 单元测试无法发现介质打包、真实 CLI 退出码、
报告定位和扫描输入污染等系统性问题。

## 7. 下一轮优化优先级

1. **先升级依赖 BOM**：Tomcat、Log4j、Jackson；升级后重跑 Deep，目标是消除版本命中。
2. **处理 33 个 Path 空值点**：优先外部输入和配置边界，不全局 suppress NP。
3. **SCA 上下文治理**：引入 VEX、scope、直接/传递、可达性、上游 severity；P1 表示“优先复核”，不是“已被利用”。
4. **规范增量门禁**：保存基线，只阻断新增 P3；可增加独立 `ALIBABA_STYLE` profile。
5. **规范化 PURL 再去重**：忽略无关 `?type=jar` qualifier 后合并同一 CVE/组件，同时保留多引擎 evidence。
6. **规则注册表**：每条自定义规则记录 owner、来源、版本、适用范围、正反例、默认/strict 状态和到期日。
7. **审核反馈闭环**：把人工 TP/FP/接受风险写入抑制/VEX 文件并要求原因、责任人、到期时间；不要让 AI 自动隐藏 Finding。

## 8. 最终判断

当前默认配置已经从“工具原始输出集合”变成了可用的审计入口：

- 安全和正确性候选优先；
- 规范建议单独展示；
- 规则命中可追溯到引擎、原始等级和映射理由；
- 所有引擎失败都会显式暴露，不会被当成零问题；
- 仍保留人工复核和逐项目治理空间。

它不是“零误报”的证明，也不应该追求零结果。下一阶段的正确目标是：升级依赖、关闭已确认的
33 个空值候选、对 P3 使用增量门禁，并用真实项目的 TP/FP 反馈持续校正规则。
