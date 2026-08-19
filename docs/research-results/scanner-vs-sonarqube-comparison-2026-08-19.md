# 自研 15 引擎扫描器与 SonarQube 同源对比及 Codex 独立复核

日期：2026-08-19

结论适用提交：`34ad1c686106d92ee5c9d979d1f6b294deb0bfbb`

## 1. 先说结论

这次“双探测 + Codex 独立分析”是有价值的，而且已经发现了只看任意一份报告都不容易发现的问题。

1. 自研平台的覆盖面明显更广。它除了 Java 源码质量，还实际覆盖了字节码缺陷、密钥、Maven 依赖治理、SBOM、依赖漏洞和 CodeQL 安全查询；SonarQube 本次社区版分析主要覆盖 Java 可靠性、可维护性、测试代码、重复代码和文本密钥。
2. SonarQube 在认知复杂度、重复字面量、正则性能、测试断言写法等“可维护性”规则上更丰富；自研平台当前的 Checkstyle 规则更严格，因此产生了大量换行、花括号之类的规范问题。
3. 两套系统不是“谁报得多谁更准”。自研平台最终得到 595 条问题，SonarQube 得到 275 条问题，但只有 17 条问题可按“同文件、同一行、同一语义”直接相互印证，落在 16 个源码点。其余大部分是双方规则范围不同，不是必然漏报。
4. 自研平台的 595 条里，456 条是代码规范、25 条是重复代码、12 条是 Maven 治理、14 条是依赖漏洞。真正应优先处理的不是 595 条，而是治理结果中的 1 条 ACTIONABLE 和 15 条 CONDITIONAL；进一步人工复核后，唯一 ACTIONABLE 的 Gitleaks 告警实际也是上下文误报。
5. SonarQube 标为 BUG 的 18 条也不能直接当成 18 个真实生产 Bug。Codex 逐组核对后：1 条具有明确的资源耗尽加固价值，8 条属于同步设计加固建议，8 条在当前上下文中很可能不构成真实缺陷，1 条仅影响测试代码写法。
6. 本次最重要的发现反而来自 Codex 的系统级复核：发行介质缺少源码 commit 追溯、CodeQL 健康检查与执行约束曾不一致、源码片段提取会把最大 1GB 文件整体读入服务 JVM。这些都不是比较两个报告总数能直接看出来的问题。

因此，推荐采用三层结论：

- 第一层：扫描引擎保留尽可能完整的原始事实；
- 第二层：规则治理把事实分成 ACTIONABLE、CONDITIONAL、ADVISORY、FALSE_POSITIVE；
- 第三层：Codex/人工只复核高优先级、跨工具冲突和系统级风险。

## 2. 公平对比的输入与可追溯性

两套系统使用同一份不可变源码 ZIP：

| 项目 | 值 |
| --- | --- |
| Git commit | `34ad1c686106d92ee5c9d979d1f6b294deb0bfbb` |
| 输入 ZIP SHA-256 | `78035783583f3919e02eea3e2db8d5bbc8198584fe824c2fda92396f00b8f76d` |
| Java 文件 | 269 |
| Maven 根 | 1 个 reactor，10 个模块 |
| 排除项 | 仅排除仓库内嵌的独立 Maven 测试 fixture：`backend/scanner-adapters/src/test/resources/fixtures/**`、`packaging/fixtures/**` |

排除 fixture 是必要的。平台 API 按产品约束只接受一个 Maven 根，而这些 fixture 是用于测试各扫描器解析器的独立小项目，不属于被评测产品源码。SonarQube 也使用相同过滤后的 ZIP，避免一方扫描 fixture、另一方不扫描。

自研平台不是直接使用无法证明源码版本的旧介质，而是从上述 commit 重新执行 JDK 17 全仓构建：216 tests，0 failure，0 error，21 skipped。最终运行 JAR SHA-256 为：

`d825bb7b34e19d7e85b243d01093aa4d9f9c584d16578fba59d26b8fce7922e7`

这一过程也暴露了发行问题：现有 `release-manifest.json` 记录了 JAR 哈希，但没有记录源码 commit、工作树是否干净、规则包哈希和 CodeQL 查询集哈希。因此旧介质即使能运行，也不能严格证明与待测 commit 一致。

## 3. 两套扫描实际运行情况

### 3.1 自研平台

最终有效任务：`c4e61183-3992-4074-b11a-f19b83ebec79`，状态 `COMPLETED`，15/15 引擎成功，10/10 Maven 模块构建成功。

| 引擎 | 版本 | 原始命中 | 本次作用 |
| --- | ---: | ---: | --- |
| Checkstyle | 12.3.1 | 460 | 代码格式、花括号、行长、import 等规范 |
| CodeQL | 2.26.2 | 0 | 官方 `java-code-scanning.qls` 安全查询 |
| CycloneDX | 2.9.3 | 0 Finding | 生成 63 组件 SBOM，不把每个组件当问题 |
| Dependency-Check | 12.2.2 | 11 | NVD 依赖漏洞 |
| FindSecBugs | 1.14.0 | 0 | 字节码 Web/Java 安全规则 |
| Gitleaks | 8.30.1 | 1 | 硬编码密钥与凭据模式 |
| Maven Dependency Analysis | 3.9.0 | 36 | 已使用未声明、已声明未使用依赖 |
| Maven Enforcer | 3.6.2 | 0 | 依赖收敛 |
| OSV-Scanner | 2.3.8 | 0 | OSV 在线依赖漏洞 |
| PMD | 7.26.0 | 35 | 正确性、资源、未使用代码 |
| PMD CPD | 7.26.0 | 34 | 复制粘贴代码块 |
| Semgrep | 1.170.0 | 0 | 仓库自定义 Java 安全规则 |
| SpotBugs | 4.9.3 | 85 | Java 字节码正确性与潜在空指针 |
| Trivy Artifact | 0.73.0 | 5 | 基于 SBOM 的漏洞匹配 |
| Trivy Repository | 0.73.0 | 0 | 仓库密钥、配置和 IaC |

Trivy 通用漏洞库和 Java 漏洞库在扫描前更新到 2026-08-19；第一次因 7 天旧库被平台主动标为 PARTIAL，更新后重跑才作为最终结果。这说明“陈旧数据不允许伪装为零漏洞”的门禁有效。

最终结果：

| 统计 | 数量 |
| --- | ---: |
| 原始命中 | 667 |
| 归一化、去重后 | 595 |
| P0 / P1 / P2 / P3 | 0 / 7 / 41 / 547 |
| ACTIONABLE | 1 |
| CONDITIONAL | 15 |
| ADVISORY | 579 |
| 已人工治理为 FALSE_POSITIVE | 25 |
| 已确认但仅在边界条件成立时触发 | 8 |

### 3.2 SonarQube

| 项目 | 值 |
| --- | --- |
| SonarQube | 26.8.0.126808 |
| Java Quality Profile | 内置 `Sonar way`，571 条激活规则 |
| 未解决问题 | 275 |
| BUG / CODE_SMELL | 18 / 257 |
| MAIN / TEST | 225 / 50 |
| vulnerabilities / hotspots | 0 / 0 |
| ncloc | 16,660 |
| 重复块 / 重复行 / 重复率 | 63 / 527 / 2.8% |
| 覆盖率 | 0%（公平对比使用固定 `-DskipTests` 构建，没有导入 JaCoCo） |

SonarQube 页面显示 Quality Gate 为 `OK`，但 API 返回的 gate conditions 是空数组。也就是说，这个“通过”不是“275 条都没有风险”，而是当前项目没有配置一组可执行的门禁条件，不能作为质量合格证明。

SonarQube 命中最多的规则：

| 规则 | 数量 | 实际含义 |
| --- | ---: | --- |
| `java:S1192` | 83 | 重复字符串字面量，维护性 |
| `java:S5778` | 25 | 测试 lambda 中存在多个可能抛异常的调用 |
| `java:S3776` | 19 | 认知复杂度超过 15 |
| `java:S4165` | 15 | 认为赋值无效；本项目全部落在 Java record 紧凑构造器，属于分析误判 |
| `java:S8786` | 14 | 正则可能出现超线性回溯 |
| `java:S1128` | 12 | 未使用 import |
| `java:S3358` | 12 | 嵌套三元表达式 |
| `java:S2445` | 8 | 在方法参数对象上加锁 |
| `java:S3077` | 6 | 认为 volatile 引用不足以保证线程安全 |

## 4. 客观对比：交集、独有和不可比较

### 4.1 可直接相互印证的交集

使用保守条件：同一项目相对路径、同一开始行、显式维护的语义规则映射。结果为：

| 语义 | 自研规则 | Sonar 规则 | 匹配数 |
| --- | --- | --- | ---: |
| 未使用 import | `UNUSED_IMPORTS` | `java:S1128` | 12 |
| 未使用 private 方法 | `UNUSED_PRIVATE_METHOD` | `java:S1144` | 2 |
| 未使用 private 字段 | `UNUSED_PRIVATE_FIELD` | `java:S1068` | 1 |
| 未使用局部变量 | `UNUSED_LOCAL_VARIABLE` | `java:S1481` / `java:S1854` | 2 对 |
| 无效局部存储 | `DLS_DEAD_LOCAL_STORE` | `java:S1854` | 1 |

共有 18 组规则配对、双方各 17 条唯一问题，落在 16 个源码点。局部变量同一源码点被两套系统各自拆成多个规则，因此“配对数”大于“源码点数”。这些交集基本都是真实存在的低风险清理项，但不代表高危 Bug。

### 4.2 自研平台独有或明显更强的范围

- 14 条依赖漏洞，覆盖 4 个组件；Sonar 本次日志明确为 `Dependency analysis skipped`，不能拿 Sonar 的 0 vulnerabilities 与这 14 条相互否定。
- 12 条 Maven 依赖治理问题：9 类已使用未声明、3 类已声明未使用。36 条模块原始命中被归并为 12 个问题。
- 1 条 Gitleaks 凭据模式。
- 33 条 SpotBugs 空指针边界、18 条 PMD 异常栈保留建议。
- Checkstyle 的 225 条缺少花括号、184 条超 120 字符行等团队规范。
- CycloneDX 输出完整 SBOM；SBOM 组件不是问题，不能计入 Finding 总数。

### 4.3 SonarQube 独有或明显更强的范围

- 83 条重复字面量、19 条认知复杂度、12 条嵌套三元表达式；自研规则集目前没有等价规则。
- 25 条测试异常断言写法、7 条测试 `Thread.sleep` 等测试代码质量规则。
- 14 条正则回溯性能提示，其中部分与不可信输入处理有关，值得保留。
- Sonar 的重复代码以 63 个块、527 行、2.8% 统计；自研 CPD 以 34 个原始 clone group、25 条归一化 Finding 统计。二者都证明存在重复代码，但计数单位不同，不能直接用 25 对比 63。

### 4.4 为什么交集只有 17 条

交集小不等于某一方不准。两个系统使用的规则集合、分析层次和计数模型不同：

- SpotBugs 看编译后的 JVM 字节码；SonarJava 主要看语法树和语义模型；
- Checkstyle 看团队格式规范；Sonar way 默认不强制 120 字符和所有 `if` 花括号；
- Dependency-Check/Trivy 看组件版本和漏洞库；Sonar 本次没有执行 SCA；
- Sonar 的复杂度和测试规则没有被当前 PMD/Checkstyle 规则集启用。

因此，交集只能作为“独立工具相互佐证”，不能直接计算 precision 或 recall。真正的准确率仍需要独立真值 Benchmark。

## 5. Codex 对关键告警的独立判断

### 5.1 自研平台

#### Gitleaks 唯一 ACTIONABLE：上下文误报

命中 `scripts/sonarqube-local-up.sh:87-88` 的 `admin:admin`。这是 SonarQube 首次启动时的厂商默认凭据，服务只绑定 `127.0.0.1`，脚本随后立即生成随机密码并更换默认密码。它不是仓库泄露的真实秘密。

判断：`FALSE_POSITIVE / ADVISORY`，不应作为 ACTIONABLE。正确优化是给这个精确 fingerprint 增加带到期时间和理由的治理记录，或给 Gitleaks 添加“精确路径 + 精确固定串”例外；不能全局关闭 basic-auth 规则。

#### 33 条 SpotBugs 空指针

已有项目治理证据把其中 25 条判为 FALSE_POSITIVE，原因是绝对路径、受控工具路径和短路条件形成了 SpotBugs 无法跨边界推断的不变量；8 条通过 JDK 17 极端 Path 输入复现为真实缺陷，但当前 Web 入口不会提供该极端值。

判断：25 条可继续隐藏在默认问题列表之外；8 条保留为 CONDITIONAL，属于防御性加固，不应升级为当前生产事故。

#### 14 条依赖漏洞

版本匹配是真实的，但“版本受影响”不等于“当前项目可利用”：

- 7 条经过源码、配置和构建 JAR 证据判断为 NOT_AFFECTED，例如漏洞只存在于 Tomcat 示例应用，或所需 Jackson 注解组合不存在；
- 7 条需要 RewriteValve、EncryptInterceptor、DefaultServlet 安全约束等部署侧触发条件，仓库内未发现，保留为 CONDITIONAL / TRIGGER_NOT_FOUND。

判断：依赖结果不是误报，而是“版本事实 + 适用性尚未成立”。报告默认页应优先展示触发条件和升级版本建议，而不是只展示 CVE 数量。

#### 456 条规范与 25 条重复代码

它们大多真实违反了当前规则，但不是功能 Bug。比如行长 121 和缺少花括号是可验证的事实，风险是可读性和变更成本。

判断：保留为 ADVISORY；在领导汇报或默认首页中单独放入“代码规范债务”，不能与 P1 漏洞相加后说“发现 595 个 Bug”。

### 5.2 SonarQube 的 18 条 BUG

| 分组 | 数量 | Codex 判断 |
| --- | ---: | --- |
| `S5998` 正则栈/性能 | 1 | 有明确加固价值。处理不可信且可能很长的源码片段时，正则和整文件读取可形成服务可用性风险 |
| `S2445` 对 `runtime` 参数加锁 | 8 | 当前 `RuntimeScan` 是私有、稳定、未外泄的任务对象，没有证据表明已发生竞态；建议改成专用 `final lock` 提升可证明性 |
| `S3077` volatile 引用 | 6 | 本项目是不可变结果/异常/上下文引用的整体发布，volatile 足以提供所需可见性；大部分是规则无法理解使用约束 |
| `S5850` 正则 `^_+|_+$` | 1 | 运算符优先级与当前意图一致，属于可读性建议，不是功能 Bug |
| `S899` 忽略 `awaitNanos` 返回值 | 1 | 循环每次都用绝对 deadline 重新计算 remaining，故意忽略返回值是正确实现；双方工具曾对此共同告警，但共同告警仍可能是误报 |
| `S5783` 测试 lambda | 1 | 只影响测试断言定位精度，不是生产 Bug |

另外，Sonar 的 15 条 `S4165` 全部命中 Java record 紧凑构造器中的参数重新赋值。Java 会在构造器结束时把重新赋值后的参数写入 record 字段，这些赋值不是无效赋值。该规则在本项目语境中应标记为 FALSE_POSITIVE，或等待 SonarJava 版本修复。

## 6. Codex 独立发现、两份报告都没有直接给出的问题

### 6.1 发行介质缺少源码级追溯

旧介质只有 JAR SHA，没有 commit、dirty 状态和规则/query 哈希。实测旧介质与当前源码产生了 1,051 与 595 两个完全不同的结果。如果不先重建并固定来源，任何跨系统对比都可能比较错版本。

建议：发行清单必须增加 `sourceCommit`、`sourceArchiveSha256`、`worktreeDirty=false`、`applicationJarSha256`、每个规则文件 SHA、CodeQL suite/query pack SHA、漏洞库更新时间。

### 6.2 CodeQL 健康检查和执行约束口径不一致

首次用旧配置 `java-security-and-quality.qls` 启动当前 JAR时，健康接口仍把 CodeQL 和 DEEP 判为 AVAILABLE，真正执行才以 `CODEQL_QUERY_SUITE_UNAVAILABLE` 失败。当前实现规定的是 `java-code-scanning.qls`。

建议：健康检查必须复用适配器的完整 applicability 校验，包括 suite 文件名、pack 版本、CLI 版本、JDK/Maven；提交 DEEP 前再次校验，避免“健康可用、任务失败”。

### 6.3 不可信大文件可能耗尽服务 JVM

`AdapterSupport.snippet` 使用 `Files.readAllLines` 读取整个源文件，而默认单文件上限可达 1GB。多个适配器在主服务 JVM 内调用它；一个合法但巨大的 Java 文件可能在报告归一化阶段消耗大量堆内存。Sonar 的一条正则性能告警提示了相邻风险，但没有给出这条完整调用链。

建议：源码片段按字节和行流式读取，只保留目标前后最多 50 行；同时增加单行字节上限、单个 snippet 字节上限和回归测试。不要依赖 4GB JVM 堆来吸收 1GB 文件。

### 6.4 Sonar Quality Gate 当前没有实际门禁

Quality Gate 返回 `OK` 但 conditions 为空。建议至少设置：新代码不得出现 Blocker/Critical 可靠性和安全问题、新代码重复率上限、测试覆盖率目标；存量代码采用逐步收敛，不要一次性以 275 条存量问题阻断。

## 7. 建议的优化顺序

### 第一优先级：保证结果可信

1. 给发行介质补全源码、规则、查询集、工具和漏洞库追溯信息。
2. 修复 CodeQL 健康检查与执行检查不一致。
3. 修复片段提取整文件读取和超长单行风险。
4. 把 Gitleaks `admin:admin` 精确命中治理为到期可复核的 FALSE_POSITIVE。

### 第二优先级：让默认报告真正可用

1. 首页默认只展示 ACTIONABLE 和 CONDITIONAL，本次人工校正后实际是 0 条 ACTIONABLE、15 条 CONDITIONAL。
2. CODE_STYLE、DUPLICATION、TEST_CODE 单独统计，不计入“Bug 数”。
3. 依赖漏洞必须同时显示版本命中、触发条件、适用性和修复版本。
4. 对同一源码点的多规则命中生成一个问题组，保留全部引擎证据。

### 第三优先级：吸收 Sonar 的增量能力

可以在 PMD/自定义规则中逐步补充：认知复杂度、危险正则、测试等待、嵌套三元表达式；重复字面量只作为低优先级维护性建议。不要照搬 Sonar 全部规则，也不要把 Sonar 的 BUG 类型原样映射为 P1/P2。

### 第四优先级：建立独立真值 Benchmark

本次是同源交叉验证，能发现冲突和互补，但不能给出严格准确率。下一步应在独立仓库维护：

- 每个漏洞/缺陷一个最小正例和对应负例；
- 真实开源 CVE 修复前后 commit；
- 人工双人复核的真实项目片段；
- 每条样本的 CWE、触发条件、期望文件/行、证据和来源；
- 规则版本升级后自动计算 TP、FP、FN、precision、recall。

## 8. 最终判断

当前自研平台已经具备“多引擎代码审计工具”的完整骨架，15 个引擎均能在同一 Web 任务中真实运行，供应链范围明显超过本次 SonarQube 社区版。它现在的主要问题不是扫描不到，而是：

- 规范类问题数量太大，容易淹没真正需要处理的事项；
- ACTIONABLE 的上下文治理还不够严格；
- 介质、健康检查和大文件边界需要进一步工程化；
- 还没有用独立真值集量化准确率。

SonarQube 很适合补充日常代码质量和趋势管理，但本次 18 个 BUG 标签中大部分不能直接证明存在生产缺陷。最合理的方案不是二选一，而是：自研平台负责广覆盖和统一报告，SonarQube作为代码质量对照源，Codex/人工负责高优先级适用性判断，最终由独立 Benchmark 衡量准确率。

## 9. 证据文件

本次可重复计算脚本：`scripts/compare-scanner-sonarqube.py`。

未提交 Git 的本机证据目录：

`dist/scanner-comparison/34ad1c686106d92ee5c9d979d1f6b294deb0bfbb/`

关键文件：

- `platform-current-report-v2.html/json/zip`：当前 JAR 的最终 15 引擎报告；
- `sonar-issues.json`、`sonar-measures.json`、`sonar-quality-gate.json`：Sonar API 全量导出；
- `normalized/comparison-summary.json`：归一化总览；
- `normalized/semantic-overlap.csv`：逐条交集；
- `comparison-input-manifest.json`：不可变输入清单。
