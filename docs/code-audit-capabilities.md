# Java 代码审计能力全景与组件说明

> 文档状态：方案基线（后续随扫描器接入持续更新）
>
> 适用场景：个人使用、Web 端部署、Java/Maven 项目、ZIP 上传或 SVN 地址
>
> 更新时间：2026-08-12

## 1. 十五秒结论

本平台不是重新实现一套静态分析算法，而是把成熟扫描器组织成一次可追踪的审计任务：用户提交 Java/Maven 源码，隔离 Runner 分别执行源码、字节码、依赖和供应链扫描，平台统一保存证据、去重、分级并生成一份可下载报告。

最终方案能够较全面地覆盖代码规范、潜在 Bug、空指针、并发、资源泄漏、Java Web 安全、污点路径、依赖漏洞、密钥泄漏、重复代码、依赖治理、SBOM、配置/IaC、构建产物和许可证风险。它能覆盖现有四个 Skill 的主要检查范围，但不能承诺与 IntelliJ IDEA Inspect Code 或 Qodana 的规则和结果逐条一致，也不能替代业务逻辑审计、动态渗透测试和人工安全评审。

第一阶段不需要 AI。扫描器确定性地产生报告，用户直接下载即可；AI 只作为后续可选的解释、误报复核、风险归并和修复建议能力。

## 2. 全景图：一次审计由六个环节组成

```text
源码输入
  ↓
项目识别与扫描计划
  ↓
隔离构建与多引擎扫描
  ↓
原始证据与覆盖度记录
  ↓
Finding 归一化、去重和策略分级
  ↓
统一报告与原始附件下载
```

六个环节分别解决不同问题：

1. **源码输入**：接收 ZIP 或 SVN 地址，安全解压或检出到一次性工作区。
2. **项目识别**：识别 Maven 根、子模块、源码目录、JDK 版本、Spring 技术栈和可执行扫描器。
3. **多引擎扫描**：无构建扫描和需要编译的扫描在隔离 Runner 中按依赖关系执行。
4. **证据记录**：保留扫描器原始 JSON、XML、SARIF、日志、SBOM 和覆盖元数据。
5. **结果归一化**：把不同规则、严重性、位置、CWE 和数据流转换为统一 Finding，同时保留原始来源。
6. **报告交付**：输出一份总报告，并明确哪些引擎成功、失败、超时、跳过或只完成了部分模块。

## 3. 一个具体例子

假设用户上传一个包含 8 个 Maven 模块的 Spring 项目，其中存在以下问题：

- Controller 参数未经校验进入 DAO 拼接 SQL；
- 一个 Service 在某条分支上可能解引用 `null`；
- `pom.xml` 引用了带高危 CVE 的旧版本依赖；
- 配置文件误提交了云服务密钥；
- 两个模块复制了大段相同校验代码；
- Maven 依赖树存在版本不收敛。

标准/深度扫描的证据链会是：

| 问题 | 主要发现引擎 | 报告中应出现的证据 |
| --- | --- | --- |
| SQL 注入 | CodeQL、FindSecBugs，Semgrep CE 作补充 | Source、Sink、路径或调用位置、规则 ID、CWE |
| 潜在空指针 | SpotBugs、Error Prone，可选 NullAway | 字节码路径或编译期诊断、类/方法/源码行 |
| 依赖 CVE | Dependency-Check、OSV-Scanner、Trivy | 组件坐标、版本、CVE/GHSA、CVSS、修复版本 |
| 密钥泄漏 | Gitleaks，Trivy Secrets 作补充 | 文件位置、规则、脱敏后的命中证据 |
| 重复代码 | PMD CPD | 两个代码块的位置、重复 token/行数 |
| 版本不收敛 | Maven Enforcer | 冲突依赖路径和收敛失败原因 |

如果 SpotBugs 只扫描到 6 个模块，报告不能简单写“SpotBugs 发现 0 个问题”，而要写成“成功 6/8 模块，覆盖不完整”。这是平台比简单拼接多个扫描器输出更重要的价值之一。

## 4. 目标、非目标与能力等级

### 4.1 本期目标

- 用户通过一个 Web 页面完成上传、启动、查看进度和下载报告。
- 支持 Java/Maven 单模块与多模块工程。
- 不依赖 IDEA，本地或服务端命令行扫描器即可完成全流程。
- 保留原始证据，任何统一结论都可以追溯到具体引擎。
- 同一任务可选择快速、标准或深度档位。
- 没有 AI、没有外部大模型时，扫描和报告仍完整可用。

### 4.2 不承诺的事情

- 不承诺发现所有漏洞，也不把“0 个 Finding”解释为“代码安全”。
- 不承诺与 IDEA Inspect Code、Qodana 或商业 SAST 逐条同结果。
- 不自动理解金额、权限、租户、库存、审批等业务规则。
- 不在第一期主动运行 Web 应用进行攻击验证。
- 不把 SBOM、许可证清单或依赖清单本身当作漏洞结论。

### 4.3 本文中的覆盖等级

| 等级 | 含义 |
| --- | --- |
| 强 | 有成熟专用引擎，同输入和配置下结果可重复，证据清楚 |
| 较强 | 多个引擎互补，能覆盖常见类别，但仍受框架建模或规则质量影响 |
| 基础 | 能发现明显模式或资产，但存在显著漏报、误报或分析深度限制 |
| 未覆盖 | 当前方案不应对此作安全承诺 |

这些等级是工程判断，不是经过统一基准测出的召回率百分比。

## 5. 审计维度总表

| 审计维度 | 主要组件 | 能检查什么 | 预计程度 | 主要边界 |
| --- | --- | --- | --- | --- |
| Java 潜在 Bug | SpotBugs、PMD、Error Prone | 空指针、错误 API、无效分支、资源误用、异常处理等 | 强 | 需要正确构建/类路径；反射和运行时行为会漏报 |
| 并发正确性 | SpotBugs、PMD、Error Prone | 锁、共享状态、错误同步、并发 API 误用 | 较强 | 无法证明完整线程安全性 |
| Null 安全 | SpotBugs、Error Prone、NullAway | 潜在解引用、空值契约违反 | 较强 | NullAway 需要注解边界和项目配置 |
| 代码规范 | Checkstyle、PMD | 命名、导入、格式、复杂度、设计和团队规范 | 强 | 与 IDEA 规则集合不一一对应 |
| Java Web SAST | FindSecBugs、Semgrep CE、CodeQL | SQL/命令/路径/XPath 注入、XSS、SSRF、反序列化、弱加密等 | 较强 | 框架封装、自定义 sanitizer、反射影响精度 |
| 污点分析 | CodeQL、FindSecBugs、Semgrep CE | 不可信输入从 Source 到危险 Sink 的传播 | 较强 | Semgrep CE 仅单文件；复杂业务数据流仍可能漏报 |
| 依赖漏洞 | Dependency-Check、OSV-Scanner、Trivy | Maven 直接/传递依赖关联 CVE/GHSA/OSV | 强 | 版本识别错误、数据库时效、漏洞可达性不足 |
| 密钥泄漏 | Gitleaks、Trivy | Token、密码、私钥、云凭据等 | 强（当前快照） | SVN 历史需另做历史抓取；密钥有效性通常不验证 |
| 重复与可维护性 | PMD CPD、PMD | 重复代码、复杂度、设计异味、可维护性规则 | 较强 | 不能替代架构和领域设计评审 |
| Maven 依赖健康 | Dependency Plugin、Enforcer | 未声明/未使用依赖、依赖收敛、禁用依赖、版本约束 | 强 | Spring、SPI、反射可能造成“未使用”误报 |
| SBOM/资产清单 | CycloneDX Maven Plugin | 直接与传递组件、坐标、版本和关系 | 强 | SBOM 是资产事实，不代表漏洞是否可利用 |
| 配置/IaC/镜像 | Trivy | 配置错误、IaC、容器镜像、JAR/WAR/EAR 风险 | 较强 | 只扫描仓库时无法代表生产环境真实配置 |
| 许可证风险 | Trivy、SBOM | 依赖许可证识别和策略命中 | 基础到较强 | 不是法律意见，模糊或多许可证需要人工确认 |
| 业务逻辑安全 | 人工评审，未来可选 AI 辅助 | 越权、IDOR、租户隔离、金额和流程绕过 | 未覆盖 | 需要业务语义、威胁模型和动态验证 |
| 运行时 Web 安全 | 未来 ZAP/人工渗透 | Header、Cookie、CORS、认证会话、真实端点行为 | 未覆盖 | 当前是源码/构建产物静态审计，不启动目标应用 |

## 6. 组件清单：它们最终以什么形式使用

这些组件不是都以“部署一个长期服务”的形式提供。平台内部更适合把它们当作独立 CLI、Maven 插件或容器镜像：Orchestrator 下发一次任务，Runner 启动工具，工具写出报告后退出。

| 组件 | 交付形态 | 是否通常需要编译 | 主要输入 | 建议保留的输出 |
| --- | --- | --- | --- | --- |
| SpotBugs | CLI / Maven 插件 | 是 | class、依赖类路径 | XML、SARIF、日志 |
| FindSecBugs | SpotBugs 插件 | 是 | class、依赖类路径 | 随 SpotBugs 输出 |
| Semgrep CE | CLI / 容器 | 否 | 源码与 YAML 规则 | JSON、SARIF、日志 |
| CodeQL CLI | 独立 CLI 工具链 | Java 通常需要构建提取 | 源码、构建过程、查询包 | SARIF、数据库元数据、日志 |
| PMD | CLI / Maven 插件 | 否 | Java 源码、ruleset | XML、SARIF/文本、日志 |
| PMD CPD | CLI / Maven 插件 | 否 | 源码 | XML、重复片段信息 |
| Checkstyle | CLI / Maven 插件 | 否 | 源码、配置 | XML、日志 |
| Error Prone | javac 编译插件 | 是 | Java 编译过程 | 编译诊断、结构化转换结果 |
| NullAway | Error Prone 插件 | 是 | 源码、类型信息、空值注解 | 编译诊断 |
| Dependency-Check | CLI / Maven 插件 | 解析依赖即可 | POM、依赖、制品 | JSON、SARIF、HTML、日志 |
| OSV-Scanner | CLI / 容器 | 否或仅需依赖清单 | POM、锁文件、SBOM | JSON、SARIF |
| Gitleaks | CLI / 容器 | 否 | 当前目录或 Git 仓库 | JSON、SARIF、脱敏日志 |
| Maven Dependency Plugin | Maven 插件 | 需要 Maven 解析 | Reactor、依赖树 | 结构化转换结果、日志 |
| Maven Enforcer | Maven 插件 | 需要 Maven 解析 | Reactor、规则配置 | 构建诊断、依赖路径 |
| CycloneDX Maven Plugin | Maven 插件 | 需要 Maven 解析 | Maven Reactor | CycloneDX JSON/XML |
| Trivy | CLI / 容器 | 仓库扫描否，产物扫描需要产物 | 仓库、POM、JAR/WAR、镜像、SBOM | JSON、SARIF、SBOM |

Web 平台自身只长期运行 API、任务编排、存储和报告服务；扫描器在隔离执行环境中按任务启动，不要求用户安装 IDEA，也不要求为每个扫描器维护一个常驻 Web 服务。

## 7. 各组件能做什么、怎么接入、做到什么程度

### 7.1 SpotBugs：Java 字节码 Bug 检测主引擎

**做什么**

- 在编译后的 class 上检测潜在 Bug，而不是只做文本匹配。
- 常见类别包括空指针、错误相等比较、资源处理、异常误用、序列化、并发正确性和安全问题。
- 能直接覆盖现有 `smart-spotbugs-check-review` Skill 的底层扫描来源。

**怎么做**

1. Runner 使用项目要求的 JDK 执行 Maven 编译。
2. 为每个可构建模块收集 class 目录和依赖类路径。
3. 用固定版本、固定 include/exclude filter 执行 SpotBugs。
4. 保存 XML/SARIF，并将 `type`、`rank`、`category`、源码位置映射到统一 Finding。
5. 平台策略复现现有 Skill：只保留 `rank <= 9` 且 category 为 `CORRECTNESS`、`SECURITY`、`MT_CORRECTNESS` 的结果。

**程度与边界**

同一 SpotBugs 版本、相同 class、类路径和 filter 下，可以做到接近原 Skill 的同引擎覆盖。构建失败、生成代码缺失、依赖类路径不完整会直接降低覆盖，因此报告必须记录“发现模块/成功构建模块/实际扫描模块”。

### 7.2 FindSecBugs：Java Web 安全规则扩展

**做什么**

- 作为 SpotBugs 插件补充 Java/JVM 安全检测。
- 重点覆盖 SQL/HQL/命令/XPath 注入、路径处理、XSS、弱加密、Cookie/Servlet API 误用等常见 Web 安全模式。

**怎么做**

- 与 SpotBugs 在同一字节码扫描阶段运行，加载固定版本插件。
- 规则结果仍使用 SpotBugs 报告结构，平台通过 detector/rule namespace 区分来源。
- 对注入类 Finding 尽量保留调用位置、污点角色、CWE 和上下文代码。

**程度与边界**

对典型 Java Web API 的覆盖较强，但对项目自定义框架、封装后的 Source/Sink 和复杂跨层传播有限，不能单独等价于 Qodana 的完整污点分析。

### 7.3 Semgrep CE：快速源码规则和安全模式扫描

**做什么**

- 不要求 Maven 构建成功，可快速检测 Java/Spring 安全模式、内部禁用 API、代码规范和项目自定义规则。
- YAML 规则易于维护，适合把团队经验转为确定性检查。

**怎么做**

- 在快速扫描阶段直接扫描安全解压后的源码。
- 规则必须固定版本并记录来源与许可证；平台自有规则放在 `config/rules/`。
- 输出 JSON/SARIF，保留 metavariable、fix、rule metadata 和源码位置。

**程度与边界**

Semgrep CE 的核心限制是**单文件分析**。它适合快速发现明确模式和单文件污点路径，不应被描述成完整跨文件污点引擎。复杂的 Controller → Service → DAO 跨文件传播应主要依靠 CodeQL 或其他深度引擎。

### 7.4 CodeQL：深度跨过程/跨文件安全分析

**做什么**

- 为 Java 代码建立可查询数据库，运行官方或自定义查询包。
- 适合发现跨方法、跨文件的数据流漏洞，并输出 SARIF 和路径证据。
- 是替代 Qodana 污点能力时最重要的深度引擎，但不是逐规则兼容层。

**怎么做**

1. 先执行 CodeQL 使用资格策略，不满足条件时标记 `SKIPPED_POLICY`。
2. 在专用 Runner 中创建 Java 数据库；优先使用受控的手工 Maven 构建，记录被提取的源码范围。
3. 固定 CLI、query pack 和 query suite 版本。
4. 执行安全扩展查询，保存 SARIF、查询包锁定信息、数据库统计和日志。
5. 将 SARIF codeFlow 映射为统一 Finding 的 Source → Step → Sink 路径。

**许可边界非常重要**

CodeQL CLI 不是“因为个人使用或不商用就可以任意扫描”。其当前条款允许分析采用 OSI 认可许可证发布的开源代码，并对自动分析、CI/CD、数据库生成和向他人提供托管方案设置了额外限制。尤其是从 SVN 上传的项目，不能仅凭“代码公开”就自动判定可用。平台应默认关闭 CodeQL，只有在代码许可证、托管位置和使用方式都通过策略检查，或用户具有相应商业许可时才启用。这里是工程合规提醒，不是法律意见。

### 7.5 PMD：Java 源码质量与易错模式

**做什么**

- 覆盖 Best Practices、Code Style、Design、Documentation、Error Prone、Multithreading、Performance、Security 等规则类别。
- 补充 IDEA Inspect Code 类别中的常见规范、潜在错误、复杂度和设计问题。

**怎么做**

- 快速档位直接扫描源码，使用平台固定 ruleset。
- 按项目逐步启用规则，不建议第一天打开全部规则。
- 输出规则 ID、优先级、位置和描述；规范类 Finding 与 Bug/安全类 Finding 分域显示。

**程度与边界**

对源码质量覆盖广，但规则数量越多不等于质量越高。必须通过基线、抑制和项目规则版本控制降低噪音。它与 IDEA 的实现和规则语义不同，只能做类别级替代。

### 7.6 Checkstyle：可执行的团队代码规范

**做什么**

- 检查命名、导入、空白、Javadoc、代码布局、部分规模和结构约束。
- 最适合做明确、稳定、可在团队内达成一致的规范门禁。

**怎么做**

- 在快速档位运行固定配置。
- 报告中单独展示规范结果，避免大量格式问题淹没真实 Bug 和漏洞。
- 规范版本、例外和抑制文件必须跟扫描记录一起保存。

**程度与边界**

格式与结构规则覆盖强，但它不是 Bug 引擎，也不做污点分析。不能用 Checkstyle Finding 数量衡量安全性。

### 7.7 Error Prone 与 NullAway：编译期 Bug 和 Null 契约

**做什么**

- Error Prone 接管或扩展 javac 编译诊断，发现错误 API 使用、无效代码、异常误用和多类高置信 Bug。
- NullAway 在项目采用明确空值注解和包边界时进行更严格的 Null 安全检查。

**怎么做**

- 放在深度扫描档位，不直接修改用户 POM，优先通过受控 Maven profile、编译参数或临时构建描述接入。
- 最新 Error Prone 自身要求 JDK 21+，因此用专用 JDK 21+ Runner 启动；仍可通过 `--release` 编译较旧 Java 源码。
- NullAway 默认可选，只有识别出可用注解体系和包边界后才运行。

**程度与边界**

Error Prone 会改变编译链路，注解处理器、老旧 Maven 插件和定制编译器可能不兼容。NullAway 若没有清晰的 annotated/unannotated 边界会产生大量噪音，所以不能对所有上传项目强制启用。

### 7.8 Dependency-Check：OWASP 依赖漏洞主引擎

**做什么**

- 对 Maven 直接和传递依赖做软件成分识别，关联公开漏洞数据。
- 直接覆盖现有 `smart-owasp-check-review` Skill 的底层扫描来源。

**怎么做**

- 使用固定插件/CLI 版本、漏洞数据库快照、analyzer 配置和 suppression 文件。
- 输出至少保存 JSON 和 SARIF；HTML 可作为原始附件。
- 平台策略复现现有 Skill：CVSS `>= 9.0` 映射 P0，`>= 7.0` 映射 P1；低于阈值的数据仍可在完整原始报告中查询。

**程度与边界**

同版本、同数据库、同依赖解析和 suppression 下，可以做到接近原 Skill 的同引擎覆盖。误识别组件、数据库更新差异、被抑制规则和 Maven 解析失败都会造成结果差异。CVSS 高不代表漏洞在当前代码中一定可达。

### 7.9 OSV-Scanner：依赖漏洞的第二数据视角

**做什么**

- 使用 OSV 生态数据扫描清单、锁文件或 SBOM，补充 Dependency-Check 的识别和数据源差异。
- 适合交叉验证漏洞身份与受影响版本范围。

**怎么做**

- 标准档位从 POM/依赖清单或 CycloneDX SBOM 输入。
- 结果与 Dependency-Check 以漏洞 ID、PURL、组件和版本归并，但保留双方证据。

**程度与边界**

第二个引擎可以减少单一数据源盲区，但不能把两个引擎的重复命中计为两个漏洞，也不能自动证明漏洞可利用。

### 7.10 Gitleaks：密钥和凭据泄漏

**做什么**

- 检测 API Token、私钥、密码、云凭据和高熵秘密等。
- 支持规则、基线、脱敏和结构化输出。

**怎么做**

- ZIP 和 SVN 当前检出目录执行 `dir` 类扫描。
- 报告和日志必须默认脱敏，原始代码访问也应受权限控制。
- 对 Git 仓库可扫描历史；SVN 历史若要覆盖，需要另外设计 revision 拉取与历史遍历，不能把当前 checkout 当成完整历史。

**程度与边界**

对当前源码快照的常见秘密覆盖强，但规则命中不代表凭据仍有效。平台不应默认联网验证密钥，因为这会带来审计授权和外部副作用问题。

### 7.11 PMD CPD：重复代码

**做什么**

- 基于 token 检测复制粘贴代码，定位重复块及其文件位置。
- 为维护成本、缺陷同步扩散和重构候选提供证据。

**怎么做**

- 快速档位扫描 Java 源码，按项目规模配置最小 token 阈值。
- 相同重复组生成一个“重复组”Finding，而不是为每个片段重复计数。

**程度与边界**

它只能证明代码相似，不能证明一定应该抽象。测试夹具、生成代码和协议模型常需要排除。

### 7.12 Maven Dependency Plugin 与 Enforcer：依赖健康治理

**做什么**

- Dependency Plugin 检查已使用但未声明、已声明但未使用、重复声明和依赖分析。
- Enforcer 检查依赖收敛、禁用组件、版本上界、Maven/JDK 要求和组织策略。

**怎么做**

- 在隔离 Maven Runner 中执行，保存完整依赖路径和模块范围。
- “未使用依赖”默认只提示，不直接阻断，因为 Spring、SPI、反射和注解处理器可能在字节码引用之外使用组件。
- 依赖收敛和明确禁用组件可以配置为高优先级门禁。

**程度与边界**

它们检查的是依赖工程健康，不是 CVE 扫描。与 Dependency-Check/OSV 组合后，才能同时回答“依赖是否健康”和“依赖是否已知有漏洞”。

### 7.13 CycloneDX Maven Plugin：SBOM 资产底账

**做什么**

- 生成 Maven 直接/传递依赖及关系的 CycloneDX SBOM。
- 为漏洞扫描、许可证治理、版本追踪和报告存档提供稳定资产输入。

**怎么做**

- 多模块项目优先生成 aggregate SBOM，同时记录未纳入聚合的模块。
- 保存 CycloneDX JSON；必要时同时保存 XML。
- SBOM 与扫描任务、源码 revision、Maven profile、时间和工具版本绑定。

**程度与边界**

SBOM 是“这里有什么”，不是“这里一定有漏洞”或“这个漏洞可达”。动态下载、运行时挂载和未参与 Maven Reactor 的组件可能不在清单内。

### 7.14 Trivy：仓库、依赖、配置、产物和许可证补充扫描

**做什么**

- Repository 模式检查仓库中的依赖、秘密和配置/IaC。
- Artifact/Image 模式检查 JAR、WAR、EAR、容器镜像和其中的软件包。
- 可输出漏洞、错误配置、秘密、许可证和 SBOM 数据。

**怎么做**

- 快速档位运行 repository 扫描，标准档位在构建成功后运行 artifact 扫描。
- 与 Gitleaks、Dependency-Check、OSV 的重复结果做归并，但保留 Trivy 作为独立证据来源。
- 扫描数据库版本和更新时间必须进入 manifest。

**程度与边界**

Trivy 覆盖面很广，适合作为供应链与配置的兜底引擎，但不应替代 Java 语义 Bug 分析或 CodeQL 深度污点分析。

## 8. 对现有四个 Skill 的覆盖关系

四个 Skill 本质上分成两层：底层扫描器生成报告，Skill 再解析报告、筛选优先级、读取上下文并生成复核清单。新平台会把第一层自动化，并把第二层的确定性部分放进 Finding Normalizer 和 Policy；后续如果需要，仍可在统一报告上运行 AI Reviewer。

| 现有 Skill | 原始来源与筛选 | 新平台覆盖方式 | 结论 |
| --- | --- | --- | --- |
| `smart-inspect-code-review` | IDEA XML；`severity=ERROR` 或 problem class 含 `probable bug` | SpotBugs + Error Prone + PMD + Checkstyle + 可选 NullAway | 类别覆盖较高；无法保证 IDEA 规则 ID 和结果逐条一致 |
| `smart-qodana-security-review` | Qodana XML；Critical/High/Warning；利用 `taint_flow` | CodeQL + FindSecBugs + Semgrep CE | 常见 Java Web 漏洞和污点类别覆盖较强；无法保证 Qodana 引擎、框架模型和路径完全一致 |
| `smart-spotbugs-check-review` | SpotBugs XML；`rank<=9` 且三个重点 category | 同一 SpotBugs 引擎 + 相同过滤策略 | 在版本、class、类路径和 filter 一致时可接近同等结果 |
| `smart-owasp-check-review` | Dependency-Check JSON；CVSS `>=7` | 同一 Dependency-Check 引擎 + 相同阈值，OSV/Trivy 补充 | 在版本、数据库、依赖识别和 suppression 一致时可接近同等结果 |

### 8.1 “覆盖”不等于“克隆”

- SpotBugs 和 Dependency-Check 使用相同底层引擎，属于**同引擎复现**。
- IDEA Inspect Code 和 Qodana 被其他引擎组合替代，属于**能力类别覆盖**。
- 新平台可以保留四个 Skill 的 P0/P1/P2 筛选逻辑，但不会伪造 IDEA/Qodana 的规则 ID。
- 原 Skill 里的“读取完整方法、理解上下文、给修复建议”带有人类或 AI 复核性质，不属于扫描器本身的确定性检测能力。

## 9. 第一批五项增量能力

在四个 Skill 关注范围之外，第一批增加以下五类能力：

1. **Gitleaks：秘密泄漏**

   解决代码中误提交 Token、私钥和密码的问题，四个原 Skill 没有系统覆盖这一层。

2. **PMD CPD：重复代码**

   找到复制粘贴和同步维护风险，为重构提供可定位证据。

3. **Maven Dependency Plugin + Enforcer：依赖健康**

   检查依赖声明、版本收敛和组织策略；这与 CVE 扫描互补。

4. **CycloneDX：SBOM**

   形成每次审计的组件资产底账，为漏洞、许可证和版本变化提供统一输入。

5. **Trivy：配置、IaC、构建产物和许可证**

   把审计从 Java 源码扩展到仓库配置、制品和供应链层面。

这五项加入后，平台已经覆盖大多数“个人对 Java/Maven Web 项目做一次综合静态审计”的常见场景。剩余的主要缺口不是再叠加一个相似 SAST，而是业务逻辑、运行时 Web 行为、架构约束和测试有效性。

## 10. 扫描档位与执行计划

### 10.1 Quick：快速扫描

目标是即使 Maven 构建失败，也尽量给出早期结果。

| 引擎 | 主要输出 |
| --- | --- |
| Gitleaks | 密钥泄漏 |
| Semgrep CE | Java/Spring 安全模式和自定义规则 |
| PMD | 质量、设计、易错模式 |
| PMD CPD | 重复代码 |
| Checkstyle | 代码规范 |
| Trivy Repository | 仓库依赖、配置、秘密和许可证补充 |

### 10.2 Standard：标准扫描

在 Quick 基础上执行隔离 Maven 解析和构建：

| 引擎 | 主要输出 |
| --- | --- |
| SpotBugs + FindSecBugs | Bug、空指针、并发和 Java Web 安全 |
| Dependency-Check + OSV-Scanner | 依赖漏洞交叉识别 |
| Maven Dependency Plugin + Enforcer | 依赖声明与治理 |
| CycloneDX | 聚合 SBOM |
| Trivy Artifact | JAR/WAR/EAR 等构建产物风险 |

Standard 应是默认档位，因为它在覆盖度、耗时和接入复杂度之间最平衡。

### 10.3 Deep：深度扫描

在 Standard 基础上增加：

- CodeQL：通过许可和使用资格策略后运行；
- Error Prone：项目构建兼容时运行；
- NullAway：项目已有或可安全建立 Null 注解边界时运行。

Deep 不是“Standard 一定能运行的超集”。某个深度引擎不适用时，应明确显示 `SKIPPED` 原因，而不是让整个扫描任务无结果。

## 11. JDK 17 与扫描 Runner 的关系

平台的 API、Orchestrator、Finding Core 和报告服务统一以 JDK 17 编译运行。Spring Boot 4.1.0 的官方最低要求就是 Java 17，因此当前技术栈可以使用 JDK 17。

但是平台 JDK、被扫描项目 JDK、扫描器 JDK 是三个概念：

| JDK 角色 | 示例 | 选择规则 |
| --- | --- | --- |
| 平台 JDK | API、编排、报告服务 | 固定 JDK 17 |
| 项目构建 JDK | 用户上传的 Maven 项目 | 由 POM、toolchains、字节码和预检识别，支持 JDK 8/11/17/21 等 |
| 扫描器运行 JDK | 最新 Error Prone、SpotBugs Runner 等 | 按扫描器官方要求选择，可与项目 target release 不同 |

因此“平台改为 JDK 17”不会把所有被扫描项目强制降级到 Java 17。每个 Runner 镜像应在 manifest 中记录镜像 digest、Java runtime、Maven 版本和工具版本。

## 12. 统一 Finding 与报告应该包含什么

### 12.1 Finding 最小字段

```json
{
  "fingerprint": "stable-hash",
  "engine": "spotbugs",
  "engineVersion": "pinned-version",
  "ruleId": "NP_NULL_ON_SOME_PATH",
  "domain": "CORRECTNESS",
  "severity": "HIGH",
  "confidence": "HIGH",
  "title": "Possible null pointer dereference",
  "file": "module/src/main/java/example/Service.java",
  "startLine": 45,
  "cwe": ["CWE-476"],
  "dataFlow": [],
  "rawArtifact": "raw/spotbugs/report.xml"
}
```

还应支持组件坐标、CVE/CVSS、PURL、修复版本、重复组、许可证、模块、Source/Sink、抑制状态、基线状态和多引擎来源。

### 12.2 引擎执行状态

每个引擎至少记录：

- 状态：`SUCCEEDED`、`PARTIAL`、`FAILED`、`TIMED_OUT`、`SKIPPED`、`CANCELLED`；
- 开始/结束时间和耗时；
- 发现模块、适用模块、实际扫描模块；
- 输入 revision、构建 profile、JDK、Maven、工具和规则版本；
- Finding 数量、原始报告和日志位置；
- 失败或跳过原因。

“成功且 0 个问题”必须与“没有运行”“运行失败”“只扫了一部分”在数据模型和界面上完全不同。

### 12.3 去重原则

- 用规则族、CWE、文件、位置、Sink、组件 PURL/CVE 等生成稳定指纹。
- 同一 SQL 注入被 CodeQL、FindSecBugs 和 Semgrep 同时发现时，合并为一个展示组，但保留三个证据来源。
- 不同数据流到同一 Sink 是否合并，由 Source 和路径差异决定。
- 原始报告永不因去重而删除。

### 12.4 下载包建议结构

```text
scan-report.zip
├── report.html
├── report.json
├── report.sarif
├── manifest.json
├── coverage.json
├── sbom/
│   └── bom.cdx.json
├── raw/
│   ├── spotbugs/
│   ├── semgrep/
│   ├── dependency-check/
│   └── ...
└── logs/
    ├── build.log
    └── engines/
```

HTML 用于阅读，JSON 用于平台二次处理，SARIF 用于接入其他代码安全系统，raw 用于审计追溯，manifest/coverage 用于回答“这次究竟扫了什么”。PDF 可后续加入，但不应成为唯一交付格式。

## 13. Web 扫描的安全边界

上传的 Maven 项目是不可信代码。仅仅把 `mvn package` 放进普通 Docker 容器并不够，因为 Maven 插件和测试都可能执行任意代码。

Runner 至少要做到：

- 每个任务独立的一次性用户、工作区和容器/微虚拟机；
- 不挂载宿主 Docker Socket，不暴露宿主凭据、SSH key、云凭据或 GitHub Token；
- CPU、内存、进程数、磁盘、文件数、上传大小和总时长限制；
- ZIP Slip、符号链接逃逸、压缩炸弹和异常文件名防护；
- SVN 凭据只在取源码阶段短期使用，扫描器不可读取；
- Maven 仓库缓存受控，不能让任务修改全局缓存或扫描器配置；
- 默认限制网络出口，确需下载依赖时只开放受控代理/仓库；
- 扫描规则和扫描器镜像只读，并使用 digest 固定；
- 构建、扫描和报告服务之间使用最小权限的制品协议；
- 任务结束后销毁工作区，并按策略清理源码和日志。

如果为了安全跳过测试、禁用插件或限制网络，报告必须说明这对生成代码和覆盖度的影响。

## 14. AI 是否介入、如何介入

### 14.1 V1：不需要 AI

V1 的完整流程是：

```text
上传/检出 → 确定性扫描器 → 统一规则处理 → 报告下载
```

扫描器负责“发现证据”，Normalizer 负责“转换和去重”，Policy 负责“固定阈值和门禁”。这三层都应该可重复、可测试、可离线运行。

### 14.2 后续可选 AI Reviewer

AI 可以在扫描完成后做：

- 结合完整方法或调用链解释 Finding；
- 将多个引擎的重复证据归并为面向开发者的描述；
- 根据上下文判断疑似误报并给出理由，但不能静默删除原始 Finding；
- 生成修复建议、补丁草案和验证步骤；
- 按业务上下文重新排序风险；
- 把报告转换为管理摘要或复核清单。

AI 不应负责：

- 代替扫描器宣称代码已被完整扫描；
- 无证据地产生漏洞结论；
- 修改原始报告或覆盖度数据；
- 未经确认直接修复高风险业务逻辑；
- 把“模型认为是误报”当成确定性抑制规则。

最佳边界是：扫描结果是事实层，AI 输出是建议层，两者在报告和数据模型中分开存储。

## 15. 仍然存在的缺口与后续增量

### 15.1 优先级较高的下一批

| 能力 | 候选组件 | 解决的问题 |
| --- | --- | --- |
| 运行时 Web 扫描 | OWASP ZAP | Header、Cookie、CORS、认证会话和真实端点行为 |
| 架构规则 | ArchUnit | Controller/Service/Repository 依赖边界、包和分层约束 |
| 测试有效性 | JaCoCo、PIT | 覆盖率和测试是否真正能杀死缺陷 |
| 更深 Java 程序分析 | Tai-e | 自定义指针、调用图、数据流研究型分析 |

这些能力应该在核心流水线稳定后接入。否则会在尚未解决构建覆盖、Finding 归一化和隔离执行之前，过早增加运行复杂度。

### 15.2 长期仍需人工的部分

- 登录、授权、越权、租户隔离和数据权限；
- 金额、库存、状态机、审批流和幂等业务逻辑；
- 威胁建模、攻击面判断和跨系统信任边界；
- 漏洞是否在生产配置中真正可利用；
- 许可证冲突的法律判断；
- 高风险修复是否改变业务语义。

## 16. 验收标准

只有“能启动几个命令”还不能算平台完成。首个可用版本至少应通过以下验收：

1. ZIP 和 SVN 两种输入都能创建可追踪任务。
2. Quick 在 Maven 构建失败时仍能产出源码扫描报告。
3. Standard 能识别 Maven 多模块，并记录构建/扫描覆盖率。
4. 四个现有 Skill 的筛选阈值可以在统一 Policy 中复现。
5. 至少准备一组 Java/Spring 样例，包含 SQL 注入、空指针、依赖 CVE、秘密、重复代码和依赖不收敛。
6. 对样例记录每个引擎的 TP、FP、FN 和无法适用原因。
7. 同输入、同工具/规则/数据库版本重复运行，结果和指纹保持稳定。
8. 任一引擎失败时，总任务可以 `PARTIAL` 完成并下载其他结果。
9. 报告同时包含统一 Finding、覆盖信息、原始报告、日志和 SBOM。
10. Runner 无宿主凭据、Docker Socket 和跨任务工作区访问能力。

## 17. 关键取舍

| 选择 | 收益 | 成本/风险 | 何时考虑替代方案 |
| --- | --- | --- | --- |
| 多引擎编排而非单一大平台 | 开源可控、覆盖互补、可逐步替换 | 归一化、去重、版本维护复杂 | 团队不愿维护平台且可接受商业产品成本时 |
| Standard 作为默认档位 | 覆盖主要审计域，耗时可控 | 依赖 Maven 构建成功 | 只需提交前快速反馈时用 Quick |
| CodeQL 放入有条件的 Deep | 深度数据流能力强 | 资源重、构建复杂、许可边界严格 | 不满足使用条件时禁用，或采用合法授权的替代引擎 |
| V1 不引入 AI | 结果可重复、部署简单、成本低 | 人工复核体验较基础 | 扫描与报告稳定后再加入 Reviewer |
| 平台固定 JDK 17、Runner 多 JDK | 平台维护简单，同时兼容不同项目 | 需要维护镜像矩阵 | 目标项目全部统一 JDK 后可收敛镜像 |

## 18. 官方资料

- [Spring Boot 4.1 System Requirements](https://docs.spring.io/spring-boot/system-requirements.html)
- [SpotBugs Maven Plugin](https://spotbugs.readthedocs.io/en/stable/maven.html)
- [SpotBugs Running and Output](https://spotbugs.readthedocs.io/en/stable/running.html)
- [Find Security Bugs](https://find-sec-bugs.github.io/)
- [Semgrep CE Glossary and Analysis Boundaries](https://semgrep.dev/docs/writing-rules/glossary)
- [CodeQL CLI](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli)
- [GitHub CodeQL Terms and Conditions](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md)
- [PMD Java Rules](https://pmd.github.io/pmd/pmd_rules_java.html)
- [PMD Copy/Paste Detector](https://pmd.github.io/pmd/pmd_userdocs_cpd.html)
- [Maven Checkstyle Plugin](https://maven.apache.org/plugins/maven-checkstyle-plugin/)
- [Error Prone Installation](https://errorprone.info/docs/installation)
- [NullAway: How NullAway Works](https://github.com/uber/NullAway/wiki/How-NullAway-Works)
- [OWASP Dependency-Check Maven Configuration](https://jeremylong.github.io/DependencyCheck/dependency-check-maven/configuration.html)
- [OSV-Scanner Documentation](https://google.github.io/osv-scanner/)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Maven Dependency Plugin](https://maven.apache.org/components/plugins/maven-dependency-plugin/index.html)
- [Maven Enforcer: Dependency Convergence](https://maven.apache.org/enforcer/enforcer-rules/dependencyConvergence.html)
- [CycloneDX Maven Plugin](https://cyclonedx.github.io/cyclonedx-maven-plugin/)
- [Trivy Repository Scanning](https://trivy.dev/docs/latest/guide/target/repository/)
- [Trivy Java Coverage](https://trivy.dev/docs/latest/guide/coverage/language/java/)
- [ArchUnit User Guide](https://www.archunit.org/userguide/html/000_Index.html)
- [OWASP ZAP Docker](https://www.zaproxy.org/docs/docker/about/)
- [Tai-e Reference](https://tai-e.pascal-lab.net/docs/current/reference/en/index-single.html)

## 19. 最终判断

对当前“个人使用、Java/Maven、Web 上传 ZIP 或 SVN、生成报告下载”的目标，这套方案是合理且覆盖面较完整的。它既能承接四个现有 Skill 的核心检查，又通过五项第一批增量把审计扩展到秘密、重复、依赖治理、SBOM、配置和产物层。

最重要的工程工作不再是继续罗列扫描器，而是把以下三件事做好：

1. **隔离执行**：安全运行不可信 Maven 构建；
2. **覆盖度可见**：说清楚每个引擎实际扫到了什么；
3. **结果可追溯**：统一报告不丢失任何原始证据。

完成这三点后，再加入 CodeQL 深度档位、AI Reviewer、ZAP 和 ArchUnit，平台才会在不牺牲可信度的情况下持续增量。
