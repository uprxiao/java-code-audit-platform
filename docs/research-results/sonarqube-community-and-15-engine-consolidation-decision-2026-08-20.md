# SonarQube Community 与现有 15 引擎收敛决策及两种落地方案

日期：2026-08-20  
状态：讨论基线，尚未据此删除生产引擎  
适用范围：Java 17、Maven、ZIP/SVN 源码接入、SonarQube Community Build

# 第一部分：SonarQube 与 15 引擎的能力重合和收敛

## 1. 文档目的

本文第一部分回答四个问题：

1. SonarQube Community 与现有 15 个逻辑扫描引擎分别重合在哪里；
2. 哪些引擎可以考虑移除，哪些只能精简规则，哪些不能移除；
3. 外部扫描结果进入 SonarQube 后，哪些信息仍必须由统一审计报告保留；
4. 如果后续采用“SonarQube + 外部扫描器 + Excel 审计报告”，现有引擎应如何收敛。

本文只形成能力和产品决策，不在本次提交中修改扫描档位、适配器、规则或 API。

## 2. 先统一三个口径

### 2.1 “能够导入”不等于“SonarQube 自己能够检测”

SonarQube Community 可以导入 SpotBugs、FindSecBugs、PMD、Checkstyle 等报告，也可以导入 Generic External Issues 和 SARIF。导入后，问题能够出现在 SonarQube 项目中并参与 Quality Gate，但实际检测仍由外部工具完成。

因此，不能因为 SonarQube 页面能够展示 SpotBugs 问题，就认为 SpotBugs 已经可以删除。

### 2.2 “检查类别相同”不等于“检测实现相同”

例如 SonarJava 和 SpotBugs 都能报告空指针，但两者分析对象不同：

- SonarJava 主要使用源码语法树、类型和语义模型；
- SpotBugs 分析 Maven 构建后产生的 JVM 字节码；
- 同一问题被两者命中可以提高证据可信度；
- 只有一个工具命中也不必然表示误报或漏报，可能是分析层次不同。

### 2.3 SonarQube 的问题模型不能完整承载所有审计数据

有明确文件和行号的 Bug、规范和代码漏洞很适合进入 SonarQube。以下内容即使能够映射成摘要问题，也不能只保存在 SonarQube：

- PURL、直接/传递依赖和完整依赖路径；
- SBOM 组件关系；
- CVE 的多个数据源、修复版本和适用性证据；
- Source、Propagation、Sink 的完整污点路径；
- 漏洞库版本、规则包版本、工具版本和原始报告哈希；
- 扫描器失败、超时、不可用、部分成功和未覆盖原因；
- 原始日志、SBOM 和审计归档。

这些信息必须继续进入平台统一 Finding、Excel 报告和原始证据归档。

## 3. 结论摘要

现有 15 个引擎不应因为接入 SonarQube 而整体替换。建议分为四类处理：

| 决策 | 引擎 | 数量 | 结论 |
| --- | --- | ---: | --- |
| 验证后可下线 | PMD CPD | 1 | SonarQube 已提供重复代码块、重复行和重复率；完成同源验证后可取消独立 CPD Finding |
| 保留但收缩规则 | PMD、Checkstyle、Semgrep、Trivy Repository | 4 | 关闭与 Sonar 重复的通用规则，保留组织规范、安全、框架和 IaC 增量 |
| 保留为互补证据 | Gitleaks、SpotBugs、FindSecBugs、CodeQL | 4 | 与 Sonar 有类别交集，但在规则定制、字节码、安全或污点深度上不可替代 |
| 必须保留 | Dependency-Check、OSV-Scanner、Maven Dependency Analysis、Maven Enforcer、CycloneDX、Trivy Artifact | 6 | Community Build 不具备对应的完整 SCA、SBOM 和 Maven 治理能力 |

按照该建议，近期目标不是从 15 个引擎一次性削减到很少，而是：

```text
SonarQube Community
  + 14 个外部逻辑引擎（CPD 验证下线后）
  + 精简后的规则包
  + 统一 Finding、Excel 和原始证据归档
```

其中 14 是逻辑能力口径，不代表 14 个独立进程；SpotBugs/FindSecBugs、SBOM/Trivy 等仍可复用构建或产物。

## 4. 逐引擎重合与处置矩阵

| # | 当前引擎 | 主要能力 | SonarQube Community 原生重合 | 重合程度 | 推荐处置 | 主要原因 |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | Gitleaks | Token、私钥、云凭据和高熵 Secret | 内置 Secret 检测 | 中 | 保留 | Gitleaks 支持自定义规则、allowlist 和 Git 历史；Community 不支持公司自定义 Secret Pattern |
| 2 | Semgrep | Java/Spring 安全规则、危险 API、组织自定义规则 | 部分源码安全和质量规则 | 中 | 保留并收缩 | 保留 Spring、MyBatis、文件上传、命令执行和内部 API 规则；关闭通用规范重复项 |
| 3 | PMD | AST Bug、复杂度、资源、设计和规范 | Java 可靠性、可维护性规则 | 高 | 保留并收缩 | Sonar 作为通用质量主源；PMD 只保留独有规则和组织扩展 |
| 4 | PMD CPD | 复制粘贴代码块 | 重复块、重复行、重复率和新代码重复率 | 很高 | 验证后下线 | 当前最明确的重复能力；应统一计数口径，避免同一复制问题双份 Finding |
| 5 | Checkstyle | 格式、命名、Import、注释、团队规范 | 部分编码规范和可维护性规则 | 高 | 保留并收缩 | 阿里 Java 规范和公司格式规则仍需要独立规则包；纯格式默认降为 Advisory |
| 6 | Trivy Repository | Secret、Docker/Kubernetes/Terraform 和仓库配置 | 内置 Secret、部分 IaC 语言规则 | 中 | 保留并收缩 | Trivy 继续作为 IaC 和云原生安全主源；普通规范不重复启用 |
| 7 | SpotBugs | 字节码正确性、空指针、并发、资源问题 | Java 可靠性和部分 Bug | 高 | 保留 | 字节码分析层次不可被源码规则完全替代；可作为 SonarJava 交叉证据 |
| 8 | FindSecBugs | Java Web、框架和危险 API 安全 detector | 部分安全规则和 Hotspot | 中 | 保留 | Community 缺少完整 Injection Vulnerabilities Detection 和 Advanced SAST |
| 9 | Dependency-Check | NVD/CPE 依赖漏洞 | 无完整 SCA | 低 | 必须保留 | 提供 CVE、CVSS、CPE 和本地 NVD 证据；Sonar 只能承载摘要问题 |
| 10 | OSV-Scanner | OSV/GHSA/CVE、生态坐标和修复版本 | 无完整 SCA | 低 | 必须保留 | 补充 Maven 生态漏洞和修复版本；与 NVD 形成不同数据源证据 |
| 11 | Maven Dependency Analysis | 使用未声明、声明未使用依赖 | 无 | 无 | 必须保留 | 属于 Maven 构建治理；Sonar Community 不执行该分析 |
| 12 | Maven Enforcer | 依赖收敛、禁用依赖、版本约束 | 无 | 无 | 必须保留 | 属于构建和依赖政策；应与漏洞分开展示 |
| 13 | CycloneDX | 生成组件、版本、关系和许可证 SBOM | 无完整 SBOM 模型 | 无 | 必须保留 | 是供应链资产底账和 Trivy Artifact 的输入，不应按 Finding 计数 |
| 14 | Trivy Artifact | 基于 SBOM/制品的依赖漏洞 | 无完整 SCA | 低 | 必须保留 | 提供独立漏洞库交叉验证和 Java DB；完整组件证据保留在 Excel/归档 |
| 15 | CodeQL | 跨方法数据流、Source 到 Sink、高级安全查询 | 部分代码安全规则 | 中 | 保留 | Community 无法替代高级污点和路径证据；继续作为 Deep 档位 |

## 5. 按能力域确定主引擎和补充引擎

接入 SonarQube 后，应明确每个能力域的“主来源”，避免多个工具都把相同问题当作独立主问题。

| 能力域 | 主来源 | 补充/交叉证据 | SonarQube 中的呈现 |
| --- | --- | --- | --- |
| Java 通用可靠性 | SonarJava | SpotBugs、PMD | Sonar 原生问题；外部独有问题导入，重复命中合并证据 |
| 通用可维护性 | SonarJava | 精简后的 PMD | Sonar 原生为主，PMD 只导入独有规则 |
| 代码规范 | Checkstyle 组织规则包 | SonarJava、精简后的 PMD | 通用规则由 Sonar；阿里/公司规则作为外部问题 |
| 重复代码 | SonarQube | CPD 仅在迁移期对照 | 最终只保留 Sonar 重复指标，不再生成 CPD 独立问题 |
| Java Web 安全 | CodeQL、FindSecBugs、Semgrep | SonarJava 安全规则 | SARIF/外部问题导入；Excel 保留完整路径和适用性 |
| Secret | Gitleaks | Sonar Secret、Trivy Repository | Gitleaks 为主；同文件同凭据类型保守去重，明文统一脱敏 |
| IaC/配置安全 | Trivy Repository | Semgrep、Sonar IaC | Trivy 为主；代码位置明确的问题导入 Sonar |
| 依赖漏洞 | Dependency-Check、OSV、Trivy Artifact | 三数据源互证 | Sonar 只显示组件漏洞摘要；Excel 保留 PURL、路径和数据库证据 |
| Maven 治理 | Maven Dependency Analysis、Enforcer | 无 | 映射到 `pom.xml` 的治理问题；不冒充安全漏洞 |
| SBOM/供应链资产 | CycloneDX | Trivy Artifact | 不按普通 Issue 导入；进入 Excel、manifest 和归档 |

## 6. 可以去掉什么

### 6.1 PMD CPD：唯一明确的下线候选

SonarQube Community 已经提供：

- 重复代码块数量；
- 重复代码行数量；
- 重复行密度；
- 新代码重复率；
- 可用于 Quality Gate 的重复率条件。

CPD 和 Sonar 的计数单位不同：CPD 倾向于 clone group，Sonar 使用重复块、行和密度。因此不能直接比较“25 条 CPD Finding”和“63 个 Sonar 重复块”，但两者表达的是同一类治理事实。

建议下线步骤：

1. 在相同源码、相同排除路径下同时执行 Sonar 与 CPD；
2. 确认当前 benchmark 中有维护价值的复制片段均能被 Sonar 展示；
3. Excel 改用 Sonar 重复块、重复行和重复率，不再把每个 CPD clone group 当作漏洞；
4. 保留 CPD 原始能力一个过渡版本；
5. 完成报告、档位、测试和文档口径调整后再删除适配器。

只有满足以下条件才允许正式下线：

- 没有经过人工确认的高价值 CPD 独有 Finding 丢失；
- Sonar 重复指标已经进入 Excel 和 Quality Gate；
- ZIP、SVN、单模块和多模块样本都通过对比；
- API、报告和验收不再硬编码 Quick 6、Standard 14、Deep 15 的旧数量；
- 原始 CPD 报告不再是任何合规交付的强制证据。

### 6.2 Checkstyle：只在不需要组织规范时才可能进一步下线

如果未来明确不需要阿里 Java 规范、公司命名、Import 顺序、行长和格式门禁，可以再评估移除 Checkstyle。但当前需求包含“建立自己的规则”和“可能内置阿里 Java 规范”，因此本阶段不能去掉。

正确做法是将其收缩为独立规则包：

```text
java-company-baseline
java-alibaba-baseline（可选）
```

纯格式结果默认进入 `CODE_STYLE / ADVISORY`，不与漏洞数量相加。

## 7. 不能去掉什么

### 7.1 依赖漏洞三引擎不能由 SonarQube Community 替代

Dependency-Check、OSV 和 Trivy Artifact 虽然都可能命中同一个 CVE，但其数据源和证据不同：

- Dependency-Check：NVD/CPE/CVSS 证据；
- OSV：生态包坐标、OSV/GHSA 和修复版本；
- Trivy Artifact：基于 SBOM 和 Trivy Java/通用漏洞库的独立匹配。

正确方向是统一组件、PURL、漏洞 ID 和依赖路径后去重，而不是删除到只剩一个数据源。

SonarQube 中只导入摘要，例如：

```text
HIGH：log4j-core 2.14.1 存在 CVE-2021-44228
位置：pom.xml
```

Excel 和原始归档继续保留完整依赖路径、修复版本、数据源、数据库时间和适用性结论。

### 7.2 CycloneDX 不能去掉

CycloneDX 输出的是本次构建的软件物料清单，不是普通问题列表。它承担：

- 直接和传递依赖资产底账；
- 组件版本和 PURL；
- 许可证和组件关系；
- Trivy Artifact 等供应链扫描的标准输入；
- Excel 的 SBOM 工作表和审计归档。

SonarQube Community 没有等价的完整 SBOM 资产模型。

### 7.3 Maven Dependency Analysis 和 Enforcer 不能去掉

两者负责构建治理而非源码规则：

- 已使用未声明依赖；
- 已声明未使用依赖；
- 依赖版本收敛；
- 禁用组件和构建版本约束。

这些问题应在 Excel 中单列“构建与依赖治理”，不能与 SQL 注入或 CVE 统计在一起。

### 7.4 CodeQL 不能由 Community Build 替代

SonarQube Community 能提供部分安全规则，但当前官方能力边界不包含完整 Advanced SAST 和 Injection Vulnerabilities Detection。CodeQL 的主要增量是：

- 跨方法数据流；
- Source、Propagation、Sink；
- SQL/命令/路径等注入类路径；
- 可扩展查询和框架模型；
- SARIF 路径证据。

CodeQL 继续作为 Deep 能力。Sonar 中展示摘要，Excel 和原始 SARIF 保留完整路径。

### 7.5 SpotBugs、FindSecBugs 和 Gitleaks 不能因“界面已能显示”而删除

- SpotBugs 提供字节码视角；
- FindSecBugs 提供 Java Web/框架安全 detector；
- Gitleaks 提供可定制 Secret 规则和可选 Git 历史扫描；
- SonarQube 只是其中部分结果的统一展示和治理入口。

## 8. 需要精简哪些规则

### 8.1 PMD

建议关闭与 Sonar 重复的通用命名、基础复杂度和普通代码味道规则，保留：

- Sonar 没有或项目实测有增量的正确性规则；
- 资源和异常处理增量；
- 组织自定义规则；
- 经独立正反例验证的规则。

### 8.2 Checkstyle

建议保留：

- 阿里 Java 规范中可机器判定的规则；
- 公司命名、Import、禁用 API 和文件组织规范；
- 必须统一的格式规则。

行长、换行和花括号等结果默认不进入高风险统计。

### 8.3 Semgrep

建议关闭通用代码味道和格式规则，保留：

- Spring MVC、Spring Security；
- JDBC、MyBatis 和 SQL 构造；
- 文件上传、路径和命令执行；
- 反序列化、SSRF 和危险外部调用；
- 公司内部危险 API 和禁止调用；
- 上传零散 Java 源码时不依赖构建的安全规则。

### 8.4 Trivy Repository

建议明确其主职责为：

- Docker、Kubernetes、Terraform 等 IaC 安全；
- 仓库 Secret 补充；
- 云原生配置问题。

不与 Sonar 的普通代码质量规则竞争主来源。

## 9. SonarQube 导入与统一报告策略

### 9.1 适合进入 SonarQube 的问题

- 有源码文件和行号的 Bug；
- 代码规范和可维护性问题；
- Secret 的脱敏位置；
- Semgrep、FindSecBugs、CodeQL 的代码漏洞；
- 能合理映射到 `pom.xml` 的依赖或 Maven 治理摘要。

官方直接支持的 Java 外部报告包括 SpotBugs、FindSecBugs、PMD 和 Checkstyle。其他结果优先使用 SARIF 2.1.0，其次转换为 Sonar Generic External Issues。

### 9.2 不按普通 Sonar Issue 处理的数据

- CycloneDX SBOM；
- JaCoCo 覆盖率原始报告；
- 工具和漏洞数据库版本；
- 失败、超时、不可用和跳过状态；
- manifest、日志和原始报告；
- 完整依赖树和污点路径附件。

### 9.3 外部规则治理仍由平台负责

SonarQube 可以展示和处理外部问题，但外部规则不会进入 Sonar Quality Profile；在 Sonar 中标记 False Positive，也不会自动同步回外部扫描器。

因此仍需保留平台侧：

- 引擎规则包版本；
- 规则启停和严重性映射；
- suppression、理由和过期时间；
- 跨引擎去重；
- ACTIONABLE、CONDITIONAL、ADVISORY、FALSE_POSITIVE；
- Excel 和归档的统一统计口径。

## 10. 建议的迁移顺序

### 阶段一：接入但不删除

1. 保持 15 引擎执行不变；
2. 将适合的问题导入 SonarQube；
3. Excel 同时读取统一 Finding 和 Sonar 指标；
4. 建立同源码、同规则族、同位置的重合统计。

### 阶段二：规则收缩

1. SonarJava 成为通用可靠性和可维护性主来源；
2. PMD、Checkstyle、Semgrep、Trivy Repository 关闭重复规则；
3. 观察真实项目和独立 benchmark 中是否损失有效问题；
4. 更新 Quality Gate 和 Excel 分类。

### 阶段三：下线 CPD

1. 完成重复代码同源验证；
2. Excel 改用 Sonar 重复率和重复块数据；
3. 修改 Quick/Standard/Deep 引擎数量口径；
4. 删除 CPD adapter、工具包入口和对应测试；
5. 保留迁移前后对比证据。

### 阶段四：持续治理

1. 用独立真值 Benchmark 验证规则升级；
2. 按确认率和使用价值继续收缩低信号规则；
3. 不以“问题数量减少”作为唯一优化目标；
4. 不因两个工具重合就删除具有独立分析层次的引擎。

## 11. 目标能力组合

建议的目标组合如下：

| 层次 | 组件 | 职责 |
| --- | --- | --- |
| 日常质量中心 | SonarQube Community | SonarJava、复杂度、重复率、代码页面、趋势、Quality Gate |
| 源码与字节码补充 | PMD、Checkstyle、SpotBugs | 组织规范、AST 增量、字节码交叉证据 |
| 代码安全 | Semgrep、FindSecBugs、CodeQL | 快速安全模式、Java detector、深度污点路径 |
| Secret/IaC | Gitleaks、Trivy Repository | 凭据、Token、容器和基础设施配置 |
| 依赖漏洞 | Dependency-Check、OSV、Trivy Artifact | NVD、OSV、Trivy 多数据源证据与修复版本 |
| Maven 治理 | Dependency Analysis、Enforcer | 依赖声明、收敛和构建政策 |
| 供应链资产 | CycloneDX | SBOM、组件、版本、关系和许可证底账 |
| 正式交付 | 统一 Finding、Excel、原始归档 | 去重、定级、适用性、覆盖说明和完整证据 |

## 12. 最终决策

当前建议可以概括为：

1. **可以去掉**：PMD CPD，但必须经过同源项目、零散源码、单模块和多模块样本验证后再下线；
2. **不能直接去掉但应精简**：PMD、Checkstyle、Semgrep、Trivy Repository；
3. **不能去掉**：Gitleaks、SpotBugs、FindSecBugs、Dependency-Check、OSV、Maven Dependency Analysis、Maven Enforcer、CycloneDX、Trivy Artifact、CodeQL；
4. **SonarQube 的定位**：日常代码质量、统一在线查看、趋势和 Quality Gate；
5. **现有平台的保留价值**：外部引擎执行、漏洞数据、统一 Finding、跨工具去重、适用性治理、Excel 和证据归档。

因此，SonarQube Community 与现有平台不是二选一。正确的收敛方向是减少重复规则和重复统计，同时保留不同分析层次、安全数据源和正式审计证据。

## 13. 参考资料

项目内证据：

- [自研 15 引擎扫描器与 SonarQube 同源对比及 Codex 独立复核](scanner-vs-sonarqube-comparison-2026-08-19.md)
- [V1 代码审计能力矩阵](../v1/capability-matrix.md)
- [Java 代码审计平台研究成果汇报摘要](executive-summary.md)
- [SonarQube 与平台能力矩阵](sonarqube-vs-audit-platform-capability-matrix.csv)

SonarSource 官方资料：

- [Community Build 功能对比](https://docs.sonarsource.com/sonarqube-community-build/feature-comparison-table)
- [Community Build 外部问题说明](https://docs.sonarsource.com/sonarqube-community-build/analyzing-source-code/importing-external-issues/about-external-issues)
- [Generic External Issues](https://docs.sonarsource.com/sonarqube-community-build/analyzing-source-code/importing-external-issues/generic-issue-import-format)
- [SARIF 报告导入](https://docs.sonarsource.com/sonarqube-community-build/analyzing-source-code/importing-external-issues/importing-issues-from-sarif-reports)
- [Java 分析和字节码要求](https://docs.sonarsource.com/sonarqube-community-build/analyzing-source-code/languages/java)

# 第二部分：两种开发、架构和部署方案

## 14. 第二部分解决的问题

在完成能力重合分析后，还需要决定平台最终采用哪种产品架构：

1. **方案 A：自研扫描执行与报告层 + SonarQube Community**；
2. **方案 B：纯自研扫描器平台**。

两种方案都需要满足相同的用户入口和交付目标：

```text
输入：一个 ZIP 或一个 SVN 地址
处理：识别项目形态、构建、扫描、归一化、去重和治理
输出：在线状态、完整 Excel、HTML/JSON/SARIF、SBOM 和原始证据 ZIP
```

两种方案的差别不在是否使用外部扫描器，而在于谁负责通用代码质量、在线问题管理、趋势和 Quality Gate。

## 15. 两种方案应使用同一评价口径

两种方案可以由不同仓库、不同代码和不同部署体系实现，但应使用同一组输入分类、结果字段和验收指标。这样最终比较的是两套产品的真实能力，而不是两个无法对齐口径的演示结果。

### 15.1 输入形态必须分类

| 项目形态 | 判断 | 可承诺能力 |
| --- | --- | --- |
| `FULL_MAVEN` | 有唯一根 `pom.xml` 且 Maven 构建成功 | 源码、字节码、依赖、SBOM、SonarJava、JaCoCo 和可选 CodeQL |
| `PARTIAL_MAVEN` | 有 Maven 工程但构建失败或类路径不完整 | 源码和部分依赖扫描；字节码、覆盖率和深度结果明确降级 |
| `SOURCE_ONLY` | 一个或若干 Java 文件，无可构建工程 | PMD、Checkstyle、Semgrep、Gitleaks、Trivy Repository 等源码能力 |
| `INVALID` | 多个根工程、输入越界或没有可扫描文件 | 在预检阶段拒绝，不产生虚假的零问题报告 |

报告必须区分“执行成功且零问题”和“未执行/不可用/失败”。

### 15.2 建议保持一致的 Finding 数据契约

每个扫描器的原始格式先转换成统一 Finding，至少保存：

- 引擎、规则、规则版本和原始严重性；
- 统一分类、优先级、可信度和治理结论；
- 文件、行列、代码片段和指纹；
- CWE、CVE、GHSA、OSV、PURL 和依赖路径；
- Source、Propagation、Sink 和完整数据流；
- 修复版本、修复建议、适用性证据和参考链接；
- 原始产物、工具版本、漏洞库版本和产物哈希；
- 执行状态、耗时、失败原因和覆盖范围。

方案 A 和方案 B 可以分别实现自己的数据模型，不要求共享同一个 Java 类库；但对外报告应尽量遵守相同字段定义。SonarQube、Excel 和 HTML 不应各自随意改变严重性、数量和漏洞身份，否则两套方案无法公平对比。

### 15.3 完整报告不能依赖某一个页面

正式交付包统一为：

```text
audit-report.zip
├── report.xlsx
├── report.html
├── report.json
├── report.sarif
├── manifest.json
├── sbom/bom.json
├── raw/<engine>/*
└── logs/engine-status.json
```

即使 SonarQube 不可用，只要外部扫描任务已成功，平台也应能够输出标明缺失能力的部分报告，而不是丢失全部审计结果。

## 16. 方案 A：自研扫描执行与报告层 + SonarQube Community

### 16.1 方案定位

该方案不把现有平台改造成 SonarQube 插件集合，而是明确分工：

| 层次 | 负责人 | 主要职责 |
| --- | --- | --- |
| 源码接入和任务执行 | 自研 Java 服务 | ZIP/SVN、项目分类、Maven 构建、外部进程、并发、超时和取消 |
| 专项审计 | 14 个外部逻辑引擎 | 字节码、安全、Secret、依赖漏洞、SBOM、Maven 治理和 CodeQL |
| 通用质量中心 | SonarQube Community | SonarJava、复杂度、重复率、代码页面、问题状态、趋势和 Quality Gate |
| 正式交付 | 自研报告层 | 统一 Finding、去重、适用性、Excel、HTML/JSON/SARIF 和原始证据 |
| 数据持久化 | 文件存储 + PostgreSQL | 自研任务仍使用文件；PostgreSQL 仅服务 SonarQube |

SonarQube 不是扫描任务的唯一事实源。外部问题导入 Sonar 后只是在线投影，Excel 仍以统一 Finding 为准，避免从 Sonar API 读回后重复计数。

### 16.2 逻辑架构

```mermaid
flowchart TB
    U["Web 用户"] --> API["审计 API / Web"]
    API --> INTAKE["ZIP/SVN 源码接入"]
    INTAKE --> CLASSIFY["项目分类与预检"]
    CLASSIFY --> BUILD["受控 Maven 构建"]
    CLASSIFY --> SOURCE["源码扫描器"]
    BUILD --> BINARY["字节码/依赖/SBOM/Deep"]
    SOURCE --> NORMALIZE["统一 Finding"]
    BINARY --> NORMALIZE
    NORMALIZE --> SONARFMT["外部报告/SARIF 导出"]
    BUILD --> SONARSCAN["SonarScanner"]
    SONARFMT --> SONARSCAN
    SONARSCAN --> SONAR["SonarQube Community"]
    SONAR --> SONARAPI["Sonar API：原生问题/指标/Gate"]
    NORMALIZE --> REPORT["报告聚合器"]
    SONARAPI --> REPORT
    REPORT --> XLSX["Excel"]
    REPORT --> ARCHIVE["HTML/JSON/SARIF/SBOM/原始证据"]
```

### 16.3 单次任务流程

1. 接收 ZIP 或 SVN 地址，生成 `scanId` 和不可变源码哈希；
2. 安全解压或固定 Revision 检出；
3. 识别 `FULL_MAVEN`、`PARTIAL_MAVEN` 或 `SOURCE_ONLY`；
4. 根据项目形态创建执行 DAG；
5. Maven 构建成功后并行执行字节码、依赖和 SBOM 工具；
6. 所有外部结果归一化、脱敏和初步去重；
7. 生成 Sonar 外部报告或 SARIF；
8. 对可进行 SonarJava 分析的项目运行一次 SonarScanner；
9. 等待 Sonar Compute Engine 完成，读取 Sonar 原生问题、复杂度、重复率、覆盖率和 Quality Gate；
10. 将 Sonar 原生问题转换成统一 Finding，与外部 Finding 保守去重；
11. 生成 Excel 和完整审计归档；
12. 按保留策略清理工作目录、临时 Sonar 项目和过期报告。

### 16.4 Sonar 项目映射

| 输入 | `projectKey` 策略 | 生命周期 |
| --- | --- | --- |
| ZIP 临时扫描 | `audit-adhoc-<scanId>` | 每次独立，报告生成后保留 7～30 天再清理 |
| SVN 持久项目 | `audit-svn-<repository-url-hash>` | 同仓库复用，保存 Revision 和长期趋势 |
| SVN 一次性扫描 | `audit-svn-adhoc-<scanId>` | 不污染持久项目，按临时项目清理 |

同一 Sonar 项目不得并发提交两个最终分析；同仓库的新任务应排队或取消旧的排队任务。

### 16.5 Java 工程模块建议

如果方案 A 独立立项，可以在新的代码仓库中按以下边界建设；也可以选择性复用现有平台中成熟的源码接入、Scanner Adapter、Finding 或报告模块，但复用不是方案 A 成立的前提：

```text
source-intake
project-classifier
scan-orchestrator
local-process-runner
scanner-adapters
finding-core
rule-governance
sonarqube-integration
excel-report-service
report-service
file-storage
audit-api
```

`sonarqube-integration` 建议包含：

- `SonarProjectService`：创建、查询和删除项目；
- `SonarTokenService`：最小权限项目 Token 生命周期；
- `SonarScannerRunner`：安全参数数组和超时执行；
- `SonarExternalIssueExporter`：Generic External Issues；
- `SonarSarifExporter`：SARIF 路径和严重性转换；
- `SonarComputeTaskPoller`：异步任务状态和超时；
- `SonarIssueClient`：只拉取 Sonar 原生问题，过滤外部问题镜像；
- `SonarMeasureClient`：覆盖率、复杂度、重复率和规模；
- `SonarQualityGateClient`：Gate 结果和条件；
- `SonarRetentionService`：临时项目过期清理。

`excel-report-service` 建议包含：

- 报告数据聚合和统一统计；
- 封面、概览、图表和风险矩阵；
- 代码漏洞、依赖漏洞、Secret、质量、覆盖率和 SBOM 工作表；
- 引擎状态、未覆盖项、误报和抑制工作表；
- Apache POI `SXSSF` 大数据量流式输出；
- Secret 脱敏、超链接安全和 Excel 公式注入防护。

### 16.6 最小部署单元

正式环境最少需要三个逻辑服务：

| 服务 | 端口示例 | 持久化 | 是否对用户开放 |
| --- | ---: | --- | --- |
| 自研审计 Java 服务 | 8080 | 任务、报告、缓存和工具数据目录 | 是 |
| SonarQube Community | 9000 | 配置、索引和日志目录 | 建议仅内网或经审计服务跳转 |
| PostgreSQL | 5432 | SonarQube 数据库 | 否，只允许 SonarQube 访问 |

JDK、Maven、扫描器 CLI、NVD/Trivy 数据库和 CodeQL 查询包是工具或数据，不是常驻服务。

推荐部署方式：

```text
Linux x86_64
├── audit-service.jar                  # 宿主机 JDK 17/systemd
├── tools/                             # 固定版本工具包
├── data/jobs|reports|cache|databases  # 本地持久化
└── Docker Compose
    ├── sonarqube
    └── postgresql
```

不使用 Docker 时，三个组件也可以全部由 systemd 管理，逻辑服务数量不变。

可选服务：

- Nginx：HTTPS、统一域名和上传大小限制；
- Jenkins：后续持续集成；
- 独立 Scanner Worker：面向不可信代码或需要横向扩容时；
- 对象存储：多节点或大规模长期报告归档时。

### 16.7 并发模型

不需要为每个任务启动一套 SonarQube。所有任务共享一个 SonarQube 和 PostgreSQL，每个任务只启动需要的扫描器子进程。

初始建议限流：

| 资源 | 初始建议 |
| --- | ---: |
| 同时运行任务 | 2～4 |
| 单任务并行引擎 | 3～5 |
| Maven | 2 |
| Dependency-Check | 1 |
| CodeQL | 1 |
| 同时提交 SonarScanner | 2 |
| 同一 Sonar `projectKey` | 1 |

实际值必须通过目标 Linux 的 CPU、内存、磁盘和 Sonar Compute Engine 队列压测后调整。

### 16.8 方案 A 优点

- 直接复用成熟的 Java 规则、代码页面、问题生命周期和趋势；
- 直接具备复杂度、重复率、覆盖率和 Quality Gate；
- SpotBugs、FindSecBugs、PMD、Checkstyle 具有官方外部报告入口；
- SARIF/Generic Issue 可以统一展示外部漏洞；
- 后续接 Jenkins、Git 和持续质量治理成本更低；
- 自研精力集中在 Sonar Community 缺失的漏洞、SBOM、报告和输入服务。

### 16.9 方案 A 缺点

- 正式部署从一个 JAR 变成至少三个服务；
- SonarQube 正式环境需要 PostgreSQL和额外运维；
- Community 仍无正式多分支和 PR 分析；
- 外部规则不进入 Sonar Quality Profile；
- 在 Sonar 中标记外部问题为误报不会自动同步回外部工具；
- 依赖漏洞、SBOM 和完整污点路径仍需自研报告；
- Sonar 升级会带来 Scanner、API、规则和报告兼容性测试成本；
- 上传零散 Java 源码时，SonarJava 因缺少字节码不能作为稳定主能力。

## 17. 方案 B：纯自研扫描器平台

### 17.1 方案定位

纯自研不是自己编写所有静态分析算法，而是继续使用现有 15 个开源引擎，由自研平台承担全部编排、治理、在线查询、报告和门禁逻辑，不部署 SonarQube。

```text
一个 Java 服务 JAR
  + 本地 tools
  + 本地漏洞/规则数据
  + 文件任务存储
  + HTML/JSON/SARIF/SBOM/Excel/ZIP
```

### 17.2 逻辑架构

```mermaid
flowchart TB
    U["Web 用户"] --> API["审计 API / Web"]
    API --> INTAKE["ZIP/SVN 源码接入"]
    INTAKE --> CLASSIFY["项目分类与预检"]
    CLASSIFY --> BUILD["受控 Maven 构建"]
    CLASSIFY --> SOURCE["源码扫描器"]
    BUILD --> BINARY["字节码/依赖/SBOM/CodeQL"]
    SOURCE --> NORMALIZE["统一 Finding"]
    BINARY --> NORMALIZE
    NORMALIZE --> GOVERN["去重/定级/适用性/抑制"]
    GOVERN --> STORE["文件任务与历史快照"]
    GOVERN --> REPORT["统一报告服务"]
    REPORT --> XLSX["Excel"]
    REPORT --> ARCHIVE["HTML/JSON/SARIF/SBOM/原始证据"]
```

### 17.3 部署单元

最小正式部署仍可保持：

| 部署项 | 类型 | 是否常驻服务 |
| --- | --- | ---: |
| `audit-service.jar` | Java 17 服务 | 是 |
| `tools/` | 外部 CLI/JAR 工具包 | 否 |
| `data/` | 任务、报告、缓存和漏洞数据库 | 否 |

即一个常驻服务，不强制 PostgreSQL、Redis、消息队列或 Kubernetes。

对于可信内部代码，可以继续使用本地子进程执行；如果允许不可信外部用户上传项目，Maven 插件和测试可能执行任意代码，两种方案都必须增加容器、受限账户或独立 Worker 隔离。

### 17.4 方案 B 优点

- 部署最简单，保持一个 JAR + 工具包；
- 不需要 PostgreSQL 和 SonarQube 运维；
- ZIP、SVN、一次性扫描和零散 Java 源码天然是一等入口；
- 报告模型、规则治理、脱敏、保留策略和 API 完全可控；
- 适合离线、内网、单机和自用场景；
- 依赖漏洞、SBOM、工具状态和原始证据无需迁就 Sonar Issue 模型；
- 现有代码、测试、工具包和生产验证可以最大程度复用。

### 17.5 方案 B 缺点

- 需要自己建设代码页面、问题评论、责任人、状态和历史趋势；
- 需要自己实现 Quality Profile、Quality Gate 和新增代码基线；
- 通用 Java 规则丰富度和维护速度难以直接追平 SonarJava；
- 重复率、认知复杂度、测试代码规则等需要继续补齐；
- 与 Jenkins/Git 的日常开发体验需要自研；
- 长期维护扫描器版本、规则包、归一化和 Web 体验的成本更高；
- 如果继续追求 Sonar 的所有能力，最终容易重复建设成熟平台。

## 18. 两种方案对比

| 对比维度 | 方案 A：自研 + SonarQube | 方案 B：纯自研 |
| --- | --- | --- |
| 建设方式 | 可新建独立的 SonarQube 增强审计平台仓库 | 继续建设当前 `java-code-audit-platform` 仓库 |
| 是否必须共用代码 | 不需要；只在确有收益时复用成熟模块 | 不需要依赖方案 A 的任何模块 |
| 最小常驻服务 | 3 个：审计服务、SonarQube、PostgreSQL | 1 个：审计服务 |
| 外部扫描器 | 收敛为 14 个逻辑引擎，新增 SonarJava | 保持现有 15 个逻辑引擎 |
| 数据库 | SonarQube 必须使用正式数据库；自研侧仍可文件存储 | 不需要数据库 |
| ZIP/SVN 一次性扫描 | 需要为 ZIP 管理临时 Sonar 项目 | 原生适配，流程最短 |
| 零散 Java 源码 | SonarJava 受字节码限制，依赖外部源码工具 | 直接使用 Quick/source-only 工具 |
| 通用 Java 质量 | SonarJava 规则和生态更成熟 | 依赖 PMD/SpotBugs/Checkstyle 和自定义规则 |
| 重复和复杂度 | Sonar 原生提供成熟指标 | CPD + 自研指标和展示 |
| 漏洞、SCA、SBOM | 仍依赖自研外部引擎和报告 | 已由现有引擎完整承接 |
| 在线问题管理 | Sonar 成熟 | 需要继续自研 |
| Quality Gate | Sonar 成熟 | 需要自研政策和门禁 |
| 外部规则治理 | Sonar 中只能展示；启停仍在外部 | 全部在自研治理层统一控制 |
| Excel/正式审计报告 | 仍需自研 | 完全由自研报告层生成 |
| Jenkins 集成 | Sonar 插件、Webhook 和 Gate 较成熟 | 调用自研 API、轮询/回调和自研 Gate |
| Community PR/分支 | 仅主分支，仍有限制 | 可按产品需求自己实现，但开发成本高 |
| 运维复杂度 | 中高 | 低 |
| 升级风险 | Sonar、数据库、Scanner、API 和外部工具共同升级 | 主要是自研服务和外部工具 |
| 离线/单机适应性 | 较弱 | 强 |
| 首次改造成本 | 较高，需要 Sonar 集成和双来源去重 | 较低，主要新增 Excel |
| 长期质量平台成本 | 较低，复用 Sonar 成熟能力 | 较高，持续自研通用平台功能 |
| 对当前成果复用 | 可选择复用，复用程度不作为方案前提 | 最高 |

## 19. 对当前真实需求的判断

当前最明确的第一阶段需求是：

```text
上传 ZIP 或提供 SVN
  → 执行 Java/Maven 审计
  → 下载一份完整 Excel/ZIP 报告
```

就这个单次扫描目标而言，纯自研方案更接近现有成果，部署简单，改造成本最低。SonarQube 的主要增量是通用 Java 质量、在线治理、趋势和未来 Jenkins 流水线，而不是依赖漏洞或 Excel。

不能据此预设两种方案必须共用一套代码。方案 A 可以作为新的 SonarQube 增强审计产品独立立项；方案 B 继续使用当前仓库。是否复用 Scanner Adapter、Finding 模型或 Excel 组件，应由实际复用收益决定，而不是把两种部署强行绑在一起。

## 20. 两套方案可以独立建设

### 20.1 方案 A：独立的 SonarQube 增强审计平台

方案 A 可以新建独立仓库，例如 `sonarqube-audit-platform`。它以 SonarQube 为质量中心，自研部分只补齐输入、专项漏洞扫描、统一报告和交付能力。

建议的仓库边界：

```text
sonarqube-audit-platform/
├── audit-api/                  # ZIP/SVN 接口、任务查询和报告下载
├── source-intake/              # 安全解压、SVN 快照和项目分类
├── scan-orchestrator/          # Maven、SonarScanner 和专项工具编排
├── external-scanner-adapters/  # SCA、Secret、SBOM、CodeQL 等专项适配器
├── sonar-integration/          # 项目、Token、分析、API、Gate 和清理
├── finding-contract/           # 方案 A 自己的统一结果模型
├── excel-report-service/       # Excel 和正式归档
└── distribution/               # 安装包、配置和部署脚本
```

它可以选择性迁移当前仓库中已经验证过的 Adapter 或报告逻辑，也可以重新实现。关键是方案 A 自己能够独立编译、测试、发布和升级，不依赖方案 B 正在运行。

方案 A 的最小部署仍是：

```text
服务 1：sonarqube-audit-service.jar
服务 2：SonarQube Community
服务 3：PostgreSQL
附属介质：Scanner CLI、专项工具、漏洞数据库、规则和查询包
```

三个服务可以使用 Docker Compose，也可以由 systemd 分别运行。SonarQube 和 PostgreSQL 是共享常驻服务，不是每次扫描各启动一个实例。

### 20.2 方案 B：当前纯自研扫描器平台

方案 B 继续在当前 `java-code-audit-platform` 仓库独立建设，不要求引入任何 SonarQube 代码或接口：

```text
java-code-audit-platform/
├── source-intake
├── scan-orchestrator
├── scanner-adapters
├── finding-core
├── rule-governance
├── excel-report-service
├── report-service
├── file-storage
├── audit-api
└── distribution
```

方案 B 的最小部署保持：

```text
服务 1：audit-service.jar
附属介质：tools、规则、NVD/Trivy 数据库、CodeQL 查询包和文件数据目录
```

它独立承担任务、引擎状态、规则治理、统计、Excel、HTML/JSON/SARIF、SBOM、原始证据和后续自研 Gate，不需要 SonarQube 或 PostgreSQL。

### 20.3 可以共享标准，但不强制共享代码

为了让两套方案能够公平比较，建议共同维护以下“标准资产”：

| 标准资产 | 作用 | 是否要求共享实现 |
| --- | --- | --- |
| 真值 Benchmark | 比较召回率、准确率和误报率 | 否，使用同一输入和人工真值即可 |
| Finding 字段规范 | 对齐规则、位置、严重性、证据和身份 | 否，各自实现 |
| 风险分类和严重性映射 | 防止同一问题在两套报告中口径相反 | 否，各自加载或编码 |
| Excel 列和统计口径 | 让领导或用户可直接横向看报告 | 否，可以有不同模板实现 |
| 规则取舍台账 | 记录重合、独有、关闭和误报原因 | 否，台账本身可以独立维护 |
| 验收场景 | ZIP、SVN、构建失败、并发和故障恢复 | 否，两边分别执行 |

未来只有在两个产品长期并行且复制维护成本明显上升时，才考虑把稳定的数据契约或报告模板抽成公共库；当前不应为了代码复用提前制造耦合。

## 21. 两套方案各自的开发计划

### 21.1 方案 A 开发计划

#### A1：独立可行性原型

1. 单独部署 SonarQube Community 和 PostgreSQL；
2. 用同一份完整 Maven、构建失败和零散 Java 样例验证 SonarJava 边界；
3. 验证 ZIP 临时项目、SVN 持久项目和项目清理；
4. 验证 Generic External Issues、SARIF、SpotBugs、FindSecBugs、PMD 和 Checkstyle 导入；
5. 验证 Sonar 原生问题、外部问题、指标和 Gate 能否稳定导出为 Excel；
6. 形成“保留、导入、只放 Excel、删除”的最终引擎清单。

#### A2：最小可用产品

1. 建立独立仓库和发布流程；
2. 实现 ZIP/SVN、任务 API、Maven 构建和 SonarScanner；
3. 接入依赖漏洞、Secret、SBOM、Maven 治理和可选 CodeQL；
4. 实现方案 A 自己的 Finding、去重、脱敏和 Excel；
5. 实现临时 Sonar 项目、Token 和保留期管理；
6. 提供一键部署、健康检查和备份恢复文档。

#### A3：生产化与持续集成

1. 完成并发、超时、取消、重启和 Sonar 故障测试；
2. 完成 PostgreSQL 备份、Sonar 升级和 API 兼容测试；
3. 通过 Jenkins 对 Git/SVN 构建结果调用审计服务；
4. 将 Quality Gate、Excel/ZIP 归档和发布阻断接入流水线；
5. 逐步建设长期项目趋势，而一次性 ZIP 继续使用临时项目。

### 21.2 方案 B 开发计划

#### B1：正式报告闭环

1. 在当前仓库新增或完善 Excel 报告；
2. 固化概览、风险、代码位置、依赖路径、引擎状态和未覆盖原因；
3. 验证完整 Maven、构建失败、零散 Java、ZIP 和 SVN；
4. 保持一个 JAR + tools + data 的发布和启动方式。

#### B2：准确率和规则治理

1. 以独立真值 Benchmark 计算每个引擎和规则族的准确率、召回率和误报率；
2. 建立规则档位、项目级白名单、基线、到期抑制和理由审计；
3. 对重合规则只保留证据更完整、真实准确率更高的一侧；
4. 补齐认知复杂度、测试代码、空指针、资源泄漏等已验证的规则缺口；
5. 通过版本化回归集防止规则调整后漏报或数量失控。

#### B3：生产化与后续 Jenkins

1. 完成 Linux x86_64 介质、完整漏洞库和离线更新流程；
2. 完成并发、限流、低磁盘、取消、重启、归档和保留测试；
3. 提供自研 Gate API，例如按新增高危、可信度和引擎失败决定是否通过；
4. Jenkins 通过 REST API 提交 ZIP/SVN 或工作区产物，轮询结果并归档 Excel/ZIP；
5. 如确有需要，再建设趋势、责任人和问题生命周期，不把它们作为首版前提。

### 21.3 两套方案的共同对比验收

两套方案应各自完成后，再使用同一批输入进行盲测，而不是用一套方案的结果当另一套方案的真值：

| 验收维度 | 主要指标 |
| --- | --- |
| 检测能力 | 已知真问题召回率、确认问题准确率、误报率、独有问题数 |
| 覆盖边界 | 完整 Maven、构建失败、源码片段、单模块和多模块 |
| 报告能力 | Excel 完整度、证据链、去重、未执行原因和可复核性 |
| 性能 | 总耗时、CPU、内存、磁盘、并发吞吐和排队时长 |
| 稳定性 | 工具失败、网络失败、数据库不可用、取消和重启恢复 |
| 部署运维 | 安装步骤、服务数量、数据更新、升级、备份和故障定位 |
| 研发接入 | ZIP/SVN 易用性、Jenkins 接入、Gate 和历史趋势 |
| 长期成本 | 规则升级、工具兼容、平台研发和人员学习成本 |

最终对比报告应同时包含数量和人工复核结论。单纯比较“谁报得多”没有意义，报得多可能只是误报更多。

## 22. 选择条件，而不是预设结论

### 更适合选择方案 A 的情况

- 目标是长期代码质量平台，而不只是一次性审计报告；
- 很快要和 Jenkins、Git 或 SVN 持续构建深度结合；
- 重视在线问题状态、代码浏览、趋势、复杂度、重复率和 Quality Gate；
- 能接受 SonarQube、PostgreSQL 和审计服务三个常驻服务；
- 愿意承担 Sonar 升级、数据库备份和 API 兼容运维。

### 更适合选择方案 B 的情况

- 当前第一目标是“上传 ZIP/SVN，完成扫描，下载 Excel/ZIP”；
- 希望保持一个 Java 服务、文件存储和较简单的部署；
- 重视专项安全、SCA、SBOM、Secret、原始证据和离线运行；
- 希望完全控制规则治理、报告格式和 API；
- 暂时不需要复制 Sonar 的全部在线质量管理能力。

### 当前阶段的客观判断

按当前已经明确的 ZIP/SVN 和正式报告需求，方案 B 的短期交付成本更低，并且可以直接延续已有成果；按未来 Jenkins、持续质量治理和长期趋势需求，方案 A 的平台能力更成熟。这两个判断可以同时成立，不代表必须把它们做成一套代码。

如果要在投入完整开发前做决策，建议先建设两个相互独立的小型原型：

1. 方案 A 原型：SonarQube + 必要专项扫描器 + Excel；
2. 方案 B 原型：当前 15 引擎 + Excel；
3. 使用同一份独立真值数据和同一批真实项目进行盲测；
4. 再根据准确率、报告、部署、性能和长期维护成本决定建设哪一个，或者将二者作为不同定位的产品分别保留。

无论最终选择哪套方案，都不应把 SonarQube 的结果当作绝对真值，也不应以当前自研扫描器的结果反向证明自己准确。判断依据必须是独立真值 Benchmark、人工复核和真实生产样本。
