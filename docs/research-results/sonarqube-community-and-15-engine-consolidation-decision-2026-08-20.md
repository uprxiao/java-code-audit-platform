# SonarQube Community 与现有 15 引擎功能重合及收敛决策

日期：2026-08-20  
状态：讨论基线，尚未据此删除生产引擎  
适用范围：Java 17、Maven、ZIP/SVN 源码接入、SonarQube Community Build

## 1. 文档目的

本文回答四个问题：

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

