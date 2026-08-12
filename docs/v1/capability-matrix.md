# V1 代码审计能力矩阵

## 1. 数量口径

V1 对外表达为：

- **9组用户可理解的审计能力**；
- **12类可计数的问题分类**；
- **1类不可计入问题总数的 SBOM/资产清单**；
- **15个逻辑扫描引擎项**，外加1个 Maven 构建阶段；
- 多个逻辑引擎可以复用同一次进程，例如 SpotBugs 与 FindSecBugs，也可以复用同一份构建或 SBOM。

逻辑引擎数是调度和覆盖口径，不代表必须启动15个独立进程。

## 2. 九组能力

| # | 能力包 | 主要工具 | 主要检查 | 能力程度 | 主要边界 |
| --- | --- | --- | --- | --- | --- |
| 1 | Java 潜在 Bug | SpotBugs、PMD | 空指针、错误 API、异常误用、无效条件、资源泄漏、并发误用 | 较强 | 需要正确字节码/类路径；反射和运行时状态会漏报 |
| 2 | Java Web 漏洞与污点 | FindSecBugs、Semgrep CE、CodeQL | SQL/命令/路径/XPath 注入、XSS、SSRF、反序列化、弱加密、Source→Sink | 较强 | 框架自定义封装、反射和 sanitizer 模型影响精度 |
| 3 | 代码规范 | Checkstyle、PMD | 命名、导入、格式、复杂度、设计规则、禁用 API | 强 | 不逐条复制 IDEA Inspection 规则 ID |
| 4 | 依赖漏洞 | Dependency-Check、OSV-Scanner、Trivy | Maven 直接/传递依赖的 CVE、GHSA、OSV | 强 | 版本识别、数据时效和可达性影响判断 |
| 5 | 密钥与敏感信息 | Gitleaks、Trivy | Token、密码、私钥、云凭据和高熵敏感串 | 强（当前快照） | 不验证凭据仍有效；V1 不扫 SVN 历史 |
| 6 | 重复与可维护性 | PMD CPD、PMD | 重复片段、复杂度、设计异味、可维护性风险 | 较强 | 不能替代架构和领域建模评审 |
| 7 | Maven 治理 | Dependency Plugin、Enforcer | 未声明/未使用依赖、收敛、禁用依赖、版本与构建约束 | 强 | Spring/SPI/反射可能产生“未使用”误报 |
| 8 | SBOM/许可证/供应链 | CycloneDX、Trivy | 组件坐标、版本、关系、许可证、存在漏洞的组件 | 较强 | 许可证结果不是法律意见；运行时动态组件可能缺失 |
| 9 | 配置与 IaC | Trivy | Dockerfile、Kubernetes/Terraform 等仓库配置错误和安全策略 | 较强 | 不代表真实生产环境配置，不扫描运行中的基础设施 |

## 3. 十二类问题

| 分类代码 | 中文名称 | 典型内容 | 主要来源 |
| --- | --- | --- | --- |
| CORRECTNESS | 正确性与潜在 Bug | Null、分支、异常、API 误用 | SpotBugs、PMD |
| WEB_SECURITY | Java Web 安全 | 注入、XSS、SSRF、反序列化、弱加密 | FindSecBugs、Semgrep、CodeQL |
| CONCURRENCY | 并发与线程安全 | 锁、同步、共享状态、并发 API | SpotBugs、PMD |
| RESOURCE_PERFORMANCE | 资源与性能 | 流未关闭、无界分配、低效调用 | SpotBugs、PMD |
| MAINTAINABILITY | 可维护性与设计 | 复杂度、耦合、坏味道、设计规则 | PMD、SpotBugs |
| CODE_STYLE | 代码规范与风格 | 命名、导入、格式、注释和团队规则 | Checkstyle、PMD |
| DUPLICATION | 重复代码 | 复制粘贴片段和重复组 | PMD CPD |
| SECRET_EXPOSURE | 密钥与敏感信息 | Token、密码、私钥和凭据 | Gitleaks、Trivy |
| DEPENDENCY_VULNERABILITY | 依赖漏洞 | CVE、GHSA、OSV、受影响版本 | Dependency-Check、OSV、Trivy |
| BUILD_GOVERNANCE | Maven 构建治理 | 依赖收敛、声明、禁用组件和版本规则 | Maven Dependency、Enforcer |
| CONFIG_IAC_SECURITY | 配置与 IaC 安全 | 错误云/IaC/容器配置 | Trivy |
| LICENSE_SUPPLY_CHAIN | 许可证与供应链策略 | 许可证不明、禁用许可和供应链策略 | Trivy、SBOM Policy |

SBOM 的 `componentCount`、直接/传递依赖数、许可证清单属于资产统计。只有资产关联到漏洞或违反明确策略时才产生 Finding。

## 4. 扫描档位与逻辑引擎

### QUICK：6项

| 引擎 ID | 工具 | 是否依赖 Maven 构建 | 输出 |
| --- | --- | --- | --- |
| gitleaks | Gitleaks | 否 | JSON/SARIF |
| semgrep | Semgrep CE | 否 | JSON/SARIF |
| pmd | PMD | 否 | XML/JSON/SARIF（按锁定版本能力） |
| pmd-cpd | PMD CPD | 否 | XML |
| checkstyle | Checkstyle | 否 | XML |
| trivy-repository | Trivy | 否 | JSON/SARIF |

### STANDARD：Quick + 8项

STANDARD 先建立 Maven 构建状态，再执行以下逻辑引擎。源码/依赖类工具可按 DAG 与构建并行；字节码工具必须等待构建成功。

| 引擎 ID | 工具 | 构建依赖 | 输出 |
| --- | --- | --- | --- |
| spotbugs | SpotBugs | class/类路径 | XML/SARIF |
| findsecbugs | FindSecBugs | 复用 SpotBugs 执行 | SpotBugs XML/SARIF中的安全规则 |
| dependency-check | OWASP Dependency-Check | Maven 依赖/产物 | JSON/SARIF/HTML |
| osv-scanner | OSV-Scanner | POM/SBOM/锁定文件 | JSON/SARIF |
| maven-dependency-analysis | Maven Dependency Plugin | Maven Reactor | 日志和结构化转换结果 |
| maven-enforcer | Maven Enforcer | Maven Reactor | 日志和结构化转换结果 |
| cyclonedx | CycloneDX Maven Plugin | Maven Reactor | CycloneDX JSON/XML |
| trivy-artifact | Trivy | 构建产物或 SBOM | JSON/SARIF |

### DEEP：Standard + 1项

| 引擎 ID | 工具 | 构建依赖 | 输出 |
| --- | --- | --- | --- |
| codeql | CodeQL CLI + Java 查询包 | 创建 CodeQL Java 数据库 | SARIF、数据库统计、查询包清单 |

CodeQL CLI 未安装或策略不允许时，Deep 请求在预检阶段返回明确的不可用原因，不能静默降级成 Standard。

## 5. 对四个既有 Skill 的覆盖

| 既有 Skill | V1 覆盖 | 覆盖性质 | 仍有差异 |
| --- | --- | --- | --- |
| `smart-inspect-code-review` | SpotBugs + PMD + Checkstyle | 类别覆盖 | 不复制 IDEA 的全部规则、等级和规则 ID；Error Prone/NullAway 延后 |
| `smart-qodana-security-review` | CodeQL + FindSecBugs + Semgrep | 安全与污点类别覆盖 | Qodana 专属框架模型、规则和 taint path 不保证逐条一致 |
| `smart-spotbugs-check-review` | 同一 SpotBugs 引擎和可配置优先级策略 | 同引擎复现 | 工具版本、字节码、类路径和 filter 必须一致才可能接近相同结果 |
| `smart-owasp-check-review` | 同一 Dependency-Check + OSV/Trivy 补充 | 同引擎复现 + 数据补充 | 数据库时间、依赖识别和 suppression 会改变结果 |

“覆盖”表示问题类别与主要能力被扫描器组合承接，不表示复制 IDEA/Qodana 的专有实现。

## 6. 第一批五项增量

1. Gitleaks：补充密钥与凭据泄漏；
2. PMD CPD：补充重复代码；
3. Maven Dependency Plugin + Enforcer：补充依赖健康和构建治理；
4. CycloneDX：建立每次审计的 SBOM 资产底账；
5. Trivy：补充配置、IaC、制品、许可证和供应链视角。

## 7. 明确缺口

- 业务越权、租户隔离、金额/状态机绕过；
- 真实认证会话、Header、Cookie、CORS、网络调用和运行时配置；
- 反射、动态类加载、脚本、运行时生成 SQL 等难以静态建模的行为；
- 依赖漏洞的真实调用可达性证明；
- 架构约束、领域边界和测试有效性；
- 人工确认的误报、风险接受和修复优先级。

这些缺口必须在报告边界中直说，不能通过叠加命中数量掩盖。
