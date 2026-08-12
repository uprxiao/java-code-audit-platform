# V1 验收证据索引

> 对应 `main` 实现提交 `8be9d46` 及其前置提交；验收日期 2026-08-12。  
> 本文只索引可重复或可下载证据，不用“代码已写”代替验收。

## 1. 发布对象

| 项目 | 值 |
| --- | --- |
| 应用形态 | 同一 Spring Boot JAR，Java class major 61 |
| macOS | ARM64，JDK 17.0.18，Maven 3.9.12 |
| Linux | GitHub-hosted Ubuntu 22.04 x86_64，Temurin JDK 17，Maven 3.9.12 |
| Mac 最终包 | `dist/acceptance-final/java-code-audit-platform-0.1.0-v1-final-darwin-arm64.zip` |
| Mac 包 SHA256 | `752622bd7a4812691ca71f6062263fd705e5372e9daba3263f9074b9933ad5f1` |
| Mac 包大小 | 320 MB（不含动态漏洞库和 CodeQL） |
| 动态数据 | Trivy 通用+Java 库约 2.6 GB；Dependency-Check 验收库 13 MB |
| CodeQL | CLI 2.26.2 + `codeql/java-queries` 1.11.7，本机安装，不再分发 |

13 MB Dependency-Check 数据库是故意只含 2021 NVD feed 的验收数据，只用于证明
Log4Shell PURL/CVE 解析契约。它带 `productionUseProhibited=true` 和 `ACCEPTANCE-ONLY.txt`，
不能用于真实审计；生产必须使用完整 NVD 数据。

## 2. 真实介质 E2E

### macOS ARM64

三档均从发布 ZIP 解压后用 `bin/run.sh` 启动，再用介质内
`bin/acceptance-test.sh` 上传 Java 17 Maven Fixture、轮询、查询引擎/Finding、下载报告并校验归档。

| Profile | Scan ID | 引擎 | 终态 | 耗时 | unique/raw | 附加断言 |
| --- | --- | ---: | --- | ---: | --- | --- |
| Quick | `0296a3f0-e41b-4add-ae10-b9bb49be0e71` | 6 | COMPLETED | 9.427 s | 0/0 | ZIP可解、canary无泄漏、源码已清理 |
| Standard | `a4afa434-b677-4188-8533-c87d900ed415` | 14 | COMPLETED | 96.778 s | 17/17 | Maven、SBOM、依赖漏洞、字节码引擎全成功 |
| Deep | `7fee2c75-dab2-418e-ad11-8cba32b3bbca` | 15 | COMPLETED | 40.649 s | 18/18 | CodeQL真实命中，显式 Source→Propagation→Sink |

证据在 gitignored 的 `v1-acceptance-evidence/macos-final/`，每个任务包含
health/tools/profiles/create/scan/engines/findings/report.zip 和 `SHA256SUMS`。

成功后任务目录另外递归检查：不存在 `source`、`workspace`、`repository`、`target`、
`codeql-db` 或 `.m2`；除已脱敏 ZIP 外的任务文件也不含 canary。

### Ubuntu 22.04 x86_64

- [CI Run 31582732490](https://github.com/uprxiao/java-code-audit-platform/actions/runs/31582732490)：
  Linux 原生 Quick/Standard 包组装与 SHA 校验、全部真实 Standard adapter smoke、
  全仓 JDK17 verify、Linux 发布 ZIP、从 ZIP 启动和 Web Quick/Standard E2E 全成功。
- Artifact `linux-quick-standard-evidence-31582732490`；本机副本在
  `v1-acceptance-evidence/linux-final-standard/`。
- Linux Quick：`c4a3c054-939a-46cb-b94e-0727cb6c6a85`，6 引擎，7.102 s，COMPLETED。
- Linux Standard：`71bab0ec-42ba-48c8-bb8b-c1b4f3461ff0`，14 引擎，29.337 s，
  17 unique/raw，COMPLETED。
- [Deep Release Run 31584209956](https://github.com/uprxiao/java-code-audit-platform/actions/runs/31584209956)：
  Linux Deep + CodeQL 发布验收；必须显式传入 `accept_codeql_terms=true`，CodeQL CLI 不进入公开介质。
- Linux Deep：`4c82e2df-bab2-4b48-888b-2570f32e94ad`，15 引擎，76.263 s，
  18 unique/raw，真实 Source→Propagation→Sink，COMPLETED。Artifact 名为
  `linux-deep-evidence-31584209956`。

## 3. 自动化契约证据

| 验收组 | 主要证据 |
| --- | --- |
| A 运行/介质 | `build-distribution.sh`、`run.sh`、`StartupPrerequisiteCheckerTest`、`CodeqlToolIntegrityCheckerTest`、两平台介质 E2E |
| B 输入/构建 | `SafeZipExtractorTest`、`MavenProjectInspectorTest`、`MavenArgumentValidatorTest`、`MavenProcessAdapterTest`、`SvnApiCredentialE2ETest`、`SvnKitRealSmokeTest` |
| C 扫描能力 | 15 个版本化 Fixture 目录、全部 Adapter 契约测试、Mac/Linux 真实 smoke 和三档 Web E2E |
| D Finding/报告 | `FindingProcessingTest`、`FindingValidationTest`、`RedactionAndSnippetTest`、`ReportGeneratorTest`、`ReportSecurityAndDeduplicationTest` |
| E 并发/稳定 | `FairDagSchedulerTest`、`EnginePermitManagerTest`、`ScanExecutionPlanFactoryTest`、`LocalProcessExecutionBackendTest`、`HighCapacityConfigurationTest` |
| F 恢复/清理 | `FileJobStoreTest`、`ScanRecoveryInitializerTest`、`JobRetentionServiceTest`、`RetentionMaintenanceServiceTest`、`JobTemporaryFileCleanerTest` |
| G 安全 | ZIP 攻击 Fixture、Maven 注入、进程无 shell 契约、HTML/ZIP 路径、exact/canary 全归档扫描 |
| H 跨平台 | Mac 最终三档 + CI Run 31582732490 + Deep Release Run 31584209956 |
| I 工程质量 | JDK17 `clean verify`、60 个测试类、15 个版本化 Golden Fixture 集、manifest/许可清单和可重复组装脚本 |

`ReportGeneratorTest#allTwelveIssueCategoriesHaveStableReportBuckets` 为十二类分别生成 Finding，
并断言每类报告 bucket 和总数不变式。

## 4. 性能与资源基线

数字是固定验收 Fixture 的热缓存基线，不是对任意业务仓库的 SLA。

- Mac：Quick 9.427 s，Standard 96.778 s，Deep 40.649 s；
- Linux：Quick 7.102 s，Standard 29.337 s，Deep 76.263 s；
- Mac 介质 320 MB，Trivy 双库约 2.6 GB；
- 并发稳定性用 20 任务 Fake DAG 做确定性断言，不用脆弱的真工具时序证明资源不超卖；
- `config/application-high-capacity.yaml` 面向 112 CPU/1 TiB，`HighCapacityConfigurationTest` 验证绑定和约束。

## 5. 已知边界

- V1 无认证、无前端、无历史基线和 AI；
- Maven 和扫描器直接在宿主机执行，只能分析信任且有权审计的代码；
- Apple Silicon CodeQL 仍需遵守 GitHub 当前官方支持与条款边界；
- OSV V1 只读直接 Maven manifest（`--no-resolve`），传递依赖由 CycloneDX + Trivy Artifact 补足；
- SpotBugs/FindSecBugs 依赖 Maven 构建和受控 classpath；构建失败时明确跳过，不冒充零问题。
