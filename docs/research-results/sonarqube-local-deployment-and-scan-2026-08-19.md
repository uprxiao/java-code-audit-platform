# SonarQube 本机自托管与真实项目扫描报告

> 日期：2026-08-19
>
> 项目：`java-code-audit-platform`
>
> 结论：SonarQube Community Build 可以完全自托管；本机部署、鉴权、Maven 多模块分析、Compute Engine 处理、质量门和问题 API 均已真实跑通。

## 1. 为什么把 SonarQube 作为外部平台能力

SonarQube 与本项目现有的 15 个本地扫描引擎不是同一种交付形态：

- 现有扫描器以一个 Java 服务调用本地 CLI/Java 工具，任务完成后产出独立报告，不依赖数据库；
- SonarQube 是一个常驻平台，内部同时包含 Web Server、Search Server（Elasticsearch）和 Compute Engine，并依赖外部数据库保存项目历史、问题状态、质量门和规则配置；
- 因此不应该把 SonarQube 硬塞进单 JAR 的 `tools/` 目录。正确方式是把它作为可选的外部质量平台：本项目负责构建和提交分析，SonarQube 负责长期治理与趋势展示。

这不会替换 SpotBugs、FindSecBugs、CodeQL、Dependency-Check、Trivy 等引擎。SonarQube 本次日志明确显示 `Dependency analysis skipped`，所以不能用“SonarQube 漏洞数为 0”替代依赖漏洞、SBOM 和深度污点扫描。

官方资料：

- [Docker 镜像部署](https://docs.sonarsource.com/sonarqube-community-build/server-installation/from-docker-image/set-up-and-start-container)
- [服务端组件](https://docs.sonarsource.com/sonarqube-community-build/server-installation/server-components-overview)
- [数据库要求](https://docs.sonarsource.com/sonarqube-server/server-installation/installing-the-database)
- [SonarScanner for Maven](https://docs.sonarsource.com/sonarqube-community-build/analyzing-source-code/scanners/sonarscanner-for-maven)
- [Java 分析与字节码要求](https://docs.sonarsource.com/sonarqube-community-build/analyzing-source-code/languages/java)
- [SonarQube 源码许可证](https://github.com/SonarSource/sonarqube/blob/master/LICENSE.txt)
- [SonarSource 关于分析器 SSALv1 的说明](https://community.sonarsource.com/t/a-new-sonar-license-for-sonarqube-analyzers/130731)

许可上需要区分两层：SonarQube 服务端源码仓库使用 LGPLv3，但 Community Build
镜像内的 Sonar 分析器采用 Sonar Source Available License 1.0。SonarSource 明确说明，
普通用户用 Community Build 扫描自己的代码不受影响；但 SSALv1 对衍生、再分发、
对外提供同类产品/服务以及某些 AI 使用方式有额外限制。因此本项目只引用、部署官方
镜像，不把这些分析器复制进自己的单 JAR 或公开工具包。

## 2. 已部署的固定版本与拓扑

| 组件 | 固定版本 | 校验/说明 |
|---|---:|---|
| SonarQube Community Build | `26.8.0.126808` | 官方镜像 manifest digest `sha256:6287ef13f5265d3eb26e6d5953ee08764d4ca73b3dabcd4e7de79ab040a6dfea` |
| PostgreSQL | `16.6-alpine` | digest `sha256:1d04b9ba1d4996401f2552b51beda8187f175c0645c091e4781134fc9c9a3eef` |
| SonarScanner for Maven | `5.5.0.6356` | 使用完整 Maven 坐标固定，不依赖浮动 `latest` |
| 项目构建 JDK | JDK `17.0.18` | 与项目 `maven.compiler.release=17` 一致 |
| Scanner 分析 JRE | JRE `21.0.11` | 由 Maven Scanner 自动供应，未改变项目构建 JDK |

镜像通过 `mirror.gcr.io` 拉取，这是 Docker Hub 官方 library 镜像的公共缓存；Compose 同时固定原官方 manifest digest，缓存内容与 Docker Hub 原镜像一致。

运行边界如下：

- Web 仅监听 `127.0.0.1:19000`，不对局域网或公网开放；
- PostgreSQL 没有任何宿主机端口，只存在于隔离网络；
- SonarQube 上限为 4 CPU / 4 GiB，PostgreSQL 上限为 2 CPU / 1 GiB；实测空闲时约使用 1.7–2.1 GiB + 110 MiB；
- 已避开本机 MinIO 的 9000/9001 和既有 PostgreSQL 的 5432/5433；
- 数据、索引、日志和数据库使用独立 Docker named volumes，不接触现有容器的数据卷。

## 3. 凭据和数据安全

首次启动脚本执行了以下动作：

1. 生成 256 位随机 PostgreSQL 密码；
2. 等待 `/api/system/status` 返回 `UP`；
3. 立即替换 SonarQube 默认 `admin/admin` 密码；
4. 生成独立分析 Token，并通过 `/api/authentication/validate` 验证；
5. 将本地环境和凭据文件权限设为 `600`。

以下内容均已被 Git 忽略，不会提交到 GitHub：

- `deploy/sonarqube/.env`
- `deploy/sonarqube/.state/`
- `deploy/sonarqube/evidence/`
- 所有 Docker volumes
- Maven/Sonar 临时目录 `**/target/sonar/` 和 `.scannerwork/`

脚本和报告不会输出明文密码或 Token。不要手工把上述文件复制进日志、Issue 或提交记录。

## 4. 真实扫描方式

最终采用一个 Maven reactor 调用完成构建与分析：

```bash
./scripts/sonarqube-local-up.sh
./scripts/sonarqube-scan-current.sh
```

扫描脚本等价于以下受控流程：

1. 强制确认 `JAVA_HOME` 指向 JDK 17；
2. 执行全模块 `clean verify`；
3. 在同一 reactor 中执行固定版本 `sonar-maven-plugin:5.5.0.6356:sonar`；
4. 等待 `target/sonar/report-task.txt` 指向的 Compute Engine 任务进入 `SUCCESS`；
5. 再读取质量门、度量、全部问题、分析历史、质量配置和插件 API；
6. 把不含凭据的 JSON 证据写入 Git 忽略目录。

把 `verify` 和 `sonar` 保持在同一 reactor 很重要。首次分成两次调用时，Sonar Java Analyzer 报告跨模块类型无法完全解析，只发现 242 项；修正后警告消失并发现 275 项。这证明“命令返回成功”不等于分析输入完整。

## 5. 本次验收证据

| 验收项 | 真实结果 |
|---|---|
| SonarQube 系统状态 | `UP` |
| 系统健康 | `GREEN` |
| Compute Engine | `SUCCESS`，`warningCount=0` |
| 分析 revision | `51531caef324bc883fee13bb17c39c613695d2a9` |
| Maven reactor | 10/10 模块 `SUCCESS` |
| 索引文件 | 282 个，检测到 Java/XML/YAML 三种语言 |
| Java 质量配置 | 默认 `Sonar way`，571 条激活规则 |
| 代码规模 | 16,660 行非注释代码（NCLOC） |
| 重复率 | 2.8% |
| 覆盖率 | 0.0%（本项目当前没有生成 JaCoCo XML，见限制） |

无敏感信息的原始 API 证据保存在：

```text
deploy/sonarqube/evidence/latest/
```

其中包括 `compute-engine-task.json`、`quality-gate.json`、`measures.json`、`issues-first-500.json`、`analyses.json`、`quality-profiles.json`、`plugins-installed.json`、`system-health.json` 和聚合后的 `summary.json`。

## 6. 扫描结果怎么理解

最终完整扫描得到 275 项：

| 类型 | 数量 | 含义 |
|---|---:|---|
| Bug | 18 | Sonar 认为可能造成错误行为的代码模式，仍需结合业务和并发语义人工确认 |
| Vulnerability | 0 | 当前 Community Build 激活规则没有报漏洞；不代表依赖或深层数据流绝对安全 |
| Security Hotspot | 0 | 当前规则没有需要人工安全复核的热点 |
| Code Smell | 257 | 可维护性、复杂度、重复、测试写法等问题，不等同于线上故障 |

严重性分布为 Critical 109、Major 117、Minor 49。数量最多的规则是：

| 规则 | 数量 | 大意 |
|---|---:|---|
| `java:S1192` | 83 | 字符串字面量重复，应考虑常量化 |
| `java:S5778` | 25 | 测试断言 lambda 内存在多个可能抛异常的调用 |
| `java:S3776` | 19 | 方法认知复杂度过高 |
| `java:S4165` | 15 | 对变量赋值但实际值没有发生变化 |
| `java:S8786` | 14 | 可维护性/清晰度相关的新增 Java 规则 |
| `java:S1128` | 12 | 无用 import |
| `java:S3358` | 12 | 嵌套三元表达式降低可读性 |

18 个 Bug 的规则分布：`S2445` 8 项、`S3077` 6 项，`S5783`、`S899`、`S5998`、`S5850` 各 1 项。其中值得优先人工复核的是：

- `ScanService` 多处使用方法参数 `runtime` 作为同步锁：对象身份若能逃逸或被替换，会带来锁语义风险；
- 多个 `volatile` 字段被判定“volatile 本身不足以保证复合操作线程安全”：必须逐处确认是否只有原子读写；
- `FindingFingerprintService` 的重复处理被认为可能在大输入下导致栈溢出；
- `RuleFamilyCatalog` 的正则运算符优先级不明确，可能与维护者意图不一致；
- 一项位于测试代码的异常断言写法，更偏测试准确性而非生产 Bug。

这些是“需要审查的候选问题”，不是 18 个已经被证明会发生的线上故障。Sonar 的价值是把人工审查范围从 16,660 行缩小到具体规则、文件和行号；最终真阳性仍需结合调用路径、线程模型和输入边界确认。

## 7. 为什么质量门是 ERROR

最终质量门失败条件只有一个：

```text
new_violations > 0，实际值 33
```

原因是本机项目先产生了一次跨模块解析不完整的 242 项基线，随后正确的一体化 reactor 扫描补出了 33 项。质量门把这 33 项视为“新问题”，所以返回 ERROR。它不表示服务部署失败，也不表示 275 项全部都违反了质量门。

保留这个结果比删除项目重建一个“看起来为绿色”的基线更诚实。后续正式接入时应先确定新代码定义和质量门，再用一次完整、可重复的扫描建立基线。

## 8. 当前限制和下一步

1. **覆盖率为 0**：测试执行成功，但项目没有生成 JaCoCo XML。要让 SonarQube 正确展示覆盖率，应在 Maven 中增加 JaCoCo report/aggregate 配置；不能把“没有报告”解释成“测试没有价值”。
2. **没有 SCA 结果**：本次 Sonar 日志明确为 `Dependency analysis skipped`。依赖漏洞仍以 Dependency-Check、OSV、Trivy 和 CycloneDX 为准。
3. **没有证明 0 漏洞**：0 Vulnerability/0 Hotspot 只表示当前激活规则没有命中，CodeQL、FindSecBugs、Semgrep 的结果仍应保留。
4. **Community Build 是平台补充**：适合规则治理、质量门、历史趋势和统一 Web UI；不替代现有扫描器的离线报告、供应链数据和多引擎交叉验证。
5. **规则治理建议**：复制 `Sonar way` 创建自己的质量配置，先处理 Bug 和高置信安全问题，再根据真值 Benchmark 调整 Code Smell；不要为了让数字变小直接关闭整类规则。

## 9. 日常运维命令

打开控制台：<http://127.0.0.1:19000/dashboard?id=java-code-audit-platform>

```bash
# 幂等启动、健康检查和凭据验证
./scripts/sonarqube-local-up.sh

# 完整构建、扫描、等待服务端终态并导出证据
./scripts/sonarqube-scan-current.sh

# 停止服务但保留数据库、索引和历史
./scripts/sonarqube-local-down.sh

# 明确删除 SonarQube/PostgreSQL Docker volumes
# 这是不可恢复操作，只有确定不再需要历史时才能执行
./scripts/sonarqube-local-down.sh --volumes
```

如果显式删除了 volumes，还应删除本地 `.state/credentials.env`，然后重新运行启动脚本，让新实例修改默认密码并生成新 Token。
