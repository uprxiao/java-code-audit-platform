# 扫描器适配协议

## 1. 目的

每个第三方工具的命令、退出码和报告格式都不同。适配层把这些差异限制在单个模块中，使编排器只理解“适用性、执行描述、原始产物、统一 Finding和覆盖状态”。

## 2. 领域对象

```java
public interface ScannerAdapter {
    EngineDescriptor descriptor();
    Applicability probe(ProjectContext project, ToolContext toolContext);
    ExecutionSpec prepare(ProjectContext project, ScanContext scanContext);
    RawArtifactValidation validate(ExecutionResult result);
    NormalizationResult normalize(RawArtifactSet artifacts, NormalizationContext context);
}
```

### `EngineDescriptor`

- engine ID、显示名、能力包、默认问题分类；
- 工具 ID、Parser Schema、支持的 Profile；
- DAG 前置、资源等级、默认超时和工具信号量；
- 输出格式与是否可能返回部分结果。

### `Applicability`

```text
APPLICABLE
NOT_APPLICABLE
BLOCKED_MISSING_TOOL
BLOCKED_PROJECT_INCOMPATIBLE
BLOCKED_POLICY
```

必须包含机器可读 reason code 和中文说明。`NOT_APPLICABLE` 是合法跳过；缺失工具或策略禁止不能伪装成“不适用”。

### `ExecutionSpec`

```java
record ExecutionSpec(
    List<String> command,
    Path workingDirectory,
    Map<String, String> environment,
    Duration timeout,
    ResourceRequest resources,
    Set<ExpectedArtifact> expectedArtifacts,
    RedactionPolicy redactionPolicy
) {}
```

约束：

- `command` 第一个元素是已校验的绝对工具路径或允许的系统命令；
- 不生成 `sh -c`、`bash -c` 或拼接后的命令字符串；
- 工作目录必须位于当前任务工作区；
- 环境变量使用允许清单，不继承不必要的 Token、代理凭据或用户密钥；
- 输出路径只能位于当前引擎目录；
- 参数中的 Maven Profile/属性经过字符和名称校验；
- 日志展示命令前执行敏感值替换。

## 3. 退出码和产物

不能假设非零退出码都表示工具故障。有些工具用特定退出码表示“发现问题”。每个适配器声明：

```yaml
exitCodes:
  success: [0]
  findingsPresent: [1]
  retryableFailure: []
  fatalFailure: [2, 3]
```

最终状态同时由三项决定：

1. 退出码语义；
2. 预期报告是否存在、可读且通过基本 Schema；
3. 报告是否声明扫描被截断或只完成部分模块。

例：退出码0但 JSON 损坏仍是 `FAILED_INVALID_OUTPUT`；退出码1且适配器定义为“发现问题”可以是 `SUCCEEDED`。

## 4. 原始产物

每个引擎目录：

```text
raw/{engine-id}/
├── engine-result.json
├── report.{json|xml|sarif}
├── stdout.log
├── stderr.log
└── extra/
```

`engine-result.json` 至少包含：

- 实际工具和规则版本；
- 开始/结束时间、耗时、退出码；
- 状态和 reason code；
- 模块发现/扫描数；
- 产物文件、大小和 SHA256；
- 日志是否截断；
- 数据库版本和时间（适用时）；
- 参数摘要（脱敏）；
- Parser Schema 版本。

原始报告在归档前也经过密钥字段脱敏，但不能改变用于归一化的规则 ID、位置、路径和漏洞标识。

## 5. 归一化

Parser 只能读取适配器声明的产物，不能访问任意宿主路径。它输出：

```java
record NormalizationResult(
    List<FindingCandidate> findings,
    CoverageEvidence coverage,
    List<NormalizationWarning> warnings
) {}
```

规则：

- 保留原始规则 ID、消息和证据引用；
- 文件路径转成项目根相对路径；
- 拒绝归一化后逃出项目根的路径；
- 原始严重性与平台严重性分别保存；
- 依赖问题使用 PURL、坐标、CVE/GHSA/OSV；
- 污点问题保存 Source、Sink 和路径节点；
- 密钥值在进入 Finding 前完成脱敏；
- Parser 不负责跨引擎去重；
- 无法解析的条目计入 warning，不静默丢弃；
- 解析失败不能把原始命中报告成0。

## 6. 适配器实现顺序

1. Fake Scanner：建立执行/Parser契约；
2. Semgrep：第一个纵向切片；
3. Gitleaks、Checkstyle、PMD/CPD；
4. Trivy Repository；
5. Maven build；
6. SpotBugs + FindSecBugs；
7. Dependency-Check、OSV；
8. Maven Dependency、Enforcer、CycloneDX、Trivy Artifact；
9. CodeQL。

选择 Semgrep 作为第一切片，是因为它不依赖 Maven 构建、能产生带文件/行号的结构化结果，又足以验证工具发现、进程执行、Parser、Finding 和报告完整链路。

## 7. 共享进程与逻辑引擎

SpotBugs 加载 FindSecBugs 插件时可以一次进程输出两类规则。实现允许一个 `ExecutionGroup` 产出两个逻辑引擎的覆盖和 Finding：

- 进程失败：两个逻辑引擎都记录共享失败证据；
- 产物成功：按规则 namespace/category 分派；
- 报告既显示共享进程耗时，也显示两个逻辑引擎命中；
- 原始命中只按原始条目计一次，不因逻辑展示重复。

类似地，CycloneDX SBOM 可以作为 OSV/Trivy 的输入，但每个消费者仍记录自己的结果状态。

## 8. Parser 契约测试

每个适配器必须保存脱敏后的 Golden Fixture：

```text
src/test/resources/fixtures/{engine}/{tool-version}/
├── clean.*
├── findings.*
├── partial.*
├── malformed.*
└── expected-findings.json
```

升级工具版本时，必须：

- 重新生成 Fixture；
- 审查 Schema 变化；
- 证明旧 Parser 是否兼容，或提升 Parser Schema；
- 检查 Finding 数、位置、严重性和证据引用；
- 在 Mac/Linux 分别运行至少一个真实冒烟样例。

## 9. 新增引擎 Definition of Done

- 许可证和分发策略记录；
- 工具版本、SHA256和健康检查完成；
- Profile/DAG/资源权重配置完成；
- 成功、发现问题、无问题、失败、超时、取消、无效输出测试完成；
- Golden Fixture 和真实冒烟测试完成；
- Finding 映射、分类、严重性、指纹输入和去重样例完成；
- 原始报告、日志、覆盖信息进入下载包；
- 中文规则模板至少覆盖验收样例中的核心规则；
- 对能力边界和未覆盖情况有文档。
