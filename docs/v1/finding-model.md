# 统一 Finding 模型

## 1. 目标

Finding 是报告统计的最小风险单元。它既要统一不同扫描器，又不能丢失原始工具证据。V1 同时保留三层数据：

```text
Raw Finding（扫描器原始条目）
  → Finding Candidate（平台归一化）
    → Finding Group（跨引擎去重后的展示问题）
      → Governance Assessment（不改原始严重性的适用性/可行动性结论）
```

首页“问题总数”统计 Finding Group；“原始命中数”统计有效 Raw Finding。

## 2. Finding 字段

```json
{
  "id": "F-01J...",
  "fingerprint": "sha256:...",
  "category": "WEB_SECURITY",
  "severity": "P1",
  "confidence": "HIGH",
  "ruleFamily": "SQL_INJECTION",
  "titleZh": "用户输入参与构造 SQL",
  "titleOriginal": "SQL query built from user-controlled sources",
  "descriptionZh": "...",
  "messageOriginal": "...",
  "impactZh": "...",
  "remediationZh": "...",
  "module": "web",
  "location": {
    "file": "web/src/main/java/example/UserController.java",
    "startLine": 42,
    "startColumn": 13,
    "endLine": 42,
    "endColumn": 55
  },
  "snippet": {
    "startLine": 37,
    "endLine": 47,
    "highlightLines": [42],
    "text": "...",
    "redacted": false
  },
  "identifiers": {
    "cwe": ["CWE-89"],
    "cve": [],
    "ghsa": [],
    "osv": []
  },
  "component": null,
  "dataFlow": [],
  "evidence": [],
  "suppression": null,
  "reviewState": "UNREVIEWED",
  "governance": {
    "disposition": "ACTIONABLE",
    "applicability": "TRIGGER_PRESENT",
    "policyId": "project-sqli-reviewed-2026-08",
    "rationale": "污点路径和真实 SQL sink 都存在",
    "evidence": ["src/main/java/example/UserController.java matches reviewed sink"],
    "upstreamSeverity": "HIGH",
    "expiresAt": "2026-11-13T00:00:00Z"
  }
}
```

### 必需字段

- ID、稳定指纹；
- 主分类、平台严重性、置信度；
- 规则族、中文或原始标题；
- 至少一个证据来源；
- 文件问题必须有项目相对路径；
- 依赖问题必须有组件坐标/PURL和漏洞标识；
- 密钥问题必须声明已脱敏；
- 所有问题必须能链接到原始报告条目。

## 3. 严重性

| 平台级别 | 含义 | 典型示例 |
| --- | --- | --- |
| P0 / CRITICAL | 高可信且可能造成重大直接影响，需要立即处理 | 可利用的远程命令执行、确认泄漏的高权限密钥 |
| P1 / HIGH | 高风险或高优先级缺陷 | SQL注入、严重依赖漏洞、明确空指针主流程崩溃 |
| P2 / MEDIUM | 有现实影响但条件较多或严重性中等 | 中危漏洞、资源泄漏、明显并发误用 |
| P3 / LOW | 低风险、规范、维护和改进项 | 风格、轻度坏味道、低影响重复代码 |

映射策略：

1. 保留 `engineSeverity`、rank、CVSS和工具原始属性；
2. 根据引擎规则映射表得到基础平台级别；
3. 允许 CVSS、利用状态、密钥类型、置信度等受控字段调整；
4. 不因多个引擎命中自动提高严重性；
5. 报告记录 `severityMappingId` 和映射理由；
6. 未知规则保守映射并产生映射警告，不丢弃。

### 严重性不等于处置优先级

`severity` 回答“如果问题成立，影响有多大”；`governance.disposition` 回答“基于当前项目证据，
现在怎么处理”。两者必须同时保留：

| disposition | 含义 |
| --- | --- |
| `ACTIONABLE` | 触发条件已证实，或高优先级发现尚未完成上下文复核 |
| `CONDITIONAL` | 版本/边界缺陷成立，但部署配置、输入或调用路径仍需确认 |
| `ADVISORY` | 规范/低风险改进项，或已有可审计证据证明不适用/误报 |

`applicability` 记录 `AFFECTED_VERSION`、`TRIGGER_PRESENT`、`TRIGGER_NOT_FOUND`、
`NOT_AFFECTED`、`CONFIRMED_DEFECT`、`FALSE_POSITIVE` 或 `UNKNOWN`。治理层不得改写引擎原始
severity/CVSS/规则，不得删除 evidence。

## 4. 置信度

`HIGH`、`MEDIUM`、`LOW` 表示扫描证据可靠程度，不表示影响大小。例如高置信的格式问题仍然可以是 P3；低置信的潜在 SQL 注入可能是 P1 但需要人工复核。

## 5. 代码片段

- 普通文件问题：问题行前后各5行；
- 最多默认50行，用于多行数据流或重复片段；
- 不保存完整源文件；
- 文件无法按文本读取时只保存位置和哈希；
- 统一处理 UTF-8，其他编码识别失败时记录 warning；
- HTML/JSON/SARIF 使用同一脱敏结果；
- 源码工作区删除后，报告片段仍可用于复核。

密钥类：

- 不保存完整 secret；
- 默认最多保留首尾各2个字符，其余替换为 `*`；
- 私钥正文整体替换为类型和指纹摘要；
- 原始报告、stdout/stderr进入归档前也执行同一 Redaction Policy；
- 脱敏失败时不生成公开报告包，任务进入报告生成错误。

## 6. 数据流

```json
{
  "source": {"file": "...", "line": 20, "label": "HTTP parameter"},
  "sink": {"file": "...", "line": 68, "label": "Statement.execute"},
  "nodes": [
    {"index": 0, "kind": "SOURCE", "location": {}},
    {"index": 1, "kind": "PROPAGATION", "location": {}},
    {"index": 2, "kind": "SINK", "location": {}}
  ],
  "engine": "codeql"
}
```

FindSecBugs 或 Semgrep 没有完整路径时可以只提供 source/sink 或调用位置，但不得伪造缺失节点。

## 7. 依赖组件

```json
{
  "purl": "pkg:maven/org.example/example@1.0.0",
  "groupId": "org.example",
  "artifactId": "example",
  "version": "1.0.0",
  "scope": "compile",
  "direct": false,
  "dependencyPath": ["app", "parent:2.0", "example:1.0.0"],
  "fixedVersions": ["1.0.3"]
}
```

同一 CVE 在同一 PURL/version 上由多个数据源发现时合并证据。不同版本、不同模块或不同实际依赖路径是否合并，由组件身份和修复影响决定。

## 8. 指纹

指纹先计算问题类型专属的 canonical key，再取 SHA-256。

### 源码问题候选键

```text
ruleFamily | normalizedPath | semanticAnchor | sinkSymbol | normalizedMessageKey
```

### 依赖问题候选键

```text
vulnerabilityId | purl-with-version | affectedModule
```

### 重复代码候选键

```text
normalized-token-hash | sorted-occurrence-paths
```

行号不能作为唯一锚点，否则在文件前插入一行会造成全部问题变新。V1 可结合规则族、符号、代码片段 token hash 和近似位置。算法一旦进入发布，变更时必须提升 `fingerprintVersion`。

## 9. 跨引擎去重

合并条件：

- 问题分类/规则族语义相容；
- 项目相对文件或组件一致；
- 位置、Sink、符号或组件标识足够一致；
- CWE/CVE 等标识不冲突；
- 数据流差异不会代表两个独立攻击路径。

合并后：

- 只产生一个 Finding Group；
- 严重性使用有证据的最高平台级别，但保留各引擎级别；
- 置信度可依据多源证据提升，必须有明确规则；
- 所有 evidence 都保留；
- 原始报告不删除；
- UI/HTML 显示“3个引擎共同发现”。

保守原则：证据不足就不合并。错误地少报两个真实路径比展示一个重复组风险更大。

Maven 依赖特例：同一模块内的“归一化 PURL + 同一漏洞 ID”是同一修复单元。
`?type=jar` 这类 Maven 默认 qualifier 不制造新问题；Dependency-Check 与 Trivy 给出的
依赖路径表达不同时可合并，但两条路径仍分别保留在 evidence 中。不同模块或
`classifier=tests` 等有语义 qualifier 仍保持独立。

## 10. 抑制

抑制匹配支持：

- engine；
- rule ID / rule family；
- project-relative path glob；
- fingerprint；
- dependency PURL / vulnerability ID；
- 必填 reason；
- 可选 expiry。

被抑制问题：

- 不计入默认有效问题总数；
- 计入 `suppressedCount`；
- 报告可展开查看原因、规则和证据；
- 原始命中和原始报告仍保留；
- 过期 suppression 不生效并产生警告。

路径预排除的文件可能不会进入扫描器，因此只进入 coverage，不产生被抑制 Finding。两者统计不能混为一谈。

## 11. 复核与项目治理

V1 保留 `UNREVIEWED`、`CONFIRMED`、`FALSE_POSITIVE`、`ACCEPTED_RISK`。当前不建设多人审批 UI，
但支持版本化的 `config/rules/finding-governance.json`：

- 已复核源码问题用稳定 fingerprint 精确匹配；
- 依赖漏洞用 Maven PURL + CVE/GHSA/OSV + 项目触发证据匹配；
- 必须填写 rationale、evidence 和 expiry；
- 过期结论自动失效并生成 `GOVERNANCE_EXPIRED` warning；
- 未知指纹 fail open 为未复核问题，不会被相似白名单隐藏。
