# 统一报告规范

## 1. 报告回答的五个问题

1. 一共发现多少个不重复的问题？
2. 各严重性、问题分类、模块和扫描器分别有多少？
3. 每个问题在哪段代码/依赖上，证据和修复建议是什么？
4. 这次哪些引擎、模块和数据真正扫描成功，哪些失败或跳过？
5. 使用了哪些源码 revision、JDK、Maven、工具、规则和漏洞数据库？

如果报告只回答问题数量而不回答覆盖状态，则不能作为可信审计结果。

## 2. 首页统计

```json
{
  "uniqueFindingCount": 86,
  "rawHitCount": 117,
  "suppressedCount": 9,
  "severity": {"P0": 1, "P1": 12, "P2": 31, "P3": 42},
  "categories": {"WEB_SECURITY": 8, "CORRECTNESS": 23},
  "engines": {"succeeded": 12, "partial": 1, "failed": 1, "skipped": 1},
  "modules": {"discovered": 8, "scanned": 7},
  "sbom": {"components": 428, "vulnerableComponents": 17},
  "durationMs": 481000
}
```

口径：

- “问题总数”默认等于 `uniqueFindingCount`；
- `rawHitCount` 是所有成功解析的原始条目之和；
- 被抑制问题不计入 `uniqueFindingCount`，单列展示；
- SBOM 组件数不是问题；
- 引擎失败/未运行不是零问题；
- 分类和严重性之和应等于唯一有效问题数；
- 一个问题只有一个主分类，其他标签不参与分类总和。

## 3. HTML 结构

1. 扫描摘要与醒目的完成状态；
2. 覆盖/失败告警；
3. 严重性、12类问题、模块和引擎统计；
4. 重点 P0/P1 问题；
5. 可筛选 Finding 列表；
6. Finding 详情：中文说明、英文原文、代码片段、数据流、组件、证据和修复；
7. SBOM 和依赖资产摘要；
8. 抑制和排除项；
9. 引擎执行表；
10. 构建、版本、规则、数据库和覆盖清单；
11. 报告边界和免责声明。

HTML 必须是自包含文件或只引用报告目录内的静态资源，不依赖外部 CDN。报告可在服务停止后本地打开。

## 4. JSON 顶层结构

```json
{
  "schemaVersion": "1.0",
  "scan": {},
  "summary": {},
  "coverage": {},
  "findings": [],
  "suppressedFindings": [],
  "sbomSummary": {},
  "engines": [],
  "build": {},
  "toolchain": {},
  "exclusions": [],
  "warnings": [],
  "artifacts": []
}
```

发布前必须提供 JSON Schema 并用它验证所有 E2E 报告。破坏性字段变化提升主版本；新增可选字段提升次版本。

## 5. SARIF

- 使用 SARIF 2.1.0；
- 每个逻辑引擎可作为一个 run，或在平台统一 run 中保留 `properties.engine`；最终方案在兼容性测试后冻结；
- rule ID、原始消息、文件位置、CWE和数据流尽量保留；
- 平台去重后的 Finding 作为主要 result，证据引擎进入 properties/relatedLocations；
- 不把 SBOM 组件写成 result；
- 扫描失败写入 invocation/toolExecutionNotifications，不制造“0 results”；
- 密钥信息使用与 JSON/HTML 相同的脱敏值。

## 6. Coverage

`coverage.json` 至少包含：

```json
{
  "project": {
    "modulesDiscovered": 8,
    "modulesBuilt": 7,
    "modulesScanned": 7,
    "excludedPaths": ["**/target/**"]
  },
  "engines": [
    {
      "engine": "spotbugs",
      "status": "PARTIAL",
      "applicableModules": 8,
      "scannedModules": 7,
      "reasonCode": "MODULE_BUILD_FAILED",
      "artifact": "raw/spotbugs/report.xml"
    }
  ]
}
```

引擎状态表必须在 HTML 首页可见，不能只藏在 JSON。

## 7. Manifest

`manifest.json` 用于复现和审计：

- scanId、创建/完成时间、Profile；
- ZIP SHA256或 SVN URL脱敏值 + revision；
- Java、Maven、OS、架构；
- Maven Profile和脱敏属性；
- 工具版本、SHA256、规则/查询包版本；
- 漏洞数据库版本和更新时间；
- 配置摘要和 `configFingerprint`；
- report schema/fingerprint/parser 版本；
- 每个文件大小和 SHA256。

## 8. 下载包

```text
scan-report-{scanId}.zip
├── report.html
├── report.json
├── report.sarif
├── manifest.json
├── coverage.json
├── sbom/
│   ├── bom.cdx.json
│   └── bom.cdx.xml
├── raw/
│   ├── semgrep/
│   ├── spotbugs/
│   └── ...
└── logs/
    ├── build.log
    └── engines/
```

下载包不包含完整源码、Maven仓库、target、CodeQL数据库或未脱敏凭据。

## 9. 中文和英文

- HTML：中文标题、说明、影响、修复建议为主；
- 原始规则 ID、CWE/CVE、类/方法、原始引擎消息保留；
- JSON：同时保留平台中文字段和 original 字段；
- SARIF：优先兼容工具生态，保留原始语义，并在 properties 中补充中文；
- 没有人工维护的中文模板时显示英文原文，不调用 AI 临时翻译。

## 10. 不可变性

最终化完成后，`report/` 视为不可变。抑制配置或映射规则变化不会悄悄修改旧报告；重新生成必须生成新的 report revision，并保留原 manifest。V1 默认只生成 revision 1。

## 11. 一致性校验

报告生成结束前验证：

- severity 合计 = category 合计 = 唯一有效问题数；
- raw hit >= unique + suppressed（允许解析/去重关系导致不严格相等，但需可解释）；
- 每个 Finding 至少一个 evidence；
- 每个 evidence 指向存在的原始产物；
- 每个引擎有终态和 reason；
- 所有归档文件路径不逃出报告根；
- 所有密钥 Fixture 不出现明文；
- JSON Schema和SARIF基础校验通过；
- manifest 中的 SHA256 与实际文件一致。
