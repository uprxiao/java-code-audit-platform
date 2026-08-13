# 规则治理优化实施与真实复验报告（2026-08-13）

## 1. 结论

本轮优化只修改扫描器的去重、上下文治理、报告和 API，**没有修改 48 条 P1/P2
发现所对应的业务实现**。最终结果为：

- 原始检测事实、severity、CVSS、引擎规则和 raw evidence 全部保留；
- 48 条已人工复核证据去重为 47 个逻辑问题，没有遗失任何引擎证据；
- 47 个问题中：`ACTIONABLE=0`、`CONDITIONAL=15`、`ADVISORY=32`；
- `CONDITIONAL=15` 由 8 个已确认边界缺陷和 7 个尚未找到项目触发条件的依赖漏洞组成；
- `ADVISORY=32` 由 25 个已复核 SpotBugs 误报和 7 个有项目证据的不适用依赖漏洞组成；
- 最终 Deep 报告另有 547 个未匹配项目白名单的 P3 规范/改进项，均保留为
  `ADVISORY + UNKNOWN`。这证明治理层没有把未知新问题误隐藏。

“0 个立即行动”不等于“没有问题”。它仅表示在本次上传源码、当前部署边界和已复核
证据下，这 48 条中没有一条已同时证明“缺陷/版本命中 + 当前项目触发条件”。

## 2. 为什么不直接调低 SpotBugs 级别

原规则运行只能回答“检测器看到了什么”。同一条 P1/P2 还有两个不同问题：

1. 如果问题成立，影响有多大？由 `severity` 回答。
2. 结合当前项目证据，现在怎么处理？由 `governance` 回答。

因此实现不会把 SpotBugs P2 改成 P3，也不会把依赖引擎的 CVSS 改小。报告在原发现上叠加：

```text
Raw Finding
  -> 平台归一化
    -> 跨引擎保守去重
      -> 项目上下文治理
        -> HTML / JSON / SARIF / API
```

## 3. 新的统计和适用性模型

### 3.1 处置结论

| 值 | 业务含义 | 默认行为 |
| --- | --- | --- |
| `ACTIONABLE` | 当前证据已支持修复/阻断 | P0-P2 未复核发现保守进入 |
| `CONDITIONAL` | 缺陷或受影响版本事实存在，调用/部署/触发条件待确认 | 不自动阻断，不丢弃 |
| `ADVISORY` | 低风险改进项，或已有可审计证据证明误报/不适用 | 仍在报告显示 |

### 3.2 适用性事实

`UNKNOWN`、`AFFECTED_VERSION`、`TRIGGER_PRESENT`、`TRIGGER_NOT_FOUND`、`NOT_AFFECTED`、
`CONFIRMED_DEFECT`、`FALSE_POSITIVE` 与上述处置结论同时记录。

报告首页现在分别展示 `actionableFindingCount`、`conditionalFindingCount` 和
`advisoryFindingCount`，三者之和必须严格等于 `uniqueFindingCount`。severity 的 P0-P3 总和也必须
独立等于唯一 Finding 数。

## 4. 规则是如何扩展的

项目治理文件为 `config/rules/finding-governance.json`。它不是模糊文本白名单：

- 源码类复核使用稳定 SHA-256 fingerprint 精确匹配；
- 依赖漏洞使用归一化 Maven PURL + CVE/GHSA/OSV + 触发证据组匹配；
- 每条策略必须有 rationale、evidence、upstream severity 和 expiry；
- 过期策略不再生效，并产生 `GOVERNANCE_EXPIRED` warning；
- 新 fingerprint 默认 fail open 为未复核发现，不会被相似旧问题误隐藏；
- Maven 根项目 `artifactId` 不匹配时，项目专用策略完全不应用；子模块同名不会误触发。
- SpotBugs 优先使用其原生 `instanceHash + instanceOccurrenceNum` 形成稳定检测器实例键；
  同一缺陷附近的注释、日志或无关语句变化不会再让人工复核结论失效。旧版 XML 没有这两个
  字段时仍兼容原有语义回退，不会把合法旧报告误判为空。

当用户上传其他项目时，这组自审策略不会泛化到其他代码库。

## 5. 48 条复验结果

| 来源 | 原始证据 | 逻辑 Finding | 治理结论 | 处理 |
| --- | ---: | ---: | --- | --- |
| SpotBugs 路径不变式误报 | 25 | 25 | `FALSE_POSITIVE` | `ADVISORY` |
| SpotBugs 合法边界缺陷 | 8 | 8 | `CONFIRMED_DEFECT` | `CONDITIONAL` |
| 依赖漏洞，未找到触发配置 | 7 | 7 | `TRIGGER_NOT_FOUND` | `CONDITIONAL` |
| 依赖漏洞，项目证据不适用 | 8 | 7 | `NOT_AFFECTED` | `ADVISORY` |
| **合计** | **48** | **47** |  | **0 / 15 / 32** |

8 条不适用依赖证据中，`CVE-2026-54515` 被 Dependency-Check 和 Trivy 同时发现。
一个引擎给出普通 Maven PURL，另一个带 `?type=jar`，依赖路径表达也不同。平台现在只在
“同模块 + 同归一化组件 + 同漏洞”时合并，但保留两条 engine evidence 和依赖路径。
不同模块或 `classifier=tests` 等有语义 qualifier 仍不合并。

## 6. 最终真实介质和 Web API 复验

### 6.1 验证对象

| 项目 | 值 |
| --- | --- |
| 发布包 | `dist/rule-governance/java-code-audit-platform-rule-governance-v17-darwin-arm64.zip` |
| SHA-256 | `cb5bfedf7efd6bae07b119c78955eb22e57f6d7e37175d71d79839db83b23934` |
| Java class major | 61（JDK 17） |
| 介质受保护文件 | 6,143 |
| 源码 ZIP | `dist/rule-governance/fixtures/java-code-audit-platform-source-v15.zip` |
| 源码 ZIP SHA-256 | `0f0d325020e1c554bfd6be23b10ebcea68665dd80ce815efe4abba0e9ea366af` |
| NVD | `production-full`，`productionUseProhibited=false` |
| Trivy | 通用 DB + Java DB，启动门禁均 `AVAILABLE` |
| CodeQL | CLI 2.26.2 + Java query pack 1.11.7，本机受控安装 |
| 最终 Deep HTML | `dist/rule-governance/service-data-v17/jobs/33acd747-8c5e-466b-86fc-4b9f6e23fb14/report/report.html` |
| HTML / JSON / SARIF SHA-256 | `a4e740d7… / 1fc5687f… / 5939d803…` |
| 报告归档 SHA-256 | `a594e6aaf4a765865468d6c7697efa288cb5a5c2e75a9821a08103f5e473583f` |

### 6.2 三档实测

| Profile | Scan ID | 引擎 | 终态 | 耗时 | unique/raw | actionable/conditional/advisory |
| --- | --- | ---: | --- | ---: | --- | --- |
| QUICK | `d09de138-208b-4749-880e-e77d60cb6367` | 6/6 | COMPLETED | 19.905 s | 516/529 | 0/0/516 |
| STANDARD | `bde59557-c29d-49a5-87d1-f8114a6fca04` | 14/14 | COMPLETED | 164.525 s | 594/664 | 0/15/579 |
| DEEP | `33acd747-8c5e-466b-86fc-4b9f6e23fb14` | 15/15 | COMPLETED | 139.840 s | 594/664 | 0/15/579 |

Deep 报告中 594 个 Finding 的完整构成为：

- 本轮定向复核：47 个 Finding / 48 条引擎证据；
- 未匹配任何项目复核策略的 P3 发现：547；
- 因此 `ADVISORY=25 + 7 + 547 = 579`，`CONDITIONAL=8 + 7 = 15`。

本轮完整报告严重度为 `P0=0 / P1=6 / P2=41 / P3=547`。严重度仍表达上游检测
影响，处置结论独立表达当前项目是否需要立即行动，二者没有互相篡改。

### 6.3 黑盒 API 断言

`scripts/production-readiness-api.py` 从服务外部完成了：

- 空上传、非法 profile/Maven 参数、ZIP 路径穿越、无 Maven 根、多 Maven 根、Java 21 拒绝；
- 上传、轮询、引擎列表/详情、Finding 列表/详情、终态取消幂等；
- severity/category/engine/module/text/suppressed/disposition/applicability 筛选和非法筛选拒绝；
- HTML、JSON、SARIF、ZIP 下载，媒体类型、文件名、Schema、计数不变式；
- ZIP 内不含 source/workspace/target/codeql-db/.m2/home/cache 和 canary 明文；
- disposition/applicability 两组计数各自等于 unique Finding，三个首页处置数与治理明细完全相等。

主流程共执行 464 次 HTTP 调用（包括轮询），证据目录为：

- `dist/rule-governance/evidence/final-v17-current-source-all-profiles/`

### 6.4 并发与重复扫描稳定性

在同一服务实例上同时提交两次完整 Deep，CodeQL 的工具许可保持为 1，其他任务阶段并行，
高资源阶段按预期排队：

| Scan ID | 引擎 | 耗时 | unique/raw | actionable/conditional/advisory |
| --- | ---: | ---: | --- | --- |
| `7817d324-14ea-48f3-a2b2-895c2cac815e` | 15/15 | 154.788 s | 594/664 | 0/15/579 |
| `f8964b30-eb44-4209-baa7-37bb8abeb03e` | 15/15 | 262.351 s | 594/664 | 0/15/579 |

Standard、单次 Deep 和两次并发 Deep 的 594 组 `fingerprint + disposition + applicability`
逐项完全相同。三次 Deep 结束后均不存在 `codeql-db/database`，证明报告稳定且临时库正确清理。
并发证据分别位于 `final-v17-current-source-deep-repeat-a/` 和
`final-v17-current-source-deep-repeat-b/`。

## 7. CodeQL 真实测试中发现的稳定性问题

第一轮 Deep 复验曾在 macOS 上遇到一次 CodeQL `database finalize` 清理 `trap` 目录的
`Error while recursively deleting` / exit 2。完全相同的第二次任务 15/15 成功，证明是瞬时文件
删除竞态，不是查询、建库或源码错误。

扫描器现在只在同时满足以下条件时重试一次：

- finalize 返回 `FAILED` 且 exit code = 2；
- stderr 同时包含 recursive deletion、failed to delete 和 trap 签名；
- 数据库仍存在，任务未取消。

其他 finalize 错误、超时、取消、SARIF 校验错误均不重试且仍明确失败。单元测试分别
锁定了“已知瞬时签名重试一次”和“其他错误零重试”。

后续三档联合复验又捕获一次不同的清理竞态：CodeQL 已成功生成并校验 SARIF，
但平台遍历删除临时数据库时，一个 cache 文件同时消失，`NoSuchFileException` 被误当作
引擎失败。现在仅容忍经路径安全校验的 `codeql-db/database` 内“目标已不存在”，并有界
重启遍历；权限错误、路径越界或最终目录残留仍会使扫描失败。

真实复验还发现一类与工具执行无关、但会损害规则治理准确性的指纹漂移：平台原先在单条
SpotBugs Finding 上重新计算去重组指纹，而 SpotBugs 没有平台语义锚点时会退化为附近 11 行
snippet。即使上游 `instanceHash` 没变，附近代码变化也可能让已复核误报重新变成 ACTIONABLE。

最终实现把 `instanceHash + instanceOccurrenceNum` 作为首选组身份。不能只用 `instanceHash`，
因为 SpotBugs 会在同一方法内给多个 occurrence 复用它，且这些 occurrence 可能有不同的人工结论。
回归测试锁定了“snippet 改变但检测器实例不变时组指纹必须不变”，最终三档和并发复验均为
`ACTIONABLE=0`，不再出现漂移。

## 8. 自动化测试

最终 JDK 17 全仓 `clean verify` 结果：

| tests | failures | errors | skipped |
| ---: | ---: | ---: | ---: |
| 215 | 0 | 0 | 18 |

新增的 48 条真值基准覆盖：

- 25/8/7/7 四类数量不变式；
- 48 条原始证据去重后仍全部可追溯；
- 触发证据出现时，依赖问题从 `TRIGGER_NOT_FOUND` 提升为 `TRIGGER_PRESENT + ACTIONABLE`；
- 未知 SpotBugs fingerprint 不会被已有误报集隐藏；
- 复核策略到期后自动回到未复核状态并告警；
- 缺少处置结论、适用性、证据或有效期的治理配置会在服务启动时被拒绝；
- 同名子模块不能触发为 Maven 根项目编写的专用治理策略；
- PURL `?type=jar` 能合并，有意义 qualifier 和不同模块不误合并；
- 相同 SpotBugs 检测器实例在 snippet 变化后仍得到同一治理指纹，不同 occurrence 不误合并；
- JSON/HTML/SARIF 都保留治理结论，SARIF 的误报/不适用有说明性 suppression；
- 旧报告缺少新治理 Map 时仍可恢复查询。

## 9. 仍然存在的边界

1. **静态证据不是运行时可利用性证明**。`TRIGGER_NOT_FOUND` 不能排除上传包之外的运维配置，
   因此只标记 `CONDITIONAL`，不标记 `NOT_AFFECTED`。
2. **fingerprint 稳定不等于结论永久有效**。SpotBugs 实例键已避免无关代码导致的漂移；
   但源码语义或检测器实例真正变化仍会生成新身份，即使身份不变，策略也必须按到期时间复核。
3. **当前是文件化治理，不是多人审批系统**。规则应走 Git review，不应允许无理由、无到期时间的在线点击忽略。
4. **P3 数量仍多**。本轮重点是保证 48 条 P1/P2 的可行动性准确，没有继续收紧 547 条
   Checkstyle/PMD/CPD/构建治理建议。后续应用项目基线、变更量扫描和规则分组降低阅读噪音，
   而不是删除原始结果。

## 10. 后续优化顺序

1. 先把 547 条 P3 按“必须规范 / 建议规范 / 历史基线”分组；
2. 增加“只看新增 Finding”和指纹 baseline，同时保留全量报告；
3. 为用户项目建立独立 policy ID/责任人/到期时间，不复用本项目的 fingerprint；
4. 积累每条规则的 TP/FP/条件性样本，以真实数据调整默认规则组；
5. AI 只用于归纳和提示复核证据，不直接自动隐藏 Finding。
