# V1 规则治理优化与真实复验计划

## 1. 目标

在不减少 Java/Maven/Web 端 15 引擎覆盖的前提下，把默认输出从“尽可能多地罗列命中”
调整为“适合人工代码审计的可行动候选”。本轮不以问题数量下降作为成功标准，而以以下
验收条件为准：

1. 高价值安全、正确性、依赖漏洞能力仍真实运行；
2. 代码规范、重复、质量和安全候选不再被混淆；
3. 默认规则有明确选择依据，扩展规则有测试和审批边界；
4. 对平台自身执行同一 Deep Web API 扫描，15 个引擎必须全部成功且报告可下载；
5. 对优化前后的 raw、unique、严重度、类别和引擎结果进行可复现对比；
6. 对优化后剩余结果逐类抽样，给出合理、误报、需上下文确认或规则仍需调整的判断。

## 2. 基线

优化前基线报告为任务 `8d8c1be1-f645-46e1-a9ad-bd251d9ba699`：

| 指标 | 基线 |
| --- | ---: |
| 原始命中 | 2,093 |
| 去重后 Finding | 1,814 |
| P1 / P2 / P3 | 9 / 882 / 923 |
| PMD / CPD / Checkstyle | 828 / 414 / 428 |
| SpotBugs / FindSecBugs / CodeQL | 54 / 35 / 26 |
| 依赖漏洞 | 15 |
| 引擎成功 | 15/15 |

其中 PMD、CPD、Checkstyle 共 1,670 条，占最终 Finding 的约 92%。这说明首要问题是
默认规则和展示口径，而不是平台发现了 1,814 个已确认 Bug 或漏洞。

## 3. 本轮调整

| 组件 | 优化前 | 本轮默认策略 | 保留/扩展方式 |
| --- | --- | --- | --- |
| Gitleaks | 内置规则 + 宽泛 password/token 正则 | 只使用锁定版本内置规则 | 组织 Token 格式放独立 TOML；必须有正反例、entropy/allowlist |
| PMD | 整类导入 errorprone、bestpractices、performance、design | 精选确定性正确性和资源规则 | 新规则先进入观察集，达到可接受真阳性率再进入默认集 |
| CPD | 30 tokens | 100 tokens | 严格审查可显式降低；测试/生成代码未来按独立范围统计 |
| Checkstyle | 规范规则，统一进入报告 | 保持规则覆盖，固定 CODE_STYLE/P3 | 阿里规范应作为独立可选规则包，不与安全规则混用 |
| SpotBugs/FindSecBugs | `-low`，包含低置信启发式 | `-medium` + `-effort:max` | 精确 filter 按 rule/path/class 抑制；低置信放严格档 |
| CodeQL | security-and-quality，244 条查询 | 官方 code-scanning，当前锁定包解析为 80 条高精度查询 | 独立质量档可使用 code-quality；内部框架通过模型包扩展 |
| 严重度 | 引擎 CRITICAL 或 KEV+CVSS 可自动成为 P0 | 静态扫描最多自动 P1；P0必须确认 | 保留原始等级、置信度和映射理由，人工确认后升级 |
| SCA | 三引擎分别扫描 | 保留 PURL+CVE 保守去重、多证据 | 后续增加 scope/reachability/VEX，不按引擎命中次数计漏洞 |

## 4. 规则生命周期

每条扩展规则按以下流程进入默认档：

```text
需求/历史缺陷
  → 编写规则
  → 至少一个真阳性 fixture
  → 至少一个相似但安全的反例 fixture
  → 在代表性项目观察运行
  → 记录 TP/FP/FN 与适用范围
  → 评审后进入 default / strict / retired
```

豁免必须精确到规则、路径、组件、漏洞或指纹，包含原因和到期时间。不得因为一个误报
关闭整个 SQL 注入、命令注入、密钥或依赖漏洞类别。

## 5. 测试与报告计划

1. 运行规则文件和 Adapter 定向契约测试；
2. 使用真实 Mac ARM64 工具包运行 Quick、Standard Analysis、Standard Supply 和 CodeQL smoke；
3. 使用 JDK 17 执行全仓 `clean verify`；
4. 重新构建发布介质，从其 JAR 启动真实 Web 服务；
5. 通过 `POST /api/v1/scans/zip` 对平台自身源码 ZIP 发起 Deep 扫描；
6. 验证任务、15 引擎、Findings分页、HTML/JSON/SARIF/ZIP报告和归档安全；
7. 输出基线对比、规则分布、抽样复核、剩余边界和下一阶段建议。

最终真实扫描证据和大体积报告继续保存在 `.gitignore` 覆盖的
`dist/production-readiness/` 下，不提交动态漏洞库、源码 ZIP 或扫描任务数据。

本计划已于 2026-08-13 完成实施和真实复验，结果见
[规则治理优化真实复验报告](rule-governance-validation-report-2026-08-13.md)。
