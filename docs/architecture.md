# 系统架构

## 一句话架构

平台是一个多引擎扫描编排系统：控制面接收任务，隔离 Runner 执行扫描，Finding 服务统一结果，报告服务生成可下载审计报告。

## 组件边界

```text
Browser / API Client
        |
        v
Audit API ------> Scan Orchestrator ------> Job Queue
                                            |
                                            v
                                     Isolated Runner
                                      /     |     \
                              source tools build tools deep tools
                                      \     |     /
                                            v
                                      Raw Artifacts
                                            |
                                            v
Finding Normalizer -> Deduplication -> Policy Evaluation -> Report Service
```

### Audit API

- 上传 ZIP、接收 SVN 地址；
- 创建任务并返回 `scanId`；
- 查询进度、结果和报告；
- 不直接运行扫描器或 Maven。

### Scan Orchestrator

- 识别 Java/Maven、多模块和 JDK 要求；
- 根据 quick/standard/deep 生成 DAG 扫描计划；
- 管理依赖、并发、超时、重试和取消；
- 汇总每个引擎的执行状态与覆盖信息。

### Isolated Runner

- 在一次性容器或微虚拟机中执行不可信任务；
- 提供 JDK 8/11/17/21 等构建镜像；
- 平台控制面以 JDK 17 运行，Runner 按被扫描项目和扫描器要求独立选择 JDK；
- 通过只读扫描器配置和受控缓存执行命令；
- 输出原始报告、日志和覆盖元数据后立即销毁。

### Finding Core

- 统一不同引擎的规则、位置、严重性、CWE、数据流和指纹；
- 保存原始引擎证据，不丢失可追溯性；
- 对跨引擎同源问题去重，但保留所有来源标签。

### Report Service

- 输出 HTML、JSON、SARIF；
- 后续支持 PDF/Excel；
- 明确展示成功、失败、跳过、超时和部分完成的引擎。

## 设计原则

1. 一个用户任务可以包含多个扫描引擎，但用户只获取一个统一报告。
2. 扫描器是外部适配器，不进入核心领域模型。
3. 原始报告不可替代，统一 Finding 也不可缺少。
4. 可观测覆盖范围与 Finding 数量同等重要。
5. AI 不是完成扫描的必要依赖，后续只能作为可选 Reviewer。
