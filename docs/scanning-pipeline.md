# 扫描流水线

## 输入

- Java/Maven 项目 ZIP；
- SVN 仓库 URL、分支/路径与可选 revision；
- 扫描档位：`quick`、`standard`、`deep`。

## 阶段

### 1. 获取与预检

1. 校验上传大小或 SVN 目标；
2. 安全解压或检出到任务工作区；
3. 识别 Maven 根、模块、源码目录和 JDK 版本；
4. 生成计划并记录无法适用的扫描器。

### 2. 快速扫描

- Gitleaks；
- Semgrep；
- PMD、CPD；
- Checkstyle；
- Trivy repository；
- `pom.xml` 静态资产提取。

这组任务原则上不依赖项目编译，可以并行执行。

### 3. 标准构建扫描

1. 在隔离 Runner 中解析 Maven 依赖并编译；
2. SpotBugs + FindSecBugs 扫描 class 文件；
3. Dependency-Check、OSV 和 Trivy 扫描依赖与产物；
4. Dependency Plugin、Enforcer 检查依赖健康；
5. CycloneDX 生成聚合 SBOM。

### 4. 深度扫描

- 通过许可与使用资格策略后，使用 CodeQL 创建 Java 数据库并运行查询包；
- 兼容时运行 Error Prone；
- 有明确空值注解策略时运行 NullAway。

### 5. 结果处理

1. 保存原始 XML、JSON、SARIF、日志和 SBOM；
2. 转换为统一 Finding；
3. 计算稳定指纹；
4. 合并重复问题并保留多引擎来源；
5. 应用严重性、基线和抑制策略；
6. 生成统一报告。

## 引擎状态

每个引擎至少记录：

```json
{
  "engine": "spotbugs",
  "status": "SUCCEEDED",
  "modulesDiscovered": 8,
  "modulesScanned": 8,
  "findings": 27,
  "durationMs": 18243,
  "artifact": "raw/spotbugs.sarif"
}
```

合法状态包括：`PENDING`、`RUNNING`、`SUCCEEDED`、`PARTIAL`、`FAILED`、`TIMED_OUT`、`SKIPPED`、`CANCELLED`。
