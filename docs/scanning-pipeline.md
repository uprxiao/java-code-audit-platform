# 扫描流水线

权威流程见[V1扫描生命周期](v1/scan-lifecycle.md)。

```text
ZIP/SVN
→ 容量和路径安全检查
→ 单一Maven Reactor预检
→ Profile/DAG计划
→ Quick源码扫描
→ Standard Maven构建和供应链扫描
→ 可选Deep CodeQL
→ Finding归一化/去重/抑制
→ HTML/JSON/SARIF/SBOM/raw/logs
→ 删除工作区并按保留期清理报告
```

关键口径：

- `STANDARD` 默认使用系统 Maven 3.9+和JDK17执行`-DskipTests package`；
- 构建失败不丢弃Quick结果；
- 单引擎失败不阻止独立引擎，最终可为`COMPLETED_WITH_ERRORS`；
- CodeQL仅在Deep运行，CLI本地安装且不进入公共仓库；
- 报告必须区分成功0问题、失败、跳过、超时和部分覆盖。
