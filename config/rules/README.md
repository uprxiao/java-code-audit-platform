# 平台规则目录

后续在此维护平台自有或重新分发许可允许的配置：

- Semgrep Java/Spring 规则；
- PMD ruleset；
- Checkstyle 配置；
- SpotBugs include/exclude filter；
- Dependency-Check suppression；
- Gitleaks 自定义规则；
- CodeQL query suite。
- `finding-governance.json`：项目级、可过期的适用性/VEX 与人工复核真值；不删除原始证据。

任何第三方规则进入仓库前都必须记录来源、版本和许可证。

V1 Quick 规则按引擎分目录管理：

- `semgrep/`：平台自有 Java/Spring 安全规则；
- `gitleaks/`：继承锁定版本内置规则的本地策略；
- `pmd/`：Java 17 高信号正确性与资源安全规则；默认不整类导入主观的设计、复杂度和测试风格规则；
- `checkstyle/`：确定性源码风格和卫生规则；
- `trivy/`：仓库扫描策略与资产统计/Finding 边界。

默认审计策略的治理原则：

- SpotBugs 只输出 normal/high confidence（`-medium`），低置信结果留给显式严格档；
- CPD 默认至少 100 tokens，避免短模板和样板代码淹没审计结果；
- Gitleaks 默认使用版本锁定的内置高精度检测器，组织自定义 Token 格式必须另行评审；
- CodeQL Deep 使用官方 `java-code-scanning.qls`，质量扩展不混入默认安全结果；
- Checkstyle 结果属于 `CODE_STYLE/P3`，不会被解释为漏洞或运行时 Bug；
- 自定义扩展必须附正例、反例、规则来源、适用路径和维护责任人，不能只凭一次扫描数量决定启停。
- Finding 治理只在 `projectArtifactId`、精确漏洞/PURL 或精确稳定指纹同时匹配时生效；到期后自动失效并产生警告。
