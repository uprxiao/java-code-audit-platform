# 平台规则目录

后续在此维护平台自有或重新分发许可允许的配置：

- Semgrep Java/Spring 规则；
- PMD ruleset；
- Checkstyle 配置；
- SpotBugs include/exclude filter；
- Dependency-Check suppression；
- Gitleaks 自定义规则；
- CodeQL query suite。

任何第三方规则进入仓库前都必须记录来源、版本和许可证。

V1 Quick 规则按引擎分目录管理：

- `semgrep/`：平台自有 Java/Spring 安全规则；
- `gitleaks/`：继承锁定版本内置规则的本地策略；
- `pmd/`：Java 17 正确性、资源、性能和设计规则；
- `checkstyle/`：确定性源码风格和卫生规则；
- `trivy/`：仓库扫描策略与资产统计/Finding 边界。
