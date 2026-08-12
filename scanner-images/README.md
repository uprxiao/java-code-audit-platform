# 扫描器镜像

该目录后续保存扫描器镜像定义和版本锁定清单。建议按职责拆分，而不是把所有工具塞进一个超大镜像：

- `source-scan`：Gitleaks、Semgrep、PMD/CPD、Checkstyle、Trivy；
- `java-build-scan-jdk8|11|17|21`：Maven、SpotBugs/FindSecBugs、Dependency-Check、CycloneDX；
- `codeql-java`：CodeQL CLI 和固定查询包。

镜像只能由编排层启动，不在容器内挂载宿主 Docker Socket。
