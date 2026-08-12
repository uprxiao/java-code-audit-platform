# 本地开发

完整开发顺序、串并行门槛和测试要求见：

- [V1 开发计划](v1/development-plan.md)
- [Worktree 策略](v1/worktree-strategy.md)
- [测试策略](v1/testing-strategy.md)

## 前置条件

- macOS ARM64 或 Ubuntu 22.04 x86_64；
- JDK 17；
- Maven 3.9+；
- Git LFS（开始提交工具二进制后必需）；
- 允许访问 Maven仓库和漏洞数据源。

macOS Homebrew 示例：

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@17
mvn -version
mvn clean verify
```

开始提交第三方工具前安装 Git LFS：

```bash
brew install git-lfs
git lfs install
```

`mvn -version` 必须显示 Java 17。机器上即使同时安装JDK25，也不能用它替代V1验证。

## 开发边界

- M0-M3串行建立公共协议、Fake Scanner和Semgrep纵向链路；
- 只有达到G1门槛才创建多个worktree；
- 本地运行数据放入被忽略的独立data目录；
- CodeQL放入版本化的`tools/local/codeql-v2.26.2`，不提交；
- 工具版本升级必须更新manifest、Fixture并跨平台回归。
