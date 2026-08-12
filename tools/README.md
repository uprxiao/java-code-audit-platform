# Scanner tools

工具布局、分发边界和版本清单规范见[`docs/v1/tool-pack.md`](../docs/v1/tool-pack.md)。

```text
tools/
├── manifest/          版本、SHA256、来源、许可和Parser Schema
├── distributable/     许可允许再分发且通过Git LFS管理的固定工具
│   ├── common/
│   ├── darwin-arm64/
│   └── linux-x86_64/
└── local/             CodeQL等本机安装内容，被gitignore排除
```

当前仓库仍不提交第三方二进制。`scripts/build-semgrep-pack.sh` 和
`scripts/build-quick-tool-pack.sh` 和 `scripts/build-standard-supply-tool-pack.sh` 会从官方锁定地址在本地 `tools/downloads/tool-pack/`
组装可验证工具包；该目录被 gitignore。每个工具根目录的 `pack-metadata.json`
是 ToolRegistry 可直接读取的版本、入口、SHA256、来源和许可证快照。

不要把漏洞数据库、Trivy checks bundle、Maven缓存、CodeQL CLI、任务或报告放入
`distributable/`或提交到 Git。
