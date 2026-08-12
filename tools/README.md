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

当前尚未提交第三方二进制。正式加入前必须完成许可复核、双平台真实扫描、SHA256和Golden Fixture。不要把漏洞数据库、Maven缓存、CodeQL CLI、任务或报告放入`distributable/`。
