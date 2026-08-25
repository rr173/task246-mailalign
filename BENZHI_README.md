# BENZHI_README — task246-mailalign

邮件 SPF/DKIM 对齐诊断服务是纯后端 Web 项目。评测重点是邮件样本字段与 Received 跳转解析、SPF include
递归、DKIM canonical body hash、strict/relaxed 组织域比较、可信转发器解释和 SQLite
快照恢复，不涉及邮件发送或外部 DNS 查询。

## 构建命令

```bash
GOTOOLCHAIN=local CGO_ENABLED=0 go build ./...
GOTOOLCHAIN=local CGO_ENABLED=0 go vet ./...
GOTOOLCHAIN=local CGO_ENABLED=0 go test ./...
GOTOOLCHAIN=local CGO_ENABLED=0 go run ./cmd/mailalign --smoke-test
```

## smoke-test 契约

冒烟测试创建 SPF/DKIM 快照和一封经转发的邮件，确认 SPF 与 DKIM 认证均能被解释，
组织域只在 relaxed 模式下对齐；随后篡改正文生成第二个样本，确认 DKIM body hash
失败不会被可信转发器标记提升；发布第一个诊断快照，关闭并重开 SQLite，确认快照
状态和内容摘要不变。成功时打印 `SMOKE TEST PASSED` 并返回退出码 0。

## Docker

镜像入口为 `/app/mailalign`，默认命令为 `--smoke-test`；运行时只传递 flag，不追加
数据库路径参数。
