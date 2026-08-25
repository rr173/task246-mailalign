# task246-mailalign — 邮件 SPF/DKIM 对齐诊断服务

面向邮件安全工程师的纯后端 Go 服务。它接收已采集的邮件样本（可见 From、Return-Path、收件 IP 和正文）、Received 跳转段、SPF
授权记录和 DKIM selector 快照，重建认证链，分别判断 strict/relaxed 域对齐，并发布可
追溯的诊断快照。服务不收发邮件、不解析未实现的原始邮件头格式，也不访问外部 DNS。

## 业务闭环

导入邮件样本 → 录入跳转链 → 保存 SPF/DKIM DNS 快照 → 计算认证结果和域对齐 → 标记可信中继解释 → 发布不可变快照 → 重启恢复。

## API

- `POST /api/samples`、`GET /api/samples/{id}`
- `POST/GET /api/samples/{id}/hops`
- `POST /api/samples/{id}/analyze`、`GET /api/samples/{id}/diagnostic`
- `POST /api/hops/{id}/trust`
- `POST/GET /api/spf-records`、`POST/GET /api/dkim-records`
- `POST /api/samples/{id}/snapshots`、`GET /api/snapshots/{id}`
- `GET /api/self-check`

## 验证

```bash
GOTOOLCHAIN=local CGO_ENABLED=0 go test ./...
GOTOOLCHAIN=local CGO_ENABLED=0 go vet ./...
GOTOOLCHAIN=local CGO_ENABLED=0 go build ./...
GOTOOLCHAIN=local CGO_ENABLED=0 go run ./cmd/mailalign --smoke-test
```

## Docker

```bash
docker build -t task246-mailalign .
docker run --rm task246-mailalign --smoke-test
```
