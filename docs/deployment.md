# 部署与冷启动

> 本文描述从一个干净 Git clone 启动新实例。新服务器不需要复制旧数据库；
> RSS 等窗口型信源只能重新获得上游当前仍提供的内容，不能保证恢复全部历史。

## 1. 前置条件

- Docker Desktop（macOS）或 Docker Engine + Compose v2（Linux）。
- 至少 12 GB 可用内存、30 GB 可用磁盘；数据量增长后应继续扩容。
- 一份未提交到 Git 的 `.env`，包含 API Token、管理员 Token、数据库凭据和可选 LLM Key。
- Apple Silicon 可直接使用本项目的 arm64 PostgreSQL、Python 和 uv 镜像。

## 2. 配置

复制示例并填写真实值：

```bash
cp .env.example .env
```

必须检查：

```dotenv
POSTGRES_PASSWORD=replace-with-a-long-random-password
INTEL_CONTAINER_DATABASE_URL=postgresql+psycopg://intel:URL_ENCODED_PASSWORD@postgres:5432/intel
INTEL_API_TOKEN=replace-with-a-long-random-read-token
INTEL_ADMIN_API_TOKEN=replace-with-a-different-admin-token
```

`POSTGRES_PASSWORD` 与连接 URL 中的密码必须一致；特殊字符要做 URL 编码。
默认端口只绑定 `127.0.0.1`。需要对外提供 API 时，应经 TLS 反向代理开放，
不要把 PostgreSQL 暴露到公网。

Mac 容器访问宿主机代理时使用：

```dotenv
INTEL_PROXY_POOL_GLOBAL=http://host.docker.internal:7897
```

代理还必须允许来自 Docker Desktop VM 的连接。Linux 上根据项目网桥使用受限
gateway 地址，不能把宿主代理监听到 `0.0.0.0`。

## 3. 首次冷启动

```bash
export INTEL_BUILD_SHA="$(git rev-parse --short HEAD)"
docker compose build --pull
docker compose up -d
```

Compose 启动顺序固定为：

```text
postgres healthy
  → migrate: alembic upgrade head + intel sync（成功后退出 0）
  → api + worker
```

API、worker 和 migrate 使用同一 `INTEL_IMAGE`。不要分别构建或混用不同
Git revision 的镜像。

## 4. 验证

```bash
docker compose ps -a
docker compose logs --tail=100 migrate worker api
curl http://127.0.0.1:8000/health/live
curl http://127.0.0.1:8000/health/ready
curl -H "Authorization: Bearer $INTEL_API_TOKEN" http://127.0.0.1:8000/stats
```

验收条件：

- `migrate` 为 `Exited (0)`。
- PostgreSQL、API、worker 为 healthy。
- readiness 返回当前构建 SHA 和 Alembic head。
- `/stats` 能使用只读 Token 查询。
- worker 日志出现各阶段 tick，来源的 `last_success_at` 开始更新。
- `uv run python scripts/gen_report.py report.html` 能在干净 clone 中运行。

## 5. 发布新版本

```bash
git pull --ff-only
export INTEL_BUILD_SHA="$(git rev-parse --short HEAD)"
docker compose build --pull
docker compose up -d
docker compose ps -a
```

独立 migrate 服务必须先成功；迁移失败时 API/worker 不会使用不匹配的 schema
启动。禁止只重建 API 或只重建 worker。

## 6. 运维权限

- 普通读取接口：`INTEL_API_TOKEN`。
- `/ops/*`：`INTEL_ADMIN_API_TOKEN`。
- `/health`、`/health/live`、`/health/ready`：无需认证，用于探针。
- `/ops/tick` 目前仍同步执行，短期只允许可信管理员调用；后续改为持久任务入队。

## 7. 旧实例归档（可选）

如果不迁移旧数据，可以不恢复数据库。旧服务器关停前仍建议保留一次离线
`pg_dump -Fc`，仅用于审计或应急，不导入新实例。API Key 和 Token 不应放入
备份仓库或 Git。
