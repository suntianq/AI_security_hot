# AI × Security 情报后端

把 AI/安全情报的采集能力融为一个稳定、可扩展的后端。基于 `docs/` 三份设计文档
（[MVP 设计](docs/mvp-design.md) · [整体蓝图](docs/system-design.md) ·
[信源注册表](docs/source-registry.md)）实现的 **M0 工程骨架 + 可运行的采集层**。

## 已实现（M0）

- **阶段化 DB 状态机**（fetch → normalize → …）：慢阶段不阻塞快阶段（plan 修正 1）。
- **FetchContext** 统一出口层：SSRF 双检、限速、重试、超时、响应大小上限、ETag/Last-Modified、代理选择。
- **Egress/代理一等配置**：`sources.yaml` 的 `egress.route` + 环境变量代理池，同一份代码跑国内/海外 VM。
- **四类 Connector + Parser（真实可跑）**：RSS / REST(JSON) / GitHub / 网页适配器；网页解析带 `parse_quality` 打分。已接入 **12 个真实源**（OpenAI/NVD/CISA KEV/Dify/Ollama/vLLM/HuggingFace/Google Security/Trail of Bits/PortSwigger/Anthropic/LangChain）。
- **二次抓取全文（fulltext stage）**：只给摘要且原文为静态 HTML 的源（如 PortSwigger/HuggingFace），自动抓原文 URL 用 trafilatura 补全正文（实测 200 字符摘要 → 2 万字符全文）。JS 渲染的 SPA（如 OpenAI）保持标题+链接，不接 Playwright（代价过大，见 `sources.yaml` 注释）。
- **BlobStore**：网页 HTML 快照存本地卷，DB 只存哈希+引用（后期可换 S3/MinIO）。
- **无状态调度 tick + self_check**：DB 是唯一真相；自检发现 stale/degraded/stuck。
- **FastAPI 只读/运维 API** + **`intel` CLI**（含 `export` 导出 JSON/JSONL/CSV）。
- **迁移 / Lint / 类型检查 / 单元+冒烟+真实爬取测试 / Linux CI**。

## 两种运行方式

- **Docker Compose（推荐，见下方「部署」）**：一条命令起 postgres+api+worker，适合交付/服务器部署。
- **纯宿主机开发（见文末）**：只容器化 PostgreSQL，应用宿主机 `uv run`，零构建、最快迭代。

CLI 常用命令：

```bash
uv run intel sync        # 载入/更新 sources.yaml
uv run intel run-once    # 手动抓一轮（fetch + normalize）
uv run intel stats       # 各阶段数量
uv run intel serve       # 起 API（:8000）
uv run intel worker      # 起后台常驻调度
uv run intel self-check  # 健康自检
```

导出数据（JSON / JSONL / CSV）：

```bash
uv run intel export --format csv  --out docs.csv          # 全部文档导 CSV
uv run intel export --format json --source cisa-kev       # 只导某个源
uv run intel export --format jsonl --min-quality 1 -n 100 # 高质量前 100 条，逐行 JSON
uv run intel export --format json                         # 不加 --out 则打到 stdout（可管道）
```

验证 API：

```bash
curl localhost:8000/health
curl localhost:8000/stats
curl "localhost:8000/documents?min_quality=1&limit=5"
curl localhost:8000/sources
```

## 测试

```bash
uv run pytest tests/test_unit.py tests/test_smoke.py   # 离线：SSRF/规范化/连接器逻辑
INTEL_RUN_LIVE=1 uv run pytest -m live                  # 真实爬取端到端（产生真实数据）
uv run ruff check . && uv run pyright                   # 质量门禁
```

## 部署（Docker Compose，推荐）

一条命令起全栈（`postgres:18` + `api` + `worker`）：

```bash
docker compose up -d --build
docker compose ps                 # 三个容器应为 Up / healthy
curl localhost:8000/health        # {"status":"ok"}
curl localhost:8000/stats         # 抓取进度
```

容器启动时会自动完成初始化，无需手动介入：

- **迁移只由 `worker` 跑一次**（`RUN_MIGRATIONS=1`），`api` 等待 schema 就绪后再启动 —— 避免多容器并发迁移时撞 `alembic_version` 唯一约束。
- `worker` 随后 `intel sync` 载入 `sources.yaml`，并按调度持续抓取。
- 数据持久化在 `pgdata` 卷，网页快照存 `blobdata` 卷。

动态网页兜底（Playwright，默认不启用）：

```bash
docker compose --profile playwright up -d
```

常用运维：

```bash
docker compose logs -f worker                                  # 看抓取日志
docker compose exec worker uv run intel export -f csv -o /tmp/d.csv
docker compose cp worker:/tmp/d.csv ./d.csv                    # 导出并拷出
docker compose down            # 停（保留数据卷）
docker compose down -v         # 停并删数据卷（谨慎）
```

### 代理 / 国内海外混合部署

每个 endpoint 的 `egress.route` 决定走直连还是代理池；代理地址来自环境变量（`.env`），不进代码/日志：

- 国内 VM 抓海外源（GitHub/Anthropic）→ 设 `INTEL_PROXY_POOL_GLOBAL`
- 海外 VM 抓国内源（AIVD/CNVD）→ 设 `INTEL_PROXY_POOL_CN`
- 未配代理池时自动回退直连。

### 构建加速

`pyproject.toml` 已把 uv 默认索引指向清华镜像（`[[tool.uv.index]]`），容器内装依赖走国内源。海外环境如需还原官方 PyPI，删除该段即可。

### 部署踩坑速查

| 现象 | 原因 | 解决 |
|---|---|---|
| `postgres` 启动 exit 1，日志提示 data 目录布局 | postgres:18 改用 `/var/lib/postgresql`（自建 `18/` 子目录） | compose volume 挂 `/var/lib/postgresql`（本项目已修） |
| 构建失败 `Readme file does not exist` | Dockerfile 未 COPY `README.md`，hatchling 打包校验依赖它 | Dockerfile 已 `COPY README.md`；换机注意保留该文件 |
| `api` 崩溃 `duplicate key ... alembic_version` | 多容器并发跑迁移竞态 | 迁移归 `worker` 独占，`api` 等 schema（本项目已修） |
| 依赖安装极慢 | 容器内走代理拉 PyPI 慢 | 已配清华镜像源（见上） |

## 纯宿主机开发（只容器化 PostgreSQL）

开发期最快的方式：只用 Docker 起库，应用在宿主机 `uv run`（`.venv` 已就绪，零构建）。

```bash
uv sync
docker compose up -d postgres
export INTEL_DATABASE_URL=postgresql+psycopg://intel:intel@localhost:5432/intel

uv run alembic upgrade head     # 迁移
uv run intel sync               # 载入 sources.yaml（12 源）
uv run intel run-once           # 真实抓取 + 标准化一轮
uv run intel stats              # 查看各阶段数量
uv run intel serve              # 起 API（:8000）
```

> Docker Hub 不可达时（如部分内网），`postgres:18` 镜像拉不到，可改用本机 apt 安装的 PostgreSQL 16/17（schema 无版本专属特性），应用照跑。

## 目录

```
src/ai_security_hot/
  config/       Settings + sources.yaml 加载器（含 egress 字段）
  domain/       枚举 + 领域值对象（RawItem/NormalizedDocument/...）
  models/       SQLAlchemy 表 + 会话
  connectors/   FetchContext + SSRF + RSS/REST/GitHub/Web 连接器
  parsers/      各源 Parser（rss/cisa_kev/nvd/github_releases/web_article）+ normalize
  storage/      BlobStore + repositories（租约/幂等/阶段推进/导出）
  pipelines/    stage 状态机（fetch/normalize 真实，后续骨架）
  jobs/         无状态调度 tick + self_check
  api/          FastAPI 只读/运维接口
  cli.py        intel CLI（sync/run-once/serve/worker/export/self-check/stats）
sources/        sources.yaml（12 个真实 endpoint，含 egress 字段）+ parsers/
migrations/     Alembic
tests/          unit / smoke（离线）+ integration（真实爬取）
```

## 后续（M1+）

去重/聚类/分类/评分/LLM 摘要、日报与飞书/邮件投递、接入首批 18 个 endpoint、
Parser 漂移检测、pgvector 可选增强。均由 MVP 定义的实际指标触发，不提前引入。
