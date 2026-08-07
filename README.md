# AI Security Hot

AI Security Hot 是一个面向 AI 与网络安全领域的增量情报后端。它持续采集新闻、研究、
漏洞库和技术社区内容，将原始材料规范化、分类、去重并聚合为可追溯事件，最终通过 API、
数据导出和静态报告提供查询能力。

项目适合运行在个人服务器或团队内部基础设施中。默认部署不依赖外部模型；需要更深层的
语义抽取时，可以接入 DeepSeek、OpenAI-compatible 服务以及独立的 Embedding 服务。

## 核心能力

- 增量采集：支持 RSS、REST、NVD、AI HOT、GitHub、网页、arXiv、Sitemap 和
  Hacker News 官方 API（结构化条目 + 提交者正文，链接帖正文二次抓取）。
- 多源覆盖：已配置 OpenAI、Anthropic、AI HOT、NVD、CISA、Google、Apple、NVIDIA、
  Hugging Face、Wiz、PortSwigger、Trail of Bits、arXiv、Hacker News 等来源。
- 生命周期审计：保留原始版本、内容修订、撤回、拒绝、来源退役和替代关系。
- 分类体系：CVE 独立于新闻与论文主题；资讯可归类为 Agent、LLM、AI for Security、
  Security for AI 和系统安全。
- 非破坏式去重：原始证据不会因去重被删除；URL、标题、正文和强标识关系均可追溯。
- 增量事件聚合：使用持久索引和有界工作队列，只重算受影响的文档与事件组件。
- 冲突保护：不同 CVE、GHSA、CNVD、版本或事故身份不会被相似度规则强行合并。
- 事件证据链：事件包含版本、Claim、支持/反驳证据、来源等级和变更记录。
- 可选语义能力：支持 LLM 相关性判断、实体/原子事件/Claim 抽取，以及独立 Embedding
  候选召回；默认关闭，不会产生模型费用。
- 冻结热点：按自然日保存不可变热点 revision，并支持 `as_of` 查询。
- 可运维部署：PostgreSQL、Alembic、FastAPI、常驻 worker、健康探针、自检和 Docker
  Compose 冷启动。

## 工作方式

```text
信源
  -> 增量抓取与原始证据
  -> 规范化与正文补全
  -> 规则或混合分类
  -> 局部去重与事件聚合
  -> Event / Claim / Evidence / EventVersion
  -> 每日热点快照 / API / 前端网站 / 后台管理

可选语义支路
  -> LLM 影子抽取
  -> 实体、原子事件和 Claim
  -> 候选召回与关系组件
  -> 人工确认后正式提升
```

PostgreSQL 是流水线状态的唯一事实来源。API、worker 和迁移服务使用同一代码镜像；
Blob 卷保存抓取到的网页正文，数据库保存内容哈希和引用。

## 快速启动

需要 Docker Engine + Compose v2，或 macOS 上的 Docker Desktop。镜像同时支持 amd64
和 arm64；应用运行时使用 Python 3.13，数据库使用 PostgreSQL 18。

```bash
git clone git@github.com:suntianq/AI_security_hot.git
cd AI_security_hot
cp .env.example .env
```

前端 `web/dist` 由 Vite 构建产物提供；`docker compose build` 会在镜像构建时通过
多阶段 Dockerfile 自动执行 `npm ci && npm run build`（`web-src/` 下）。本地单独
构建/开发前端：

```bash
cd web-src && npm ci && npm run build   # 产出 ../web/dist
cd web-src && npm run dev               # Vite dev server (http://localhost:5173)
```

至少修改 `.env` 中的以下值：

```dotenv
POSTGRES_PASSWORD=使用一个足够长的随机密码
INTEL_CONTAINER_DATABASE_URL=postgresql+psycopg://intel:URL编码后的密码@postgres:5432/intel
INTEL_API_TOKEN=只读接口Token
INTEL_ADMIN_API_TOKEN=独立的运维接口Token
```

密码中的特殊字符必须在数据库 URL 中编码。密钥和 Token 只放在 `.env`，不得写入
YAML、源代码或 Git。

```bash
export INTEL_BUILD_SHA="$(git rev-parse --short HEAD)"
docker compose build --pull
docker compose up -d
docker compose ps -a
```

启动顺序为 PostgreSQL 健康、Alembic 迁移与信源同步成功、API 和 worker 启动。
新服务器不需要旧数据时，可以直接使用空数据库重新抓取。

```bash
docker compose logs --tail=100 migrate api worker
curl http://127.0.0.1:8000/health/live
curl http://127.0.0.1:8000/health/ready
curl -H "Authorization: Bearer $INTEL_API_TOKEN" http://127.0.0.1:8000/stats
```

默认 PostgreSQL 和 API 只监听 `127.0.0.1`。如需对外提供服务，应通过带 TLS 和访问
控制的反向代理开放 API，不要把 PostgreSQL 暴露到公网。

## 网络与代理

每个 endpoint 在 `sources/sources.yaml` 中声明直连或代理路由，代理地址通过环境变量
提供：

```dotenv
# 国内服务器访问海外来源
INTEL_PROXY_POOL_GLOBAL=http://受限代理地址:端口

# 海外服务器访问国内来源
INTEL_PROXY_POOL_CN=http://受限代理地址:端口
```

容器内的 `127.0.0.1` 指向容器自身。macOS Docker Desktop 访问宿主机代理时使用：

```dotenv
INTEL_PROXY_POOL_GLOBAL=http://host.docker.internal:7897
```

Linux 应只在项目 Docker 网桥地址上暴露代理入口，不能把代理监听到公网。

### 端口清单

| 端口 | 绑定 | 服务 |
|---|---|---|
| `8000` | `127.0.0.1` | API + 前端（api 容器，FastAPI/前端/后台） |
| `5433` | `127.0.0.1` | PostgreSQL（postgres 容器，宿主机映射） |
| `7897` | `127.0.0.1` | 海外抓取代理（`INTEL_PROXY_POOL_GLOBAL`） |
| `17897` | `172.18.0.1` | Docker 网桥代理入口（容器访问宿主机 7897） |
| `22` | `0.0.0.0` | SSH |

API 与 PostgreSQL 默认只绑定 `127.0.0.1`；对外服务需经 TLS 反向代理。

## API

健康接口、静态前端页面和 `/api/*` 聚合接口无需认证；读取接口接受只读 Token 或
管理员 Token；`/ops/*` 写操作只接受管理员 Token。

```bash
curl http://127.0.0.1:8000/health/ready

curl -H "Authorization: Bearer $INTEL_API_TOKEN" "http://127.0.0.1:8000/documents?limit=20"

curl -H "Authorization: Bearer $INTEL_API_TOKEN" "http://127.0.0.1:8000/events?min_score=70&limit=20"
```

主要读取接口：

- `GET /sources`
- `GET /documents`、`GET /documents/{id}`
- `GET /events`、`GET /events/{id}`
- `GET /stats`
- `GET /api/overview` — 公开前端聚合（热点 + 模块时间线），无需 token
- `GET /api/feed` — 公开游标分页信息流（`limit`/`before`/`since`/`module`/`tech_direction`/`source`），无需 token
- `GET /api/search` — 公开全文搜索（`q`≥2 字符，标题或正文），无需 token
- `GET /api/document/{id}`、`GET /api/event/{id}` — 文档/事件详情，无需 token
- `GET /api/daily/archives`、`GET /api/daily/archives/{date}` — 每日简报归档，无需 token
- `GET /ops/self-check`

后台管理写接口（`/ops/`，管理员 Token）：

- `PATCH /ops/documents/{id}` — 手动打标签/改分类
- `PATCH /ops/documents/{id}/status`、`DELETE /ops/documents/{id}` — 软删/物理删
- `POST /ops/documents/{id}/requeue` — 单文档重新聚类
- `PATCH /ops/events/{id}/status`、`DELETE /ops/events/{id}` — 事件软删/物理删
- `POST /ops/classify`、`POST /ops/cluster` — 一键分类 / 聚类+去重
- `GET /ops/taxonomy`、`POST/DELETE /ops/taxonomy/tags` — 标签分类管理

## 常用运维命令

宿主机开发环境使用 `uv run intel ...`；查看全部参数可运行
`uv run intel <command> --help`。

```bash
uv run intel sync                 # 同步信源注册表
uv run intel fetch                # 执行一轮到期信源抓取
uv run intel normalize            # 规范化待处理原始材料
uv run intel fulltext             # 补抓已配置来源的正文
uv run intel classify             # 执行规则或混合分类
uv run intel eventize             # 局部去重并更新事件
uv run intel daily-snapshot       # 冻结一个每日热点 revision
uv run intel self-check           # 检查信源、积压、租约和配置
uv run intel stats                # 查看数据量与流水线状态
uv run intel export --format jsonl --out documents.jsonl
```

### Black Hat Briefings（Cloudflare 防护源）

Black Hat 议题由独立 Playwright 容器抓取（通过 Cloudflare 质询），写入共享卷，
主 worker 的 fetch 阶段再读取入库。手动触发一次：

```bash
docker compose --profile playwright run --rm playwright
```

可用宿主 cron 每周自动触发（例如每周日 03:00）：

```cron
0 3 * * 0  cd /path/to/ai_security_hot && docker compose --profile playwright run --rm playwright >> /var/log/blackhat_fetch.log 2>&1
```

Black Hat 是周期性会议（US 每年 8 月、Asia 每年 5 月左右），会议结束后可
`docker compose --profile playwright stop` 或移除 endpoint。

## 可选模型配置

LLM profile 位于 `config/models.yaml`，部署时由 `INTEL_LLM_*` 环境变量覆盖。API Key
只能通过 `INTEL_LLM_API_KEY` 注入。以下命令只检查配置，不发起模型请求：

```bash
uv run intel llm-config
```

默认普通冷启动不会调用 LLM：

```dotenv
INTEL_CLASSIFICATION_MODE=rule
INTEL_SEMANTIC_ENRICHMENT_ENABLED=false
```

Embedding 使用独立的 `config/embeddings.yaml` 与 `INTEL_EMBEDDING_*` 配置。它需要真正
支持 `/embeddings` 的模型，不能直接使用聊天模型，默认同样关闭：

```dotenv
INTEL_EMBEDDING_ENABLED=false
```

向量相似度只用于召回可能相关的候选，不会绕过强身份冲突规则，也不会自动合并事件。

## CVE 推送过滤

CVE 模块默认只展示**命中关注软件/系统 且 CVSS 达标**的漏洞（例如 Linux 相关的
高 CVSS 漏洞），避免每天几百条 CVE 淹没信息流。配置在 `config/cve_follow.yaml`：

```yaml
cvss_min: 7.0   # 基础分阈值，>= 该值才推送
follow:         # 关注关键词，命中受影响软件/厂商/标题/描述任一即视为关注
  - linux
  - openssl
```

`follow` 为空时表示不启用过滤（保留全部 CVE）。路径可用
`INTEL_CVE_FOLLOW_CONFIG_FILE` 覆盖。NVD 解析器会把 CVSS 基础分与受影响产品/厂商
写入文档，overview 与 feed 据此过滤。

## 前端网站与后台管理

`intel serve` 同时提供 API 和内置 Web 前端（`web/dist` 目录静态挂载，由 `web-src/` 构建）：

- **公开前端** `/`：AI × Security 每日热点情报站（Vite + TypeScript，构建产物在
  `web/dist`）。三栏情报布局（桌面端 侧栏/主信息流/右栏，平板双栏，移动端抽屉式
  侧栏）：今日热点 Top1 主卡 + Top2-5 紧凑列表、轻量统计、按日分组的"最新精选"
  信息流（粘性日期头、可折叠）、分类/技术方向/来源/排序筛选、Cmd/Ctrl+K 全局搜索、
  Dark Mode、已读变淡（localStorage）。两种视图：首页（`/api/overview`）与
  全部动态（`/api/feed` 游标分页 + 无限滚动）。筛选状态映射到 URL query
  （`?view=&category=&tech=&source=&range=&sort=`）。
  数据来自 `GET /api/overview`、`GET /api/feed`、`GET /api/search`（均无需 token）。
- **后台管理** `/admin.html`：登录后（输入 `INTEL_ADMIN_API_TOKEN`）可实时管理——
  文档/事件增删改查（打标签、软删/恢复、物理删除、重新聚类）、标签分类管理
  （taxonomy 关键词增删）、一键分类/聚类触发。

后台写操作全部挂 `/ops/` 前缀，由 `INTEL_ADMIN_API_TOKEN` 保护。

## 开发与验证

```bash
uv sync
uv run ruff check .
uv run pyright
docker compose config --quiet
uv run alembic upgrade head
uv run alembic check
uv run pytest -m "not live" -q
```

真实信源测试需要显式开启，避免外部网站波动影响普通 CI：

```bash
INTEL_RUN_LIVE=1 uv run pytest -m live -v
```

## 当前边界

- 语义抽取默认处于影子模式，不会自动改写正式事件。
- Embedding 候选召回默认关闭，正式关系裁决仍以确定性规则和人工门禁为主。
- 正式语义事件提升必须显式执行 `event-promote --apply`。
- 动态网页抓取仅用于 Cloudflare 防护的信源（Black Hat Briefings）：通过
  `--profile playwright` 的独立容器抓取，主 worker 不内置浏览器。
- 主动告警、邮件/飞书投递尚未提供。
- RSS 等窗口型来源只能抓取上游当前仍返回的内容，空库冷启动不能恢复窗口之外的历史。
- Hacker News 通过官方 API 抓取（旧 RSS 已退役）；链接帖正文依赖 fulltext 抓取，
  JS 渲染/付费墙站点可能没有正文，仅显示标题 + 原文链接。
- 公开前端暂无收藏功能；CVE 过滤只影响展示，不改变入库文档。

## 目录

```text
src/ai_security_hot/  应用、API、流水线、模型和存储代码
sources/              信源注册表与分类体系
config/               非敏感 LLM 与 Embedding profile
migrations/           Alembic 数据库迁移
scripts/              Black Hat 抓取等运维脚本
evaluation/           JSON/JSONL 评测资产
tests/                单元、数据库集成和可选真实信源测试
```
