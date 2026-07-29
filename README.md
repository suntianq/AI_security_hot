# AI × Security 情报后端

把 AI/安全情报的采集能力融为一个稳定、可扩展的后端。基于 `docs/` 三份设计文档
（[MVP 设计](docs/mvp-design.md) · [整体蓝图](docs/system-design.md) ·
[信源注册表](docs/source-registry.md)）实现的 **M0 工程骨架 + M1.1 规则分类 + 可运行的采集层**。

## 已实现

### M0 工程骨架

- **阶段化 DB 状态机**（fetch → normalize → fulltext → classify → …）：慢阶段不阻塞快阶段。
- **FetchContext 统一出口层**：SSRF 双检、限速、重试、超时、响应大小上限、ETag/Last-Modified、代理选择；新增 **`aget()` 异步接口**供并发连接器使用。
- **Egress/代理一等配置**：`sources.yaml` 的 `egress.route` + 环境变量代理池，同一份代码跑国内/海外 VM。
- **并发 fetch pipeline**：多个 endpoint 通过 `asyncio.gather` 并发抓取（最多 5 个同时），14 个 endpoint 9 秒完成一轮。
- **BlobStore**：网页 HTML 快照存本地卷，DB 只存哈希+引用（后期可换 S3/MinIO）。
- **无状态调度 tick + self_check**：DB 是唯一真相；自检发现 stale/degraded/stuck。
- **FastAPI 只读/运维 API** + **`intel` CLI**（含 `export` 导出 JSON/JSONL/CSV）。
- **迁移 / Lint / 类型检查 / 单元+冒烟+真实爬取测试 / Linux CI**。

### M1.1 规则分类

- **RuleClassifier**：基于 `taxonomy.yaml` 的多标签分类器，输出 tech_directions / company_models / event_type，带完整溯源（method / rule_version / input_hash）。
- **四条内容主线分类**：ai / ai_for_security / ai_enabled_threats / security_for_ai。
- **事件类型优先级**：source_id → connector → CVE/GHSA 硬信号 → 关键词 → 默认 opinion。

### 六类 Connector + Parser

| Connector | 版本 | Parser | 增量机制 |
|---|---|---|---|
| **RSS** | `rss-1` | `rss-default-v1` | ETag/304（feed 级） |
| **REST** | `rest-1` | `cisa-kev-v1` / `nvd-v1` | ETag/304（CISA）；**date_params + last_success_at**（NVD，API 级增量） |
| **GitHub** | `github-1` | `github-releases-v1` | ETag/304 |
| **Web** | `web-1` | `web-article-v1` | ETag/304 + content hash（双重去重） |
| **arXiv** | `arxiv-1` | `arxiv-v1` | ETag/304（arXiv API 几乎不返回 304） |
| **Sitemap** | `sitemap-1` | `sitemap-article-v1` | **lastmod > last_success_at** 增量过滤 + 并发抓取（asyncio.gather + Semaphore） |

### 已接入 14 个真实源（13 个 source，14 个 endpoint）

| Endpoint | Connector | 增量 |
|---|---|---|
| openai-news-rss | RSS | ETag/304 |
| cisa-kev | REST | ETag/304 |
| nvd-recent | REST | **date_params + last_success_at** |
| anthropic-news | **Sitemap** | **lastmod 增量** |
| huggingface-blog-rss | RSS + fulltext | ETag/304 |
| google-security-rss | RSS | ETag/304 |
| trailofbits-rss | RSS | ETag/304 |
| portswigger-research-rss | RSS + fulltext | ETag/304 |
| arxiv-ai-llm | arXiv | 304（低效） |
| arxiv-security-ai | arXiv | 304（低效） |
| hackernews-rss | RSS | ETag/304 |
| ithome-rss | RSS | ETag/304 |
| google-blog-ai-rss | RSS | ETag/304 |
| github-trending-rss | RSS | ETag/304 |

### 二次抓取全文（fulltext stage）

只给摘要且原文为静态 HTML 的源（如 PortSwigger/HuggingFace），自动抓原文 URL 用 trafilatura 补全正文。JS 渲染的 SPA（如 OpenAI/Google Security Blogspot）保持标题+链接。

### 关键改进说明

**SitemapConnector（新增）**：专为 SPA 站点设计的通用连接器。读 sitemap.xml → 按 URL 模式过滤（如 `/news/` `/research/`）→ 逐篇并发抓取原文 → trafilatura 抽正文。已替换 Anthropic 原来的 Web 适配器（原来只能抓列表页拿不到正文），以后任何有 sitemap 的 SPA 站都可复用。

**NVD 滚动时间窗 + 增量**：`options.rest.date_params` 支持动态注入 `pubStartDate`/`pubEndDate`。首次 poll 用 `now - 30d` 兜底全量抓取；后续 poll 用 `last_success_at` 作为起点，只请求上次成功至今的新 CVE（从 200 条/次降到 0~5 条/次）。

**并发 fetch pipeline**：`run_fetch_stage` 使用 `asyncio.gather` 并发处理多个 endpoint（最多 5 个同时），SitemapConnector 内部也并发抓取文章页（concurrency=5）。14 个 endpoint 一轮从 10+ 分钟降到 9 秒。

## 两种运行方式

- **Docker Compose（推荐）**：一条命令起 postgres+api+worker。
- **纯宿主机开发**：只容器化 PostgreSQL，应用宿主机 `uv run`。

CLI 常用命令：

```bash
uv run intel sync        # 载入/更新 sources.yaml
uv run intel run-once    # 手动抓一轮（fetch + normalize + fulltext + classify）
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
uv run intel export --format json                         # 不加 --out 则打到 stdout
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
uv run pytest tests/test_unit.py tests/test_smoke.py   # 离线：SSRF/规范化/连接器/分类器逻辑
INTEL_RUN_LIVE=1 uv run pytest -m live                  # 真实爬取端到端
uv run ruff check . && uv run pyright                   # 质量门禁
```

## 部署（Docker Compose）

```bash
docker compose up -d --build
docker compose ps                 # 三个容器应为 Up / healthy
curl localhost:8000/health        # {"status":"ok"}
```

容器启动时自动完成初始化：

- **迁移只由 `worker` 跑一次**（`RUN_MIGRATIONS=1`），`api` 等待 schema 就绪后再启动。
- `worker` 随后 `intel sync` 载入 `sources.yaml`，并按调度持续抓取。
- 数据持久化在 `pgdata` 卷，网页快照存 `blobdata` 卷。

动态网页兜底（Playwright，默认不启用）：

```bash
docker compose --profile playwright up -d
```

### 代理 / 国内海外混合部署

每个 endpoint 的 `egress.route` 决定走直连还是代理池；代理地址来自环境变量（`.env`），不进代码/日志：

- 国内 VM 抓海外源 → 设 `INTEL_PROXY_POOL_GLOBAL`
- 海外 VM 抓国内源 → 设 `INTEL_PROXY_POOL_CN`
- 未配代理池时自动回退直连。

### 部署踩坑速查

| 现象 | 原因 | 解决 |
|---|---|---|
| `postgres` 启动 exit 1 | postgres:18 改用 `/var/lib/postgresql` | compose volume 挂 `/var/lib/postgresql` |
| 构建失败 `Readme file does not exist` | Dockerfile 未 COPY `README.md` | Dockerfile 已 `COPY README.md` |
| `api` 崩溃 `duplicate key ... alembic_version` | 多容器并发跑迁移竞态 | 迁移归 `worker` 独占 |
| 依赖安装极慢 | 容器内走代理拉 PyPI 慢 | 已配清华镜像源 |

## 纯宿主机开发

```bash
uv sync
docker compose up -d postgres
export INTEL_DATABASE_URL=postgresql+psycopg://intel:intel@localhost:5432/intel

uv run alembic upgrade head     # 迁移
uv run intel sync               # 载入 sources.yaml（14 个 endpoint）
uv run intel run-once           # 真实抓取 + 标准化 + 分类一轮
uv run intel stats              # 查看各阶段数量
uv run intel serve              # 起 API（:8000）
```

## 目录

```
src/ai_security_hot/
  config/       Settings + sources.yaml 加载器（含 egress 字段）
  domain/       枚举 + 领域值对象（RawItem/NormalizedDocument/Checkpoint + known_ids + last_success_at）
  models/       SQLAlchemy 表 + 会话
  connectors/   FetchContext（sync get + async aget）+ SSRF + 6 类连接器（RSS/REST/GitHub/Web/arXiv/Sitemap）
  parsers/      各源 Parser（rss/cisa_kev/nvd/github_releases/web_article/arxiv/sitemap_article）+ normalize
  classify/     RuleClassifier + Classification 溯源 + taxonomy.yaml
  storage/      BlobStore + repositories（租约/幂等/阶段推进/导出）
  pipelines/    并发 fetch stage + normalize/fulltext/classify stage
  jobs/         无状态调度 tick + self_check
  api/          FastAPI 只读/运维接口
  cli.py        intel CLI（sync/run-once/serve/worker/export/self-check/stats/classify/fetch/normalize/fulltext）
sources/        sources.yaml（14 个真实 endpoint）+ taxonomy.yaml
migrations/     Alembic（initial schema + M1.1 classification columns）
tests/          unit / smoke（离线）+ integration（真实爬取）
```

## 后续（M1.2+）

- **增量更新（M1.2）**：所有连接器基于 DB `known_native_ids` 集合过滤已抓条目，只在 connector 层产出全新条目（当前已实现 NVD + Sitemap 的增量，RSS/arXiv/GitHub/CISA 待改造）。
- **去重聚类**：近重复检测（RapidFuzz + SimHash）+ 事件聚类 + 强合并键（CVE/GHSA/模型+版本）。
- **LLM 摘要/分类**：M1.3 混合分类器（规则 + LLM），中文摘要，事件影响分析。
- **日报与投递**：日报冻结/生成/版本化 + 飞书/邮件投递幂等。
- **更多信源**：接入首批 18~35 个 endpoint。
- Parser 漂移检测、pgvector 可选增强。均由实际指标触发，不提前引入。
