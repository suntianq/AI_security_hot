# AI × Security 情报后端

把 AI/安全情报的采集能力融为一个稳定、可扩展的后端。基于 `docs/` 三份设计文档
（[MVP 设计](docs/mvp-design.md) · [整体蓝图](docs/system-design.md) ·
[信源注册表](docs/source-registry.md)）实现的 **M0 工程骨架 + M1.1 规则分类 + M1.2 增量优化**。

## 已实现

### M0 工程骨架

- **阶段化 DB 状态机**（fetch → normalize → fulltext → classify → …）：慢阶段不阻塞快阶段。
- **FetchContext 统一出口层**：SSRF 双检、严格请求启动限速、重试、超时、流式响应大小上限、ETag/Last-Modified、代理选择；`aget()` 在单轮 pipeline 内复用异步连接池。
- **Egress/代理一等配置**：`sources.yaml` 的 `egress.route` + 环境变量代理池，同一份代码跑国内/海外 VM。
- **并发 fetch pipeline**：多个 endpoint 并发抓取；异步请求复用连接池并严格限制每个 endpoint 的请求启动速率。
- **BlobStore**：网页 HTML 快照存本地卷，DB 只存哈希+引用（后期可换 S3/MinIO）。
- **无状态调度 tick + self_check**：DB 是唯一真相；自检发现 stale/degraded/stuck。
- **FastAPI 只读/运维 API** + **`intel` CLI**（含 `export` 导出 JSON/JSONL/CSV）。
- **迁移 / Lint / 类型检查 / 单元+冒烟+真实爬取测试 / Linux CI**。

### M1.1 规则分类

- **RuleClassifier**：基于 `taxonomy.yaml` 的多标签分类器，输出 tech_directions / company_models / event_type，带完整溯源（method / rule_version / input_hash）。
- **当前规则标签**：结构化 NVD/CISA 漏洞记录单独标记为 `cve`；新闻与论文才参与 `llm / agent / ai_for_security / security_for_ai / system_security` 主题分类。未命中时保留为通用 AI，不强行打标。
- **事件类型优先级**：source_id → connector → CVE/GHSA 硬信号 → 关键词 → 默认 opinion。

### M1.2 增量优化

- **Connector 级过滤**：Checkpoint 携带最近的 `native_id → content_hash`，未变化内容不会进入后续 pipeline。
- **内容修订版本化**：RawItem 幂等键为 `(endpoint_id, native_id, content_hash)`；相同 ID 内容变化时保存新的不可变版本。
- **NVD 完整性**：15 分钟重叠窗口 + `totalResults/startIndex` 分页，避免发布延迟和单页上限漏数。
- **Anthropic 双通道**：Newsroom 快速发现 + 每日 Sitemap 72 小时重叠对账。
- **调度可靠性**：应用 endpoint jitter，失败按指数退避，FetchRun 记录真实开始/结束时间。

### 六类 Connector + Parser

| Connector | 版本 | Parser | 增量机制 |
|---|---|---|---|
| **RSS** | `rss-2` | `rss-default-v1` | ETag/304 + native ID/content hash 过滤与修订检测 |
| **REST** | `rest-2` | `cisa-kev-v1` / `nvd-v1` | CISA 内容修订检测；NVD 重叠时间窗 + 完整分页 |
| **GitHub** | `github-2` | `github-releases-v1` | ETag/304 + native ID/content hash 过滤与修订检测 |
| **Web** | `web-1` | `web-article-v1` | ETag/304 + content hash（双重去重） |
| **arXiv** | `arxiv-2` | `arxiv-v1` | native ID/content hash 过滤；ETag/304 作为辅助 |
| **Sitemap** | `sitemap-2` | `sitemap-article-v1` | Newsroom 快速发现 + Sitemap 重叠对账 + 并发正文抓取 |

### 已接入 18 个真实 endpoint（17 个 source）

| Endpoint | Connector | 增量 |
|---|---|---|
| openai-news-rss | RSS | ETag/304 + content hash |
| aihot-selected-rss | RSS | ETag/304 + 最新 50 条精选窗口 + content hash |
| cisa-kev | REST | ETag/304 + 同 CVE 内容修订检测 |
| nvd-recent | REST | `last_success_at - 15min` 重叠窗口 + 完整分页 + content hash |
| anthropic-news | **Newsroom + Sitemap** | 快速发现 + 每日 72h 重叠对账 |
| huggingface-blog-rss | RSS + fulltext | ETag/304 + content hash |
| google-security-rss | RSS | native ID/content hash（无稳定 HTTP validator） |
| trailofbits-rss | RSS | ETag/304 + content hash |
| portswigger-research-rss | RSS + fulltext | ETag/304 + content hash |
| apple-ml-research-rss | RSS | ETag/Last-Modified/304 + content hash |
| nvidia-blog-rss | RSS | ETag/Last-Modified/304 + content hash |
| wiz-blog-rss | RSS | ETag/Last-Modified/304 + content hash |
| arxiv-ai-llm | arXiv | native ID/content hash；304 辅助 |
| arxiv-security-ai | arXiv | native ID/content hash；304 辅助 |
| hackernews-rss | RSS | HNRSS Last-Modified/304 + content hash |
| ithome-rss | RSS | ETag/304 + content hash |
| google-blog-ai-rss | RSS | ETag/304 + content hash |
| github-trending-rss | RSS | ETag/304 + content hash |

### 二次抓取全文（fulltext stage）

只给摘要且原文为静态 HTML 的源（如 PortSwigger/HuggingFace），自动抓原文 URL 用 trafilatura 补全正文。JS 渲染的 SPA（如 OpenAI/Google Security Blogspot）保持标题+链接。

### 关键改进说明

**Anthropic 双通道增量**：每次轮询只解析服务端渲染的 Newsroom 列表，并仅抓取未知 URL；每 24 小时再用 Sitemap 做一次 72 小时重叠对账，发现列表遗漏和旧文修订。正文仍由 trafilatura 抽取，不需要 Playwright。

**NVD 滚动时间窗 + 分页**：首次 poll 回看 30 天，后续从 `last_success_at - 15min` 开始以小窗口重叠抓取；按 `totalResults/startIndex` 完整翻页，内容哈希幂等消除重叠数据。

**四个新增官方 RSS**：AI HOT 使用官方推荐的精选摘要 feed（30 分钟）；Apple ML Research（6 小时）、NVIDIA Blog（2 小时）和 Wiz Blog（2 小时）均直接复用 `rss-2`。它们统一使用 ETag/Last-Modified、304、native ID/content hash 和 DB 唯一约束，不需要新增 Connector/Parser 类。

**连接复用与严格限速**：`run_fetch_stage` 最多并发处理 5 个 endpoint；Sitemap 文章页并发为 5，但请求启动时间服从配置 RPM。单轮内复用 HTTP 连接，正文抽取在线程池执行。

### 当前增量边界

- Connector 预过滤只加载每个 endpoint 最近 5,000 个 RawItem 版本；超过窗口的旧记录即使被再次产出，DB 全历史唯一约束仍会阻止完全相同的内容重复落库。
- RSS、arXiv 和列表页只能处理上游当前返回的记录；停机时间超过上游保留窗口仍可能漏采。Anthropic 的每日 Sitemap 对账降低了该风险，但当前每次最多检查 50 个、回看 72 小时。
- AI HOT 当前接入的是官方推荐的最新 50 条精选 RSS。30 分钟轮询足以覆盖正常更新且支持条目修订，但长时间停机并导致窗口滚过 50 条时仍可能漏采；若要完整镜像全部精选与撤选事件，需要后续实现其 `snapshot + changes` opaque cursor/409 重建协议及删除语义，不能直接套用当前通用 REST 模式。
- NVD 当前使用 `pubStartDate/pubEndDate`，能覆盖首次 30 天、后续 15 分钟重叠窗口内的延迟发布与修订；窗口外旧 CVE 的后续修改尚需增加 `lastModStartDate/lastModEndDate` 对账任务。
- “内容修订检测”只对本轮被上游重新返回或被对账命中的记录生效，不等同于对任意历史记录做全量变更扫描。

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

当前离线套件覆盖 30 个用例；`live` 测试默认跳过，只有显式设置 `INTEL_RUN_LIVE=1` 才访问真实信源。

## 部署（Docker Compose）

```bash
docker compose up -d --build
docker compose ps                 # api/worker 应为 Up，postgres 应为 healthy
curl localhost:8000/health        # {"status":"ok"}
```

容器启动时自动完成初始化：

- **迁移只由 `worker` 跑一次**（`RUN_MIGRATIONS=1`），`api` 等待 schema 就绪后再启动。
- `worker` 随后 `intel sync` 载入 `sources.yaml`，并按调度持续抓取。
- 数据持久化在 `pgdata` 卷，网页快照存 `blobdata` 卷。

已有数据库升级到本版本时，必须先应用 `c3e1d7a4b902_raw_item_content_versions`：Compose 重建后由 `worker` 自动执行 `alembic upgrade head`；宿主机部署应在启动新代码前手工运行该命令。迁移只替换 RawItem 唯一约束，不删除或回填已有数据。

> 当前 API 未实现认证，且包含 `/ops/tick` 运维写操作。部署时应只绑定可信内网或在前置网关完成认证与访问控制。

动态网页兜底目前尚未实现。Compose 中的 `playwright` Profile 只是预留运行位，当前镜像不包含 Playwright 浏览器和 Connector，不应作为生产抓取能力启用。

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
uv run intel sync               # 载入 sources.yaml（18 个 endpoint）
uv run intel run-once           # 真实抓取 + 标准化 + 分类一轮
uv run intel stats              # 查看各阶段数量
uv run intel serve              # 起 API（:8000）
```

## 目录

```
src/ai_security_hot/
  config/       Settings + sources.yaml 加载器（含 egress 字段）
  domain/       枚举 + 领域值对象（RawItem/NormalizedDocument/Checkpoint + known content hashes + 独立内容水位）
  models/       SQLAlchemy 表 + 会话
  connectors/   FetchContext（sync get + async aget）+ SSRF + 6 类连接器（RSS/REST/GitHub/Web/arXiv/Sitemap）
  parsers/      各源 Parser（rss/cisa_kev/nvd/github_releases/web_article/arxiv/sitemap_article）+ normalize
  classify/     RuleClassifier + Classification 溯源 + taxonomy.yaml
  storage/      BlobStore + repositories（租约/幂等/阶段推进/导出）
  pipelines/    并发 fetch stage + normalize/fulltext/classify stage
  jobs/         无状态调度 tick + self_check
  api/          FastAPI 只读/运维接口
  cli.py        intel CLI（sync/run-once/serve/worker/export/self-check/stats/classify/fetch/normalize/fulltext）
sources/        sources.yaml（18 个真实 endpoint）+ taxonomy.yaml
migrations/     Alembic（initial + classification + RawItem 内容版本）
tests/          unit / smoke（离线）+ integration（真实爬取）
```

## 后续（M2+）

- **去重聚类**：近重复检测（RapidFuzz + SimHash）+ 事件聚类 + 强合并键（CVE/GHSA/模型+版本）。
- **LLM 摘要/分类**：M1.3 混合分类器（规则 + LLM），中文摘要，事件影响分析。
- **日报与投递**：日报冻结/生成/版本化 + 飞书/邮件投递幂等。
- **更多信源**：在当前 18 个 endpoint 基础上扩展至约 35 个。
- Parser 漂移检测、pgvector 可选增强。均由实际指标触发，不提前引入。
