# AI × Security 情报后端

把 AI/安全情报的采集能力融为一个稳定、可扩展的后端。基于 `docs/` 设计文档
（[MVP 设计](docs/mvp-design.md) · [整体蓝图](docs/system-design.md) ·
[信源注册表](docs/source-registry.md) · [M1 增量与分类](docs/m1-data-pipeline.md) · [M2 事件情报](docs/event-intelligence.md)）实现的
**M0 工程骨架 + M1 结构化采集 + M2.0 事件情报基线**。

## 已实现

### M0 工程骨架

- **阶段化 DB 状态机**（fetch → normalize → fulltext → classify → …）：慢阶段不阻塞快阶段。
- **FetchContext 统一出口层**：SSRF 双检、每次重试前严格限速、超时、流式响应大小上限、ETag/Last-Modified、代理选择；同步/异步请求都在单轮 pipeline 内复用连接池。
- **Egress/代理一等配置**：`sources.yaml` 的 `egress.route` + 环境变量代理池，同一份代码跑国内/海外 VM。
- **并发 fetch pipeline**：多个 endpoint 并发抓取；异步请求复用连接池并严格限制每个 endpoint 的请求启动速率。
- **BlobStore**：网页 HTML 快照存本地卷，DB 只存哈希+引用（后期可换 S3/MinIO）。
- **无状态调度 tick + self_check**：DB 是唯一真相；自检发现 stale/degraded/FAILED/过期租约，并报告分类重试及 M2 去重/聚类积压。
- **FastAPI 只读/运维 API** + **`intel` CLI**（含 `export` 导出 JSON/JSONL/CSV）。
- **迁移 / Lint / 类型检查 / 单元+冒烟+真实爬取测试 / Linux CI**。

### M1 增量采集与混合分类

- **不可变历史 + 双轴当前投影**：RawItem 保存全部内容/撤回版本；Document 同时记录本地来源生命周期（active/superseded/withdrawn/retired）与上游记录状态（published/rejected/withdrawn/unknown），历史可审计、当前视图可统一过滤。
- **AI HOT 完整镜像**：selected snapshot bootstrap、durable changes cursor、upsert/remove、409 自动重建，不再受 RSS 最新 50 条窗口限制。
- **NVD modified-time**：120 天 bootstrap/长停机 catch-up 使用动态缩窗和 durable cursor 分批推进；稳态从 `last_success_at - 15min` 重叠抓取；Rejected/Withdrawn CVE 保留为历史证据但退出当前视图。
- **CISA 权威快照**：官方 GitHub 镜像 + ETag/304 + 修订与删除检测。
- **Anthropic 双通道**：Newsroom 快速发现 + 每日 Sitemap 72 小时重叠对账。
- **状态版本和配置收敛**：endpoint `state_version` 控制 checkpoint 重建；`replaced_by` 可声明替代关系并审计式退役旧 endpoint；YAML 删除的 endpoint 自动 paused；长任务用心跳续租和 fencing token 防止旧 worker 越权推进水位。
- **M1.3 HybridClassifier**：严格 JSON Schema/Pydantic/标签白名单、provider registry、模型缓存、逐次审计、租约、指数退避和规则 fallback；结构化 CVE 永不调用模型。
- **独立阶段调度**：fetch、normalize、fulltext、classify、event 分别运行；NVD 长窗口抓取不会阻塞规范化积压，慢模型也不阻塞采集。

完整契约、环境变量和边界见 [M1 增量采集与混合分类](docs/m1-data-pipeline.md)。

### M2.0 事件情报基线

- **非破坏式去重**：保留每份原始文档，只写入 `near_dup_of / duplicate_kind / duplicate_score`；同 URL、同标题、同正文和近似标题均可解释。
- **强标识冲突保护**：不同 CVE/GHSA/CNVD 不因共享目录 URL或相似标题被误合并；异常大组件有关系数量熔断保护。
- **稳定事件指纹**：优先使用 `CVE / GHSA / CNVD / arXiv` 强键；无强键时按重复组件主文档生成 fallback event。
- **证据与评分**：`EventDocument` 保留来源等级和关联原因；规则分由来源可信度、强标识、独立来源数和解析质量组成。
- **版本化增量触发**：无过期版本时零扫描；有新增或下游失效时做全局一致性重算，但只写入变化记录。正文、分类或重复主记录变化会自动触发事件重算。
- **可控全量重放**：dedupe 只保留正文指纹/长度并分批更新；cluster 以事务级临时表承接成员关系、按指纹流式聚合和分批 upsert，36 万文档回填时 Python 峰值约 116 MiB（cluster）。
- **事件 API**：`GET /events` 支持主题、类型、证据等级和最低分过滤；`GET /events/{id}` 返回完整证据链。

算法、运维命令、评分公式和当前边界详见 [M2 事件情报](docs/event-intelligence.md)。

### 八类 Connector + Parser

| Connector | 版本 | Parser | 增量机制 |
|---|---|---|---|
| **RSS** | `rss-2` | `rss-default-v1` | ETag/304 + native ID/content hash 过滤与修订检测 |
| **REST** | `rest-2` | `cisa-kev-v1` | CISA 权威快照修订/删除与分页完整性保护 |
| **NVD** | `nvd-modified-v1` | `nvd-v2` | preflight 密度缩窗 + 分片 cursor + 分片完整分页 + 上游状态映射 + 稳态 overlap |
| **AI HOT** | `aihot-selected-v1` | `aihot-v1` | snapshot bootstrap + durable changes cursor + remove + 409 rebuild |
| **GitHub** | `github-2` | `github-releases-v1` | ETag/304 + native ID/content hash 过滤与修订检测 |
| **Web** | `web-1` | `web-article-v1` | ETag/304 + content hash（双重去重） |
| **arXiv** | `arxiv-2` | `arxiv-v1` | native ID/content hash 过滤；ETag/304 作为辅助 |
| **Sitemap** | `sitemap-2` | `sitemap-article-v1` | Newsroom 快速发现 + Sitemap 重叠对账 + 并发正文抓取 |

### 已配置 19 个 endpoint（18 个 active、1 个 retired；17 个 source）

| Endpoint | Connector | 增量 |
|---|---|---|
| openai-news-rss | RSS | ETag/304 + content hash |
| aihot-selected-api | AI HOT | snapshot + changes cursor + remove + 409 rebuild |
| aihot-selected-rss | RSS（retired） | 已由 API 替代；只保留历史与替代关系，不再调度 |
| cisa-kev | REST | 官方 GitHub 镜像 + ETag/304 + 修订/删除检测 |
| nvd-recent | NVD | 120d durable 分片 bootstrap/catch-up + 15min 稳态 overlap |
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

### 增量保证与边界

- AI HOT selected set 是精确镜像：完整 snapshot 后消费 durable changes；remove 和 409 重建均有专用语义。
- NVD 首次覆盖最近 120 天并把进度持久化到分片 cursor；单片失败不会重放已完成分片。120 天以前的全历史仍需独立 backfill。
- CISA KEV 是权威快照，缺失记录会撤回；GitHub 镜像由 CISA 官方仓库维护。
- RSS、arXiv 和普通列表仍受上游保留窗口约束；DB 幂等只能防重复，不能恢复上游没有返回的历史。
- Anthropic 当前每日对账最多处理 50 个、回看 72 小时；达到阈值时应调高配置或引入持久化候选队列。
- “当前文档”统一定义为：本地 `source_status=active`，且上游 `record_status` 不是 `rejected/withdrawn`。API、导出、M2 和 report 默认使用这一视图；历史版本仍保留且可查询。

更多细节见 [M1 实现说明](docs/m1-data-pipeline.md)。

## 两种运行方式

- **Docker Compose（推荐）**：一条命令起 postgres+api+worker。
- **纯宿主机开发**：只容器化 PostgreSQL，应用宿主机 `uv run`。

CLI 常用命令：

```bash
uv run intel sync        # 载入/更新 sources.yaml
uv run intel run-once    # 手动跑完整一轮（含 dedupe + cluster）
uv run intel retry-failed --endpoint <endpoint-id> --limit 500  # 修复 parser 后重放
uv run intel eventize    # 只跑 M2：dedupe + cluster
uv run intel dedupe      # 单独重算去重（--force 可强制）
uv run intel cluster     # 单独重算事件（--force 可强制）
uv run intel stats       # 文档、近重复、事件和证据数量
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

生成可离线打开的当前/历史报告：

```bash
uv run python scripts/gen_report.py report.html        # 默认最多嵌入 30,000 条明细
uv run python scripts/gen_report.py report.html 50000  # 可选：调整浏览器内明细上限
```

报告中的全库统计始终精确；明细按上限保留最新当前记录及最多 5,000 条历史记录，并可按当前/历史、逻辑来源、endpoint、上游状态筛选。

验证 API：

```bash
curl localhost:8000/health
curl localhost:8000/stats
curl "localhost:8000/documents?min_quality=1&limit=5"
curl "localhost:8000/events?topic=cve&min_score=80&limit=5"
curl localhost:8000/events/1
curl localhost:8000/sources
```

## 测试

```bash
uv run pytest -q                                      # 全部离线单元/冒烟/M2 测试
INTEL_RUN_LIVE=1 uv run pytest -m live                  # 真实爬取端到端
uv run ruff check . && uv run pyright                   # 质量门禁
```

当前离线套件覆盖 56 个用例，包括不同 CVE 冲突保护、共享目录 URL、近重复、强键事件、多来源证据和关系膨胀保护；`live` 测试默认跳过，只有显式设置 `INTEL_RUN_LIVE=1` 才访问真实信源。

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

已有数据库升级到本版本时必须应用到 `d7c4b8e1a950_document_visibility_and_retirement`：Compose 重建后由 `worker` 自动执行 `alembic upgrade head`；宿主机部署应在启动新代码前手工运行。迁移增加双轴生命周期、endpoint 替代关系、索引和约束；AI HOT RSS 历史记录被标记为 retired，NVD Rejected/Withdrawn 被标记为非当前证据，均不删除文档。Worker 会自动重建受影响的 M2 派生数据。

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
uv run intel sync               # 载入 sources.yaml（19 个配置项：18 active + 1 retired）
uv run intel run-once           # 完整增量流水线（含事件化）
uv run intel eventize           # 只运行 M2 去重 + 事件聚类
uv run intel stats              # 查看文档/重复/事件/证据数量
uv run intel serve              # 起 API（:8000）
```

## 目录

```
src/ai_security_hot/
  config/       Settings + sources.yaml 加载器（含 egress 字段）
  domain/       枚举 + 领域值对象（RawItem/NormalizedDocument/Checkpoint + known content hashes + 独立内容水位）
  models/       SQLAlchemy 表 + 会话
  connectors/   FetchContext + SSRF + 8 类连接器（RSS/REST/NVD/AI HOT/GitHub/Web/arXiv/Sitemap）
  parsers/      各源 Parser（rss/cisa_kev/nvd/github_releases/web_article/arxiv/sitemap_article）+ normalize
  classify/     RuleClassifier + HybridClassifier + 严格 Schema + taxonomy.yaml
  events/       M2 去重、强键事件聚类、证据等级和规则评分
  storage/      BlobStore + repositories（租约/幂等/阶段推进/事件 upsert/导出）
  pipelines/    fetch/normalize/fulltext/classify/dedupe/cluster stages
  jobs/         独立 fetch/normalize/fulltext/classify/event 调度 + self_check
  api/          FastAPI 只读/运维接口
  cli.py        intel CLI（采集、分类、eventize、查询、导出与运维）
sources/        sources.yaml（19 个配置项：18 active + 1 retired）+ taxonomy.yaml
migrations/     Alembic（initial + classification + 内容版本 + M2 + M1 双轴 lifecycle/endpoint retirement/LLM audit）
tests/          unit / smoke / event intelligence（离线）+ integration（真实爬取）
```

## 后续（M2.1+）

- **事件聚类增强**：加入模型+版本、公司+事故等实体强键；以离线标注集评估 SimHash/语义候选，不在缺少指标时扩大自动合并范围。
- **LLM 事件增强**：M1.3 分类已完成；后续增加中文事件摘要、影响分析和不确定性表达，不覆盖权威字段。
- **日报与投递**：日报冻结/生成/版本化 + 飞书/邮件投递幂等。
- **更多信源**：在当前 18 个 active endpoint 基础上扩展至约 35 个。
- Parser 漂移检测、pgvector 可选增强。均由实际指标触发，不提前引入。
