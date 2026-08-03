# AI × Security 情报后端

把 AI/安全情报的采集能力融为一个稳定、可扩展的后端。基于 `docs/` 设计文档
（[当前状态与路线](docs/current-status.md) · [MVP 设计](docs/mvp-design.md) · [整体蓝图](docs/system-design.md) ·
[信源注册表](docs/source-registry.md) · [M1 增量与分类](docs/m1-data-pipeline.md) · [M2 事件情报](docs/event-intelligence.md) · [模型与 DeepSeek 配置](docs/model-configuration.md) · [部署与冷启动](docs/deployment.md)）实现的
**M0 工程骨架 + M1 结构化采集 + M2.1 事件情报底座 + M2.2 影子语义富化 + M2.3 增量关系裁决 + M2.4 可回滚正式提升 + 冻结热点快照 + NVD 隔离**。

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
- **NVD modified-time**：120 天 bootstrap/长停机 catch-up 使用动态缩窗和 durable cursor 分批推进；稳态从 `last_success_at - 15min` 重叠抓取；`min_cve_year` 按 CVE 编号年份过滤（当前只保留 2026 起的 CVE，避免历史漏洞淹没资讯）；Rejected/Withdrawn CVE 保留为历史证据但退出当前视图。
- **CISA 权威快照**：官方 GitHub 镜像 + ETag/304 + 修订与删除检测。
- **Anthropic 双通道**：Newsroom 快速发现 + 每日 Sitemap 72 小时重叠对账。
- **状态版本和配置收敛**：endpoint `state_version` 控制 checkpoint 重建；`replaced_by` 可声明替代关系并审计式退役旧 endpoint；YAML 删除的 endpoint 自动 paused；长任务用心跳续租和 fencing token 防止旧 worker 越权推进水位。
- **M1.3 HybridClassifier**：严格 JSON Schema/Pydantic/标签白名单、provider registry、模型缓存、逐次审计、租约、指数退避和规则 fallback；结构化 CVE 永不调用模型。
- **独立阶段调度**：fetch、normalize、fulltext、classify、event 分别运行；NVD 长窗口抓取不会阻塞规范化积压，慢模型也不阻塞采集。

完整契约、环境变量和边界见 [M1 增量采集与混合分类](docs/m1-data-pipeline.md)。

### M2.1 可扩展事件情报

- **非破坏式去重**：保留每份原始文档，只写入 `near_dup_of / duplicate_kind / duplicate_score`；同 URL、同标题、同正文和近似标题均可解释。
- **强标识冲突保护**：不同 CVE/GHSA/CNVD 不因共享目录 URL或相似标题被误合并；异常大组件有关系数量熔断保护。
- **稳定组件与事件身份**：持久化 `DuplicateComponent`；事件强键覆盖 `CVE / GHSA / CNVD / arXiv / GitHub release / 模型或包版本 / 事故 / campaign`，无强键时生成 fallback event。
- **证据与评分**：`EventDocument` 保留来源等级和关联原因；规则分由来源可信度、强标识、独立来源数和解析质量组成。
- **真正局部增量**：URL/title/content hash、强身份和 SimHash/MinHash blocking 持久化；正文、分类、撤回、退役只写 durable work queue，去重仅重算 seed、一跳候选及其完整旧组件，事件聚类再沿强事件身份局部闭合。
- **候选安全边界**：SimHash/MinHash 只生成候选；不同漏洞、发布版本、事故等强身份冲突硬阻断。低置信 pair 进入人工复核队列，裁决触发局部重算，但批准也不能越过硬冲突。
- **事件事实与时间线**：物化 `EventVersion / Claim / ClaimEvidence`；版本快照记录事件、证据、事实及 diff，Claim 可表达 confirmed/disputed 状态和 support/contradict/context 证据。
- **质量评测与审计**：JSONL 评测器输出 dedupe/cluster precision、recall、错误合并率、Top-N 相关率和一手来源覆盖率；`M2Run` 记录增量/replay 的版本、候选量、影响量和错误。
- **可控全量重放**：正常路径不再全局重算；算法升级或灾难恢复时显式 `replay-m2`，仍按有界局部批次遍历全库。
- **事件 API**：`GET /events` 支持主题、类型、证据等级和最低分过滤；`GET /events/{id}` 返回完整证据链。

算法、运维命令、评分公式和当前边界详见 [M2 事件情报](docs/event-intelligence.md)。

### NVD/KEV 单独隔离 + 事件分类

- **NVD + CISA KEV 完全隔离**：结构化漏洞源按自身 `cve-nvd:` 命名空间去重/聚类，不与新闻交叉；事件打 `category` 标签（`vuln_db` / `general`）。
- **旧事件清理**：隔离迁移后旧的 `cve:` 事件通过 EventVersion supersede 保留历史，退出当前视图（修复"事件数 > 文档数"的口径问题）。
- **多 CVE fan-out 修复**：NVD 解析器只保留记录自身 CVE 身份，不再从描述正文扫描次要 CVE/GHSA/CNVD。
- **冻结日期热点 API**：worker 为当天和前一天生成不可变 revision；`GET /v1/daily-hotspots?date&tz&category&as_of` 读取指定时点前已冻结的去重热点，general/vuln_db 可分别筛选。

### M2.2 影子语义富化基础 + M2.3/M2.4 语义情报

- **严格语义契约**：相关性、通用实体、0～N 个原子事件和 Claim 均通过严格 JSON Schema/Pydantic 校验；实体类型含 `benchmark`，本体版本 `semantic-onto-v1`。
- **运行稳定化（M2.2.1）**：失败响应审计（raw_response/finish_reason/usage）、有界结构修复（校验失败重试一次）、batch_id 可重放、`max_attempts` 终止态。
- **分层评测（M2.2.2）**：`intel semantic-sample` 按来源平衡抽样（16 源均匀）、`intel semantic-eval` 聚合相关率/证据命中/成本，按来源与内容类型拆解。
- **关系裁决与稳定组件（M2.3）**：`intel relation-scan` 通过游标、强实体 blocking 和有界持久队列写入版本化裁决；same-event 关系再由 generation-fenced 局部队列物化成稳定 component ID、revision 和历史 membership，worker 自动运行。
- **Embedding 候选召回（M2.3.1）**：独立 `config/embeddings.yaml` 与 `INTEL_EMBEDDING_*`；持久向量和游标只在当前非 CVE 原子事件的有界时间窗内召回。vector-only=`recalled`、强冲突=`blocked`，均不会直接合并。
- **Claim 合并与正式提升（M2.4）**：只读取完整的当前持久组件；正式事件使用稳定 component key，每个 component revision 产生独立 promotion 审计。预览从 AtomicEvent/Document 推导类型、主题和时间；显式 `--apply` 才写正式事件。
- **安全默认值**：M2.2 模型调用默认关闭且只写影子表；正式提升默认只预览，worker 不会自动执行 `--apply`。
- **可切换模型 Profile**：M1.3 与 M2.2 共用 `config/models.yaml`；环境变量优先覆盖 URL/模型，API Key 只允许从环境注入；兼容 `json_schema/json_object/prompt_only`。

98 篇平衡样本评测：相关率 61.2%、证据精确命中 86%、结构失败 0。结果默认只写影子表，未参与正式事件。当前完成度与推荐实施顺序见 [项目当前状态与后续路线](docs/current-status.md)，接入 DeepSeek 或私有网关见 [模型配置](docs/model-configuration.md)。

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
uv run intel m2-index --all                            # 回填 v3 持久化候选索引
uv run intel m2-token-stats                            # 修复/核对 blocking token 桶计数
uv run intel replay-m2 --max-batches 10000             # 显式完整算法重放
uv run intel replay-m2 --resume --max-batches 10000    # 失败修复后从已有积压续跑，不重置已完成批次
uv run intel evaluate-m2 --dataset evaluation/m2_quality_seed.jsonl
uv run intel llm-config                                  # 只校验最终模型配置，不发起 API 调用
uv run intel semantic-enrich --limit 5 --force            # 显式运行一批影子语义富化（会调用已配置模型）
uv run intel semantic-sample --size 100 --batch m2.2.2-eval-v1  # 分层平衡抽样（16 源）
uv run intel semantic-eval --batch m2.2.2-eval-v1         # 语义评测聚合（相关率/证据/成本）
uv run intel relation-scan --limit 100                    # M2.3 有界增量关系队列/裁决
uv run intel claim-merge --limit 200                      # M2.4 Claim 合并（影子）
uv run intel event-promote --limit 50                 # 默认只预览
uv run intel event-promote --limit 50 --apply         # 显式正式提升
uv run intel event-promotion-rollback --promotion-id 123
uv run intel supersede-stale-vuln --limit 2000            # 清理隔离前旧 cve: 事件
uv run intel m2-reviews --status pending --limit 50    # 查看低置信候选
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

报告中的全库统计始终精确；文档明细按上限保留最新当前记录及最多 5,000 条历史记录。页面同时展示能力地图、事件/证据/版本/Claim、M2 候选复核和运行审计、语义影子状态、稳定关系组件/队列/promotion revision、Embedding 覆盖、向量候选及信源健康；事件样本最多 4,000 条，并优先保留 75% 非 CVE 热点。

验证 API。健康探针无需认证；读取接口和 `/ops/*` 分别使用只读、管理员 Token：

```bash
curl localhost:8000/health/live
curl localhost:8000/health/ready
TOKEN=change-me-to-a-real-read-token
curl -H "Authorization: Bearer $TOKEN" localhost:8000/stats
curl -H "Authorization: Bearer $TOKEN" "localhost:8000/documents?min_quality=1&limit=5"
curl -H "Authorization: Bearer $TOKEN" "localhost:8000/events?topic=cve&min_score=80&limit=5"
curl -H "Authorization: Bearer $TOKEN" localhost:8000/events/1
curl -H "Authorization: Bearer $TOKEN" localhost:8000/sources
```

## 测试

```bash
uv run pytest -m "not live" -q                       # 离线 + PostgreSQL 集成测试
INTEL_RUN_LIVE=1 uv run pytest -m live                  # 真实爬取端到端
uv run ruff check . && uv run pyright                   # 质量门禁
uv run alembic upgrade head && uv run alembic check     # 迁移 + ORM 元数据漂移门禁
```

测试覆盖 M1 增量语义、不同强身份冲突、持久化签名、高频候选桶保护、SimHash/MinHash 候选、人工批准、局部退役重选主、EventVersion/Claim/Evidence、语义 Schema、关系裁决、提升门禁、API 分权认证和 PostgreSQL 事务落库。数据库集成测试需要已迁移的 `INTEL_DATABASE_URL`；真实信源测试只在手工触发的 `Live source checks` 工作流或显式设置 `INTEL_RUN_LIVE=1` 时运行，避免外部网站波动阻断每次提交。

## 部署（Docker Compose）

```bash
cp .env.example .env
# 填写数据库密码、只读/管理员 Token 和可选 LLM Key
export INTEL_BUILD_SHA="$(git rev-parse --short HEAD)"
docker compose build --pull
docker compose up -d
docker compose ps -a
curl localhost:8000/health/live
curl localhost:8000/health/ready
```

`postgres` 健康后，独立的一次性 `migrate` 服务执行 `alembic upgrade head`
和 `intel sync`；只有它成功退出后，API 与 worker 才会启动。三个应用服务使用
同一个带构建 SHA 的镜像，API/worker 不再隐式修改 schema。worker heartbeat、
API liveness/readiness 和 `restart: unless-stopped` 用于发现并恢复进程故障。

默认 PostgreSQL 和 API 只绑定宿主机 `127.0.0.1`。读取接口使用
`INTEL_API_TOKEN`，`/ops/*` 使用独立的 `INTEL_ADMIN_API_TOKEN`；两者均
未配置时 fail-closed。完整的 Linux/macOS 冷启动、升级和验收步骤见
[部署与冷启动](docs/deployment.md)。

动态网页兜底目前尚未实现。Compose 中的 `playwright` Profile 只是预留运行位，当前镜像不包含 Playwright 浏览器和 Connector，不应作为生产抓取能力启用。

### 代理 / 国内海外混合部署

每个 endpoint 的 `egress.route` 决定走直连还是代理池；代理地址来自环境变量（`.env`），不进代码/日志：

- 国内 VM 抓海外源 → 设 `INTEL_PROXY_POOL_GLOBAL`
- 海外 VM 抓国内源 → 设 `INTEL_PROXY_POOL_CN`
- 未配代理池时自动回退直连。

Docker 容器里的 `127.0.0.1` 指向容器自身。Linux 可在项目 Docker 网桥
gateway 上建立受限 TCP bridge；macOS Docker Desktop 使用
`host.docker.internal`：

```dotenv
# Linux（地址按实际项目网桥调整）
INTEL_PROXY_POOL_GLOBAL=http://172.18.0.1:17897
# macOS
INTEL_PROXY_POOL_GLOBAL=http://host.docker.internal:7897
```

bridge 或宿主代理只应允许可信 Docker 网络访问，不要直接监听公网。修改
`.env` 后需重建 worker，使新的代理变量进入容器。

### 部署踩坑速查

| 现象 | 原因 | 解决 |
|---|---|---|
| `postgres` 启动 exit 1 | postgres:18 改用 `/var/lib/postgresql` | compose volume 挂 `/var/lib/postgresql` |
| 构建失败 `Readme file does not exist` | Dockerfile 未 COPY `README.md` | Dockerfile 已 `COPY README.md` |
| `migrate` 非 0 退出、API/worker 未启动 | schema 或配置同步失败 | 查看 migrate 日志，修复后重新 `docker compose up -d` |
| 依赖安装极慢 | 容器内走代理拉 PyPI 慢 | 已配清华镜像源 |
| 海外源报 `Network is unreachable` | 宿主代理只监听 loopback，容器不可达 | 仅在 Docker gateway 建受限 bridge，并配置对应 proxy pool |

## 纯宿主机开发

```bash
uv sync
docker compose up -d postgres
export INTEL_DATABASE_URL=postgresql+psycopg://intel:intel@localhost:5433/intel

uv run alembic upgrade head     # 迁移
uv run intel sync               # 载入 sources.yaml（19 个配置项：18 active + 1 retired）
uv run intel run-once           # 完整增量流水线（含事件化）
uv run intel eventize           # 只运行 M2 去重 + 事件聚类
uv run intel stats              # 查看文档/重复/事件/证据数量
uv run intel serve              # 起 API（:8000）
```

> 容器 Postgres 宿主机端口默认 5432，可由 `POSTGRES_HOST_PORT` 覆盖；本部署使用 5433。

## 目录

```
src/ai_security_hot/
  config/       Settings + sources.yaml 加载器（含 egress 字段）
  domain/       枚举 + 领域值对象 + STRUCTURED_VULN_ENDPOINTS
  models/       SQLAlchemy 表 + 会话（含 semantic_tables：原子事件/关系裁决/提升）
  connectors/   FetchContext + SSRF + 8 类连接器（RSS/REST/NVD/AI HOT/GitHub/Web/arXiv/Sitemap）
  parsers/      各源 Parser（rss/cisa_kev/nvd/github_releases/web_article/arxiv/sitemap_article）+ normalize
  classify/     RuleClassifier + HybridClassifier + 严格 Schema + taxonomy.yaml
  events/       M2 去重/事件规则、持久化签名、质量评测和候选判断
  semantic/     语义任务、实体/原子事件抽取、抽样、评测、持久关系队列、Claim 合并、正式提升/回滚
  storage/      BlobStore + repositories + event_repository + semantic_repository
  pipelines/    fetch/normalize/fulltext/classify/semantic/dedupe/cluster stages
  jobs/         独立采集/分类/事件/语义关系/冻结快照调度 + self_check
  api/          FastAPI 只读/运维接口（含 /v1/daily-hotspots）
  cli.py        intel CLI（采集、分类、事件、语义、关系、提升、导出与运维）
config/         models.yaml（DeepSeek/OpenAI-compatible 非敏感 Profile）
sources/        sources.yaml（19 个配置项：18 active + 1 retired）+ taxonomy.yaml
migrations/     Alembic（initial + M1 + M2.0/M2.1/M2.2/M2.2.1/M2.3/M2.4 lifecycle）
evaluation/     M2 去重/语义样本（m2.2.2-eval-v1）+ 离线诊断指标
tests/          unit / smoke / event intelligence + semantic + PostgreSQL integration + opt-in live crawl
```

## 后续（M2.5+）

- **Embedding/pgvector 召回**：可移植的有界精确向量召回已完成并默认关闭；先校准阈值/成本/延迟，数据规模需要时再增加 pgvector ANN。
- **LLM-as-judge**：M2.2.2 当前用规则聚合；独立 judge 作为代理指标（不命名 F1）。
- **延迟 p50/p95**：语义评测当前为 null，需持久化每篇 started_at。
- **日报与投递**：冻结快照已完成；后续增加文案版本、更正记录和飞书/邮件投递幂等。
- **更多信源**：在当前 active endpoint 基础上扩展至约 35 个。
- Parser 漂移检测。均由实际指标触发，不提前引入。

详细完成度、已知问题、启动条件和阶段验收标准统一维护在 [项目当前状态与后续路线](docs/current-status.md)。


### Frozen daily hotspot snapshots

Generate a revision after clustering/promotion, then serve it immutably:

```bash
uv run intel daily-snapshot --date 2026-08-03 --tz Asia/Shanghai
curl "http://localhost:8000/v1/daily-hotspots?date=2026-08-03&tz=Asia/Shanghai&as_of=2026-08-03T23:59:59%2B08:00"
```

A missing snapshot returns 404 intentionally; run the snapshot command (or schedule it) rather than silently reading mutable current event state.
