# M1 增量采集与混合分类实现说明

> 状态：M1.1、M1.2.x、M1.3 已实现
> 最后更新：2026-07-30
> 配套文档：[系统设计](./system-design.md) · [信源注册表](./source-registry.md) · [M2 事件情报](./event-intelligence.md)

M1 的目标不是“能抓到一批数据”，而是建立一条可长期演进的数据链：源端可以增量、修订、撤回和重建；原始证据不可变；当前状态可查询；慢模型失败时不影响采集；所有分类结果可重放、可审计。

## 1. 完成范围

| 子里程碑 | 状态 | 实现 |
|---|---|---|
| M1.1 | ✅ | taxonomy v2、规则多标签、结构化 CVE 独立标签、分类溯源 |
| M1.2.1 | ✅ | native ID + content hash、不可变 RawItem 内容版本、HTTP validator |
| M1.2.2 | ✅ | NVD 120 天 durable 分片 bootstrap/catch-up、密度缩窗、15 分钟稳态重叠 |
| M1.2.3 | ✅ | Anthropic Newsroom 快速发现 + Sitemap 每日 72 小时对账 |
| M1.2.4 | ✅ | AI HOT selected snapshot + durable changes cursor + remove + 409 自动重建 |
| M1.2.5 | ✅ | CISA 权威快照缺失检测、修订 supersede、撤回/重新上架 |
| M1.2.6 | ✅ | endpoint `state_version`、删除配置自动暂停、限速/重试/退避语义修正 |
| M1.2.7 | ✅ | endpoint `replaced_by` 审计式退役、NVD 上游状态映射、统一当前视图 |
| M1.3 | ✅ | provider registry、严格 Schema、hybrid 分类、缓存、审计、租约、失败回退 |

## 2. 不可变历史与当前投影

系统明确分开“发生过什么”和“现在是什么”：

```text
SourceEndpoint：采集通道生命周期
   active / paused / retired + replacement_endpoint_id
             │
             ▼
RawItem：不可变证据版本
   唯一键 (endpoint_id, native_id, content_hash)
             │
             ▼
SourceRecord：每个上游 ID 的当前投影
   active / withdrawn / retired + current_raw_item_id
             │
             ▼
Document：两个正交状态轴
   source_status = active / superseded / withdrawn / retired
   record_status = published / rejected / withdrawn / unknown
```

规则如下：

- 同一 native ID 内容改变时，新增 RawItem，不覆盖旧证据。
- 新版本成功解析后，旧 Document 才变为 `superseded`；若新版本解析失败，旧版本仍保持 active。
- 撤回会新增 operation=`withdraw` 的 RawItem，并把当前 Document 标为 `withdrawn`。
- 撤回后原样重新上架时复用历史 RawItem，将对应 Document 重新激活，不制造重复证据。
- “当前文档”只由一个共享谓词定义：`source_status=active`，并且 `record_status` 不是 `rejected/withdrawn`。
- API、导出、`report.html`、分类和 M2 都复用该谓词；指定单文档或 `include_inactive=true` 仍能查看历史状态。
- supersede/withdraw/retire 或上游 Rejected/Withdrawn 会清空受影响的分类/去重/聚类派生版本，并使事件物化一致性重建。

## 3. Checkpoint 与幂等

`source_endpoints` 保存 ETag、Last-Modified、opaque cursor、`last_success_at`、内容水位、调度时间、健康状态和租约。Connector 还会从 `source_records` 加载有限的 `native_id → current content_hash` 映射。

写入顺序固定为：

1. 完整获取并校验本轮页面；
2. 提交 RawItem 与 SourceRecord 当前投影；
3. 最后推进 checkpoint；
4. 写 FetchRun 并安排下次运行。

因此在步骤 2 后崩溃只会导致安全重放；DB 唯一键消除重复。游标不会先于证据推进。RawItem 与 SourceRecord 使用固定 500 条分块 UPSERT，既避开 PostgreSQL 参数上限，也让大批 bootstrap 的数据库往返按批次而非按记录增长。

### 3.1 endpoint 状态版本

`EndpointPolicy.state_version` 表达“checkpoint 的含义”。URL、connector 协议、时间窗语义或 cursor 规则变化时必须递增。`intel sync` 发现 URL 或 state_version 改变后，只重置该 endpoint 的 checkpoint，不删除历史数据。

`sources.yaml` 是 endpoint 启停的唯一真相：从 YAML 移除的 endpoint 会在 DB 自动变为 disabled/paused，避免旧配置继续产生幽灵抓取。被正式替代的 endpoint 不应删除配置，而应设为 `enabled: false`、声明 `replaced_by`；`intel sync` 会把 endpoint、SourceRecord 和当前 Document 标为 retired，写入替代原因并使 M2 失效。替代目标必须存在、启用且属于同一逻辑 source，配置加载时即校验。

## 4. 各源增量策略

### 4.1 AI HOT：精确 selected-set 镜像

endpoint `aihot-selected-api` 使用专用 `AIHotConnector`：

1. 无 cursor 时分页读取 `/api/v1/selected/snapshot?fields=default&limit=500`；
2. 校验每页 snapshot cursor 完全一致；
3. 只在最后一页完成后保存第一页给出的同步 cursor；
4. 后续分页消费 `/api/v1/selected/changes?cursor=...&limit=100`；
5. `upsert` 产生内容版本，`remove` 产生撤回证据；
6. changes 返回 409 时自动丢弃旧 cursor 并重建完整 snapshot；
7. snapshot 重建时，将本地 active 但不在新快照中的 ID 标为撤回。

ETag 只在 changes cursor 没有移动、请求 URL 仍相同时复用，避免把 query-bound validator 错用于新 cursor。旧 `aihot-selected-rss` 已以 `replaced_by: aihot-selected-api` 审计式退役：51 条既有 RSS 文档保留为历史，不再抓取、分类或进入 M2；API 是唯一 active 通道。

### 4.2 NVD：modified-time 对账

`nvd-recent` 的 ID 为兼容历史保留，但语义已从“recent publication”升级为 modified-time：

- 首次或 state_version 重置时从 `now - 120 days` 开始，但不把 120 天塞进一个事务；
- `NvdConnector` 先用 `resultsPerPage=1` 读取 `totalResults`，7 天候选若超过 20,000 条就二分缩窗，直至密度有界；
- 每个成功分片保存 `nvd-window-v1:<next-start>` opaque cursor，并在 1 分钟后继续；进程重启只重放当前分片；
- 分片内使用 `resultsPerPage=2000` 和 `totalResults/startIndex` 完整分页；到达 `max_pages` 未读完则该分片失败且不推进 cursor；
- bootstrap/catch-up 追到当前时间后写入 `nvd-steady-v1`，恢复 60 分钟调度；稳态从 `last_success_at - 15 minutes` 到 now；
- 长时间停机也会自动进入同一分片 catch-up，不会构造超过上游限制或内存边界的单次请求；
- 每页提取后立即释放响应体；CVE description/status/analysis 等变化会产生新 RawItem 版本；
- `nvd-v2` Parser 保留 NVD 原始 `vulnStatus`，映射为 published/rejected/withdrawn/unknown。Rejected/Withdrawn 不删除，退出当前视图；若上游后续重新发布，同一 ID 的新版本可重新成为当前证据。

120 天是 NVD API 单个 modified 查询允许的最大范围，但不是合适的单事务大小。更早历史的首次全量导入仍属于独立 backfill。

### 4.3 CISA KEV：权威快照

CISA 使用官方 `cisagov/kev-data` GitHub 镜像的 JSON。该 endpoint 是权威完整快照：

- ETag/304 避免无变化下载；
- 同 CVE 内容变化产生新版本；
- 本轮快照缺失的本地 active CVE 产生 withdraw；
- GitHub 镜像用于规避部分运行环境访问 cisa.gov 时的 403，数据仍由 CISA 官方仓库维护。

### 4.4 Anthropic：低延迟发现 + 有界对账

- 每 2 小时读取服务端渲染的 Newsroom，通常只抓 0～2 个未知页面；
- 每 24 小时读取 Sitemap，以内容水位减 72 小时为 overlap；
- 最多并发 5 个文章请求，并按 endpoint RPM 限制请求启动；
- 内容 hash 识别正文修订，不需要 Playwright。

边界：当前一次 Sitemap 对账最多处理 50 个候选。Anthropic 正常发布频率远低于该阈值；若监控发现 72 小时内候选接近上限，应提高配置或实现持久化分页队列。

### 4.5 RSS、arXiv、Web 与 GitHub

这些 connector 使用可获得的 ETag/Last-Modified/304，并以 native ID/content hash 二次幂等。它们不能突破上游 feed 或列表本身的保留窗口；停机时间超过上游窗口仍可能漏采，必须通过更完整的 API/Sitemap 或独立 backfill 解决。

## 5. HTTP 与失败语义

统一 FetchContext 执行 SSRF 前后双检、代理、超时、响应大小上限、连接复用和 endpoint RPM 限速。

- 仅重试 TransportError、408、425、429 和 5xx；普通 4xx 不重试。
- 429/503 优先遵守 `Retry-After`，否则使用有上限的指数退避。
- AI HOT 409 必须立即交给 connector 做 snapshot rebuild，不能被通用 HTTP 层重复三次。
- endpoint 失败会释放租约，短间隔指数退避；连续失败进入 degraded。
- 解析失败保持 `FAILED`，避免坏记录热循环；修复 parser 或配置后通过 `intel retry-failed` 有界重放。
- fetch 使用默认 15 分钟租约，并每 1/3 租约周期心跳续租；每次领取生成不可猜测的 fencing token，证据落库和 checkpoint 推进前都校验所有权。即使旧 worker 延迟返回，也不能覆盖新 worker 的水位；正常成功或失败会立即释放。

## 6. M1.3 混合分类

### 6.1 规则与模型边界

- 结构化 NVD/CISA CVE 始终由规则输出且只标 `cve`，不会调用 LLM。
- 新闻与论文才使用 `llm / agent / ai_for_security / security_for_ai / system_security`。
- RuleClassifier 仍负责高精度 alias、强事件类型信号和离线 fallback。
- HybridClassifier 对规则标签与模型标签做 taxonomy 顺序下的白名单并集；模型不能创造新标签。
- 文档正文作为不可信数据放进 JSON 输入；system prompt 明确禁止执行正文中的指令。

### 6.2 Provider 扩展点

`ModelProvider` Protocol 隔离分类逻辑与供应商 HTTP。当前提供 `openai-compatible` Chat Completions adapter；`llm.registry.register_provider()` 可注册新 adapter，pipeline 无需修改。

模型输出使用严格 JSON Schema，并再次通过 Pydantic `extra=forbid`、置信度范围和 taxonomy/event-type 白名单校验。任何无效 JSON、未知标签、超时或 HTTP 错误都进入 fallback。

### 6.3 缓存、审计和回退

缓存键：

```text
(task, provider, model, prompt_version, input_hash)
```

- `model_cache` 只保存验证通过的结构化输出；损坏条目会自动删除并重建。
- `model_runs` 为每次 success/cache_hit/fallback 保存 document、模型、prompt、输入 hash、耗时、usage 和截断错误；不保存 API key。
- fallback 写入规则结果、错误和下一次重试时间，采用 1 分钟起步、最长 24 小时的指数退避。
- `classify_lease_until` + opaque token + `FOR UPDATE SKIP LOCKED` 认领；慢模型批次会持续 heartbeat 剩余文档，所有结果/审计写入都校验 fencing token，防止过期 worker 重复收费或覆盖新结果。
- `classification_batch_size` 给每个 tick 设置自然的调用上限；默认 25。

### 6.4 全文与分类一致性

`RawItem.stage=DONE` 是分类入口。需要全文二次抓取的 endpoint 先停在 NORMALIZED；全文完成或明确跳过后才进入 DONE。非全文 endpoint 在 normalize 后直接 DONE。全文变化会清空旧分类和 M2 派生版本，避免基于摘要的缓存覆盖最终正文。

## 7. 独立调度

Worker 将各个速度域拆成互相独立的 APScheduler job：

| Job | 默认间隔 | 内容 |
|---|---:|---|
| fetch | 60 秒 | 领取到期 endpoint 并抓取；长 NVD 窗口只占用本 job |
| normalize | 10 秒 | 默认 2,000 条；savepoint 隔离坏记录 |
| fulltext | 30 秒 | 默认 20 条静态网页正文补全 |
| classify | 30 秒 | rules 默认 2,000；hybrid 默认 25，分别限流 |
| event | 60 秒 | dedupe → cluster |
| self-check | 600 秒 | 健康、积压与双轴生命周期分布 |

每个 job `max_instances=1`，但不同 job 可以并行。NVD 公共 API 的长分页不会再饿死 normalize/fulltext；慢 LLM、模型超时或事件全局重算也不会阻塞采集。`ingest_tick()` 仅作为手工兼容入口，顺序调用前三个阶段，不再作为常驻 Worker 的调度单元。Normalize 对一批记录使用外层事务并以 savepoint 隔离坏记录；默认规则分类也按批提交，避免大批回填时逐条事务的开销。

定时 `event` 在 M1 待 normalize/fulltext/classify 的总积压超过
`INTEL_EVENT_BACKLOG_THRESHOLD`（默认 1000）时主动延后，避免 NVD 大批回填期间
每分钟重复扫描不断增长的全量文档。积压降至阈值后会自动恢复；设为 `0` 可关闭门控。
手工执行 `intel eventize --force` 不经过这个调度门控，仍可用于运维验收。

## 8. 配置

默认配置完全离线，不调用模型：

```env
INTEL_CLASSIFICATION_MODE=rule
```

启用 hybrid：

```env
INTEL_CLASSIFICATION_MODE=hybrid
INTEL_LLM_PROVIDER=openai-compatible
INTEL_LLM_BASE_URL=https://api.openai.com/v1
INTEL_LLM_API_KEY=...
INTEL_LLM_MODEL=...
INTEL_NORMALIZE_INTERVAL_SECONDS=10
INTEL_NORMALIZE_BATCH_SIZE=2000
INTEL_FULLTEXT_INTERVAL_SECONDS=30
INTEL_FULLTEXT_BATCH_SIZE=20
INTEL_RULE_CLASSIFICATION_BATCH_SIZE=2000
INTEL_CLASSIFICATION_BATCH_SIZE=25
INTEL_CLASSIFICATION_INTERVAL_SECONDS=30
INTEL_EVENT_INTERVAL_SECONDS=60
INTEL_EVENT_BACKLOG_THRESHOLD=1000
INTEL_LEASE_SECONDS=900
```

若 hybrid 缺少 provider/model/key，worker 自动用 rules 继续处理，`self-check` 和 classify stats 会报告 config_fallback/config_errors。

## 9. 运维与验证

```bash
uv run alembic upgrade head
uv run intel sync
uv run intel fetch --limit 5
uv run intel normalize
# parser/配置修复后，受控重放确定性解析失败项
uv run intel retry-failed --endpoint <endpoint-id> --limit 500
uv run intel classify
uv run intel eventize
uv run intel self-check
uv run python scripts/gen_report.py report.html  # 生成当前/历史离线报告

uv run pytest -q
uv run ruff check src tests migrations
uv run pyright
```

关注 API：

- `/sources`：endpoint 状态、state_version、replacement endpoint 与 retired_at；
- `/documents`：默认 current；`include_inactive=true` 可看历史，也可按 logical source、endpoint 和 record_status 过滤；
- `/stats`：current 总数、source_status、record_status、endpoint 与 model run 状态分布；
- `/ops/self-check`：源健康、FAILED 数量、所有处理中阶段的过期租约、M2 积压、分类配置、重试、24 小时 fallback，以及 current/source_status/record_status 数据质量分布。

## 10. 明确边界

M1 已完成可重放的增量与分类基础设施，但以下不是 M1 的保证：

- RSS/feed 上游没有提供的历史无法凭空恢复；
- NVD 120 天以前的初始全历史需要单独 backfill；
- Anthropic 对账候选仍有配置上限；
- 当前没有真实 LLM 凭据，因此 CI 使用 fake provider 验证 Schema、白名单、CVE bypass 和 fallback 契约；生产启用 hybrid 后应先做小批量成本/质量验收；
- M1.3 只做分类，中文事件摘要、影响分析和 Claim/Evidence 生成属于后续里程碑。
