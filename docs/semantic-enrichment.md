# M2.2 语义富化与原子事件

> 状态：基础设施已实现，默认关闭，仅支持影子模式<br>
> 最后更新：2026-07-31<br>
> 任务版本：`document-semantic-v1`<br>
> Prompt 版本：`m2.2-document-semantic-v1`

M2.2 在不可变 `Document` 与确定性 M2.1 事件流水线之间增加一个可评测、
可缓存、可回放的语义层。当前阶段只保存派生结果，不修改 `Event`、
`near_dup_of`、现有分类或报告。

## 1. 当前处理链

```text
current non-CVE Document
  → 仅选择 dedupe master
  → durable SemanticWorkItem + fencing lease
  → deterministic model input/cache key
  → strict Pydantic/JSON Schema validation
  → DocumentEnrichment
      ├─ SemanticEntity + EntityMention
      └─ AtomicEvent
          └─ ExtractedClaim
```

结构化 CVE 不进入该任务。普通新闻/论文先经过 M2.1 低成本去重，只对当前
duplicate master 调用模型，避免对转载全文重复付费。正文变化会产生新的
不可变 Document，因此输入 hash、缓存和富化结果仍可完整追踪。

## 2. 模型输出契约

`DocumentSemanticOutput` 使用 `extra=forbid`，模型必须输出：

- 是否包含值得进入 AI/安全情报系统的事实及置信度。
- `news/research/release/advisory/incident/opinion/other` 内容类型。
- 文档摘要。
- 文档级实体。
- 0～12 个原子事件，每个事件表达一个 subject-action-object occurrence。
- 每个事件的实体、结构化 Claim、置信度和逐字证据摘录。

事件、实体和 Claim 没有原文证据不得持久化为可信结论。系统只接受精确证据
定位；模型摘录无法在标题或正文中原样找到时，仍保留摘录用于审计，但将位置
记为 `unknown`，后续质量门禁可以拒绝。

## 3. 表与职责

| 表 | 作用 |
|---|---|
| `semantic_work_items` | 通用 `subject_type/subject_id/task/execution_version` 租约队列 |
| `document_enrichments` | 一次通过 Schema 校验的不可变完整输出 |
| `semantic_entities` | 保守规范化后的实体身份 |
| `entity_mentions` | 实体到原始 Document/AtomicEvent/证据位置的关联 |
| `atomic_events` | 从一篇文档拆出的独立事件候选 |
| `extracted_claims` | 聚类前的结构化 Claim 和原文证据 |
| `model_cache` | 复用现有 task/provider/model/prompt/input hash 缓存 |
| `model_runs` | 复用现有逐文档调用、缓存命中、失败和用量审计 |

`execution_version` 由 task、任务版本、Prompt、provider 和 model 共同计算；
更换任何一项都会生成独立待办和结果，不覆盖旧数据。

## 4. 安全和成本边界

- `INTEL_SEMANTIC_ENRICHMENT_ENABLED` 默认 `false`。
- 当前只接受 `shadow`，不存在可配置的自动生效模式。
- 缺少 provider、API key 或 model 时不领取任务，返回
  `configuration_error`。
- 每轮默认最多 5 篇；顺序优先最新当前文档。
- 使用独立持久租约、fencing token、指数退避和现有模型缓存。
- 模型输出不能修改强标识、来源、发布时间、生命周期或绕过 M2 强冲突。

配置：

```dotenv
INTEL_SEMANTIC_ENRICHMENT_ENABLED=false
INTEL_SEMANTIC_ENRICHMENT_MODE=shadow
INTEL_SEMANTIC_ENRICHMENT_INTERVAL_SECONDS=120
INTEL_SEMANTIC_ENRICHMENT_BATCH_SIZE=5
INTEL_SEMANTIC_ENRICHMENT_LEASE_SECONDS=600
INTEL_SEMANTIC_LLM_MAX_OUTPUT_TOKENS=2500

INTEL_LLM_PROVIDER=openai-compatible
INTEL_LLM_BASE_URL=https://api.openai.com/v1
INTEL_LLM_API_KEY=...
INTEL_LLM_MODEL=...
```

手动执行前先迁移数据库：

```bash
uv run alembic upgrade head

# 默认关闭时只显式运行一小批；仍然只写 shadow 表
uv run intel semantic-enrich --limit 5 --force
```

如果显式设置 `INTEL_SEMANTIC_ENRICHMENT_ENABLED=true`，worker 才会注册独立
语义调度任务。它不阻塞 fetch、normalize、classify 或确定性 M2。

## 5. 评测和上线门槛

仓库只提供标注模板，不把模型自生成内容冒充金标。下一阶段需要从真实数据中
抽取 300～500 篇新闻/论文，双人标注：

- relevance/content type；
- 实体提及、规范名、版本和角色；
- 一篇文章的原子事件数量及边界；
- subject/action/object/time；
- Claim、证据摘录和是否受原文支持；
- 跨文档 same/related/different event 困难样本。

影子输出至少需要报告 entity F1、原子事件边界 precision/recall、证据精确命中
率、无证据 Claim 率、每千篇成本、P95 延迟和失败/回退率。达到约定门槛后，
才能进入 Embedding 候选召回和 LLM 事件关系判断；即使上线，强标识冲突仍是
不可绕过的硬边界。

## 6. 尚未实现

- 真实人工金标集及双人裁决工具。
- Embedding/pgvector 候选召回。
- `same_event/related_event/different_event` 关系裁决。
- AtomicEvent 到生产 Event 的受控提升。
- 跨证据 Claim 支持、反驳和时间线合并。
- 新颖性、影响、紧急性和可信度的独立评估。
- 按自然日返回稳定热点快照的 M2 API。
