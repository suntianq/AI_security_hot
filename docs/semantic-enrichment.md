# M2.2 语义富化与原子事件

> 状态：基础设施和首轮 100 篇真实实验已完成；默认关闭，仅支持影子模式<br>
> 最后更新：2026-07-31<br>
> 任务版本：`document-semantic-v1`<br>
> Prompt 版本：`m2.2-document-semantic-v2`<br>
> 首轮实测：[DeepSeek V4 Flash 100 篇影子实验](./semantic-experiment-2026-07-31.md)

M2.2 在不可变 `Document` 与确定性 M2.1 事件流水线之间增加一个可评测、
可缓存、可回放的语义层。当前阶段只保存派生结果，不修改 `Event`、`near_dup_of` 或现有分类。
离线报告只读展示影子表的运行状态和结果，不会把它提升为正式事件。

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

`execution_version` 由 task、任务版本、Prompt、端点感知 provider namespace 和 model 共同计算；
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

INTEL_LLM_CONFIG_FILE=config/models.yaml
INTEL_LLM_PROFILE=deepseek-v4
INTEL_LLM_API_KEY=...
```

模型 URL、名称和 `json_schema/json_object/prompt_only` 输出模式可在 Profile 中配置，也可用同名 `INTEL_LLM_*` 环境变量覆盖。API Key 只从环境读取。完整说明见 [模型配置与 DeepSeek 接入](./model-configuration.md)。

手动执行前先检查配置并迁移数据库：

```bash
uv run intel llm-config  # 不调用模型、不产生费用
uv run alembic upgrade head

# 默认关闭时只显式运行一小批；仍然只写 shadow 表
uv run intel semantic-enrich --limit 5 --force
```

如果显式设置 `INTEL_SEMANTIC_ENRICHMENT_ENABLED=true`，worker 才会注册独立
语义调度任务。它不阻塞 fetch、normalize、classify 或确定性 M2。

## 5. 实测状态、自动评估和上线门槛

2026-07-31 已用 DeepSeek V4 Flash 对 100 篇真实 current 非 CVE duplicate master 完成首轮实验：98 篇成功、2 篇因本体不接受 `benchmark` 实体而保持 retry。该实验验证了端到端影子落库、证据定位、成本和延迟审计，但样本中 90 篇来自 ITHome，且尚无独立 judge，因此不能解释为全信源质量或生产聚类效果。固定口径和指标见 [实验报告](./semantic-experiment-2026-07-31.md)。

人工双人金标不再阻塞后续开发。当前已具备严格 Schema、证据定位以及运行/用量审计；以下门禁仍需补齐或扩大验证：

- 严格 JSON Schema 和枚举范围校验；
- 实体、原子事件和 Claim 必须携带可在原文精确定位的证据；
- 使用独立 Prompt（必要时独立模型）执行 LLM-as-judge（未实现）；
- 统计证据精确命中率、无证据 Claim 率、结构校验失败率和重试率；
- 记录 token 用量、平均/P95 延迟、每千篇调用量和失败/回退率；
- 下一轮按来源、内容类型和主题分层抽取 300～500 篇，避免最新顺序导致单一来源主导。

LLM-as-judge 结果是代理指标，不命名为真实 F1。人工抽查和 reviewed 样本仍可用于争议案例诊断，但属于可选增强。进入 Embedding 和关系裁决后，强标识冲突仍是不可绕过的硬边界。

## 6. 已完成（2026-08-02 更新）

本轮已把以下能力落地（默认影子，不影响正式数据）：

- **运行稳定化（M2.2.1）**：`DocumentEnrichment`/`SemanticWorkItem` 增加 `batch_id`、`finish_reason`、`usage`、`raw_response`、`max_attempts` 审计列；校验失败做一次有界修复（`repair_once`），达 `max_attempts` 进入终态 `failed`；本体版本化（`ONTO_VERSION`、实体含 `benchmark`）。
- **分层评测（M2.2.2）**：`intel semantic-sample` 按来源平衡抽样（16 源均匀）；`intel semantic-eval` 聚合相关率/证据命中/成本/延迟，按来源与内容类型拆解。98 篇平衡样本：相关率 61.2%、证据精确命中 86%、结构失败 0。
- **关系裁决（M2.3）**：`intel relation-scan` 跨文档原子事件候选召回 + `same/related/different` 确定性裁决，写 `relation_verdicts` 影子表。
- **Claim 合并与提升预览（M2.4）**：`intel claim-merge` 合并同事件 Claims（support/contradict 立场）；`intel event-promote --dry-run` 生成门禁通过的提升预览（默认不写正式 Event）。

## 7. 尚未实现

- **正式提升启用**：`event-promote` 当前默认 dry-run；达到门禁且确认命名空间对齐后显式启用影子→正式 Event 提升。
- 独立 LLM-as-judge（作为代理指标，不命名 F1）。
- 可选的人工 reviewed 困难案例扩充（不作为发布前置条件）。
- Embedding/pgvector 候选召回（M2.3 当前用确定性召回）。
- 新颖性、影响、紧急性和可信度的独立评估。
- 延迟 p50/p95 持久化（需记录每篇 started_at）。

完整的阶段顺序与验收条件统一见 [项目当前状态与后续路线](./current-status.md)。
