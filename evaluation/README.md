# M2 事件质量评测集

项目的当前完成度、首轮 100 篇 DeepSeek 影子实验和后续阶段见 [`docs/current-status.md`](../docs/current-status.md)。这里仅定义确定性回归与可选人工诊断数据的口径。

`m2_quality_seed.jsonl` 是可选人工诊断和确定性回归的种子集，不冒充已经完成
双人复核的金标数据，也不再作为后续开发或发布的前置条件。每行一个 JSON 对象，支持三种任务：

- `dedupe_pair`：`should_merge` 表示两篇文档是否是重复证据。
- `cluster_pair`：`same_event` 表示两篇文档是否属于同一事件。
- `ranking_event`：`relevant` 与 `first_party` 用于 Top-N 相关率和一手来源覆盖率。

如果选择进行人工复核，应保留 `case_id`，填写 `annotator`、`notes`，并把
`review_status` 从 `seed_needs_review` 改为 `reviewed`。存在分歧时新增独立
裁决记录，不要覆盖原始意见。评测命令会同时报告各种 review 状态的数量。

```bash
uv run intel evaluate-m2 --dataset evaluation/m2_quality_seed.jsonl --top-n 3
uv run intel evaluate-m2 --dataset evaluation/m2_quality_gold.jsonl --review-status reviewed
```

第一条命令适合开发回归。第二条仅在可选人工 reviewed 数据存在时使用；此时
应确认 `dataset_cases` 非零且 `labels_reviewed_only` 为 `true`，其指标才表示
相对人工标签的 precision/recall。LLM-as-judge 指标不得冒充人工金标 F1。

生产评测集不应放入受版权或保密限制的完整正文；保留最小必要标题、摘要、
结构化标识和来源等级即可。

## 语义富化标注

`m2_semantic_annotation_template.json` 是真实数据标注空模板，不是样例答案或金标。每条记录应保留最小必要文档信息，并由标注者填写：

- `relevant` 与 `content_type`；
- 实体的类型、原文 mention、规范名、版本、角色和证据摘录；
- 一篇文档中的 0～N 个原子事件，以及 subject/action/object/time；
- 每个 Claim 的类型、文本、结构化值、证据和支持状态。

如需人工诊断，可另外加入跨文档 `same_event/related_event/different_event` 困难 pair，并采用双人独立标注和分歧裁决；该流程是可选增强，模型影子输出不得回填成 gold label。完整处理边界见 [`docs/semantic-enrichment.md`](../docs/semantic-enrichment.md)。

## 当前自动评测边界

- 首轮 100 篇影子实验已经记录 Schema 成功率、证据精确命中、token 和延迟；实验结果见 [`docs/semantic-experiment-2026-07-31.md`](../docs/semantic-experiment-2026-07-31.md)。
- 独立 LLM-as-judge、固定实验 `batch_id` 和按来源/内容类型聚合尚未实现。
- 未经人工 reviewed 的 seed 指标和 LLM judge 分数都不能称为真实 precision/recall/F1。
- 下一轮计划分层抽取 300～500 篇非 CVE 文档，避免最新顺序抽样被单一来源主导。
