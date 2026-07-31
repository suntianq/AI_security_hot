# M2 事件质量评测集

`m2_quality_seed.jsonl` 是用于启动人工标注流程的种子集，不冒充已经完成
双人复核的金标数据。每行一个 JSON 对象，支持三种任务：

- `dedupe_pair`：`should_merge` 表示两篇文档是否是重复证据。
- `cluster_pair`：`same_event` 表示两篇文档是否属于同一事件。
- `ranking_event`：`relevant` 与 `first_party` 用于 Top-N 相关率和一手来源覆盖率。

人工复核时应保留 `case_id`，填写 `annotator`、`notes`，并把
`review_status` 从 `seed_needs_review` 改为 `reviewed`。存在分歧时新增独立
裁决记录，不要覆盖原始意见。评测命令会同时报告各种 review 状态的数量，
发布门槛只能使用 `reviewed` 数据另行设定。

```bash
uv run intel evaluate-m2 --dataset evaluation/m2_quality_seed.jsonl --top-n 3
uv run intel evaluate-m2 --dataset evaluation/m2_quality_gold.jsonl --review-status reviewed
```

第一条命令适合开发回归，输出中的 `labels_reviewed_only` 为 `false`。发布门槛
必须显式选择 `--review-status reviewed`，并确认 `dataset_cases` 非零且
`labels_reviewed_only` 为 `true`。

生产评测集不应放入受版权或保密限制的完整正文；保留最小必要标题、摘要、
结构化标识和来源等级即可。

## 语义富化标注

`m2_semantic_annotation_template.json` 是真实数据标注空模板，不是样例答案或金标。每条记录应保留最小必要文档信息，并由标注者填写：

- `relevant` 与 `content_type`；
- 实体的类型、原文 mention、规范名、版本、角色和证据摘录；
- 一篇文档中的 0～N 个原子事件，以及 subject/action/object/time；
- 每个 Claim 的类型、文本、结构化值、证据和支持状态。

生产评测集应另外加入跨文档 `same_event/related_event/different_event` 困难 pair。至少双人独立标注，分歧另建裁决记录；模型影子输出不得回填成 gold label。完整处理边界见 [`docs/semantic-enrichment.md`](../docs/semantic-enrichment.md)。
