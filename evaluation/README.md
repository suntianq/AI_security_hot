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
