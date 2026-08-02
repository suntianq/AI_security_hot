# M2.1 可扩展事件情报实现说明

> 状态：M2.1 基础能力已实现；M2.2 基础设施及首轮 100 篇影子实验已完成；按日期返回热点的业务 API 尚未开始<br>
> 最后更新：2026-07-31<br>
> 算法版本：`signature-v3` / `dedupe-v2` / `cluster-v2`

M2.1 将 M2.0 的“出现变化就重算整个 current corpus”改为持久化候选索引和局部图重算。目标仍然是保守合并：可以把低置信内容暂时拆开，但不能仅凭相似度把不同漏洞、发布或事故合并。

## 1. 数据流与边界

```text
Document lifecycle/classification change
        ↓ durable M2WorkItem
DocumentSignature + DocumentIdentity + DocumentBlockToken
        ↓ bounded candidate/component closure
DuplicateComponent + near_dup_of
        ↓ affected event-key closure
Event + EventDocument
        ↓ material change
EventVersion + Claim + ClaimEvidence
```

M2 只把以下文档作为当前证据：

```text
source_status = active
AND record_status NOT IN (rejected, withdrawn)
```

退役、撤回和 superseded 文档不删除，原始 RawItem、旧组件关系、旧事件版本和证据仍可审计。正常增量路径不会全局清空派生状态；只有运维人员显式执行完整 replay 才会请求全量重放。

## 2. 自动质量门禁与可选评测样本

人工双人金标集不再作为后续开发和发布的前置条件。当前已经运行的自动门禁包括强身份冲突规则、严格输出 Schema、原文证据精确定位、影子隔离，以及成本、延迟和失败率审计；独立 LLM-as-judge 仍属于下一阶段。LLM 生成的标签和未来的 judge 分数都只是代理指标，不能表述为真实 precision/recall 或 F1。

`evaluation/m2_quality_seed.jsonl` 保留三类 JSONL 确定性回归样本：

- `dedupe_pair`：两篇文档是否是重复证据。
- `cluster_pair`：两篇文档是否属于同一事件。
- `ranking_event`：Top-N 是否相关、是否一手来源。

```bash
uv run intel evaluate-m2 --dataset evaluation/m2_quality_seed.jsonl --top-n 3
uv run intel evaluate-m2 --dataset evaluation/m2_quality_gold.jsonl --review-status reviewed
```

人工 reviewed 数据和分歧裁决仍可用于困难案例诊断，但属于可选增强；只有确实使用人工 reviewed 数据时，命令输出的 precision/recall 才能解释为相对人工标签的指标。

## 3. 持久化索引

| 表 | 作用 |
|---|---|
| `document_signatures` | 版本化 URL/title/content SHA-256、64-bit SimHash、16-value MinHash及 active 状态 |
| `document_identities` | CVE/GHSA/CNVD/arXiv、release、事故、campaign 和实体反向索引 |
| `document_block_tokens / document_block_token_stats` | 有界标题/摘要 token、SimHash/MinHash band，以及可增量维护的 current 文档桶计数 |
| `duplicate_components` | 与当前 master 解耦的稳定重复组件 ID |
| `m2_work_items` | lifecycle/classification 变化产生的 durable dedupe/cluster 待办 |
| `m2_runs` | 增量/replay 的版本、触发源、输入量、候选量、影响量、结果和错误审计 |

每份文档最多写入 24 个标题 token、8 个摘要 token 和 8 个 LSH band；`document_block_token_stats` 持久化每个桶的 current 文档数，签名变化时只刷新受影响 token，候选查询不再重复扫描全局 token 表。高于 100 份当前文档的普通 token、LSH 或 exact hash 桶不生成候选。URL fragment 默认忽略，但当 fragment 就是 CVE 等强记录标识时会保留，避免快照目录中的不同记录落入同一个 URL 桶。候选或组件闭包超过配置上限时事务失败并保留待办，不会截断结果后错误地标记为完成。

## 4. 局部增量算法

### 4.1 去重

1. 从 `m2_work_items` 和版本过期文档中领取 seed。
2. 刷新 seed 的签名；退役文档的签名标记 inactive 并移除 identity/token。
3. 通过精确 hash、LSH/token 和已批准人工候选查找一跳候选；去重阶段不会递归遍历弱相似边，也不使用宽泛实体 identity 直接合并。
4. 完整纳入 seed 和一跳候选原有的 `DuplicateComponent` 成员，保证拆分、退役和主证据重选不会遗漏旧组件成员。
5. 只在这个有界局部集合中重算去重，保持未受影响组件不变；候选自己的其他关系由其版本待办单独处理。
6. 合并或分裂时尽量保留稳定 component ID；旧 master 退役时在同一组件局部重选主。
7. 只有去重结果实际变化的 current 文档才使 cluster 版本失效。

自动合并仍限于可解释规则：相同 URL、标准化标题、正文 hash 和 RapidFuzz 高阈值近标题。SimHash/MinHash 只扩大候选召回，不直接自动合并。

### 4.2 事件

Cluster 从受影响组件出发，沿 `event_key=true` 的强身份反向索引扩展完整事件证据图，只重建可达事件。旧指纹失去当前证据时标记 `superseded`；未受影响事件不会改版本。

普通增量的工作量与受影响候选/组件/事件图相关，不再与全部 36 万份文档线性绑定。显式 `replay-m2` 仍会按局部批次遍历全库，用于算法升级和灾难恢复。

## 5. 强身份、相似候选与冲突规则

### 5.1 事件强键

| 输入 | Event fingerprint | 说明 |
|---|---|---|
| CVE/GHSA/CNVD | `cve:CVE-...` 等 | 漏洞事件 |
| arXiv | `arxiv:YYMM.NNNNN` | 忽略论文 `v1/v2` |
| GitHub release URL | `github_release:owner@repo@tag` | 不同 tag 冲突 |
| 模型 + 版本 | `model_release:model@version` | 仅 `event_type=release` 时为事件键 |
| 软件包 + 版本 | `package_release:name@version` | 仅 release 时为事件键 |
| 公司 + 产品 + 事故 | `incident:company@product@incident` | 依赖结构化 entities |
| 攻击组织 + campaign | `campaign:actor@campaign` | 依赖结构化 entities |
| 无强键 | `document:<master_document_id>` | fallback event |

repository、company/model、受影响 AI 组件等实体也进入候选反向索引，但普通“提及某模型/版本”不会被误当作同一发布事件。

### 5.2 硬阻断

同类强身份互斥时禁止合并，包括不同漏洞、arXiv、GitHub tag、模型/包发布、事故和 campaign。该规则优先于 URL、标题、正文、SimHash、MinHash，也优先于人工批准操作；语义模型以后只能生成候选，不能越过硬冲突。

### 5.3 人工复核闭环

标题相似度达到候选阈值、SimHash 距离不超过 8 或 MinHash 相似度达到 0.5，但不满足自动合并阈值的 pair 写入 `candidate_reviews(status=pending)`。硬冲突 pair 也留痕，但自动标记 rejected。

```bash
uv run intel m2-reviews --status pending --limit 50
uv run intel resolve-m2-review <id> --decision approved --reviewer alice --notes "same syndicated report"
uv run intel resolve-m2-review <id> --decision rejected --reviewer alice --notes "different incidents"
```

裁决写入 reviewer、notes 和 reviewed_at，并只把两份文档及其旧组件加入局部重算。批准关系以 `review_approved` 记录；算法版本变化后需要按新版本重新评估，不会无限继承旧模型判断。

## 6. EventVersion、Claim 与 Evidence

- `EventVersion`：每次 created、updated、evidence_changed、superseded 或 claim_changed 保存不可变完整快照和 diff；从 M2.0 升级的旧事件先写入 `baseline_import`，并明确记录无法还原的更早版本数量，不伪造历史。
- `Claim`：保存 claim_key、类型、文本、结构化值、置信度和 `unverified/confirmed/disputed/rejected` 状态。
- `ClaimEvidence`：把 Claim 关联到原始 Document，stance 支持 `support/contradict/context`，并可保存证据等级和最小必要摘录。

确定性事件构建会自动创建：

- `event_summary`：说明当前事件发生了什么，初始为 unverified。
- `identity`：对非 fallback 强事件键创建 confirmed 事实。

存储层的 `upsert_manual_claim()` 为后续管理 API 提供受约束入口：自动 Claim 不可被覆盖，每条人工 Claim 至少有一份有效文档证据，支持/反驳变化会增加 `Event.current_version` 并写入 `change_type=claim_changed` 的完整版本快照。

## 7. 运维、回放和自检

```bash
uv run alembic upgrade head
uv run intel m2-index --all                         # 完成持久化签名回填
uv run intel m2-token-stats                         # 重建 blocking token current 桶计数
uv run intel eventize                               # 普通局部增量
uv run intel dedupe                                 # 一个局部 dedupe batch
uv run intel cluster                                # 一个局部 cluster batch
uv run intel replay-m2 --max-batches 10000          # 显式全库版本重放
uv run intel replay-m2 --resume --max-batches 10000 # 从已有版本/待办积压断点续跑
uv run intel self-check
```

环境变量：

- `INTEL_M2_SIGNATURE_BATCH_SIZE`，默认 5000。
- `INTEL_M2_DEDUPE_BATCH_SIZE`，默认 1000。
- `INTEL_M2_CLUSTER_BATCH_SIZE`，默认 1000。
- `INTEL_M2_MAX_LOCAL_DOCUMENTS`，默认 20000，同时作为局部文档/候选 pair 安全上限。

Self-check 的 `m2_incremental` 报告 signature_due、各阶段 work_pending、reviews_pending、EventVersion/Claim 数量和 24 小时失败 run。Dedupe/cluster 各自使用 PostgreSQL transaction advisory lock；失败事务回滚后另写失败 run，待办仍可重试。

## 8. 迁移、测试与部署

迁移 head 为 `d2c5d53a7a76`。迁移创建上述索引、队列、版本、事实表和持久 token 桶计数，并从 M2.0 的 `near_dup_of/id` 回填稳定 component ID；不删除 Document、Event 或旧证据。迁移已验证：全新数据库 upgrade、downgrade 到上一版本、再次 upgrade 均成功。

GitHub CI 执行全部非 live 测试并连接 PostgreSQL。M2 专项覆盖签名确定性、相似候选、人工批准、强冲突不可越过、新强身份、质量指标、局部退役重选主、未受影响事件不改版本、EventVersion 和 Claim 支持/反驳证据。

已有大库部署顺序：

1. 升级 schema。
2. `m2-index --all` 回填持久化索引。
3. `replay-m2` 将 v1 派生状态按有界局部批次升级到 v2；若中途因安全阈值或基础设施错误停止，修复后使用 `replay-m2 --resume` 继续，避免重新失效已完成批次。
4. 观察 self-check，确认 signature_due、dedupe/cluster remaining 和 work_pending 均归零。

初次 v2 回填会写入数百万条有界 token/LSH 索引，并为变化事件创建版本和 Claim，需预留数据库时间和磁盘；正常增量不重复承担该成本。

## 9. 当前明确边界

- 人工金标不再是前置条件；LLM-as-judge 只能提供代理质量信号，报告中不得把它冒充真实 precision/recall。
- 结构化 model/package/incident/campaign 强键已经可用，但召回率取决于上游 Parser/实体抽取是否提供对应 `entities`；后续应以漏合并样本驱动实体抽取扩充。
- pgvector/embedding 未启用。影子实验确认召回质量、成本和延迟可接受后可作为候选层加入，但仍不能自动绕过强冲突。
- 自动 Claim 目前只覆盖事件摘要和强身份；影响范围、已利用状态、修复版本等领域 Claim 需要在后续抽取/管理接口中逐项增加。
- M2.2 已增加默认关闭的影子语义富化、实体、原子事件和抽取 Claim 表，但尚未影响生产 Event；详见 [`semantic-enrichment.md`](semantic-enrichment.md)。
- 按指定日期返回去重、聚类后热点的 API 仍未实现；应在原子事件输出契约和查询版本语义稳定后接入。

各里程碑完成度、首轮实验口径和推荐实施顺序统一见 [项目当前状态与后续路线](./current-status.md)。

## 10. M2.0 历史基线快照

2026-07-30 的 v1 回填用于量级对照：362,479 份 current 文档、1,520 份近重复、360,674 个 current 事件、403,132 条 current 证据关系。v1 的一次去重约 2 分 40 秒、聚类约 2 分 16 秒；这些是旧全局算法数据，不代表 v2 局部增量的单次成本。
