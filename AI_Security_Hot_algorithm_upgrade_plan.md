# AI Security Hot：去重、事件聚合与热点评分算法升级实施计划

> 目标：在**不推翻现有工程架构、不破坏证据链、不降低可审计性**的前提下，对 AI Security Hot 当前的去重、事件聚合和热点评分流程进行分阶段升级。  
> 本文档面向代码 Agent，可作为直接执行的工程 Plan。  
> 优先级原则：**先修正数据语义与关系模型，再优化算法；先保证 Precision 与可解释性，再追求 Recall 与自动化程度。**

---

# 0. 项目背景与现有约束

当前项目已经具备：

- 增量采集与规范化
- 多源数据接入
- 非破坏式去重
- 增量事件聚合
- Event / Claim / Evidence / EventVersion
- 强身份冲突保护
- PostgreSQL 作为唯一事实来源
- LLM 影子抽取
- Embedding 候选召回
- 人工确认后语义事件提升
- 每日热点不可变 Revision
- `as_of` 历史查询
- 后台重新分类 / 重新聚类能力

本次升级**不得破坏以上原则**。

尤其必须保留：

1. 原始文档不能因为去重而物理删除。
2. CVE、GHSA、CNVD、版本、事故身份等强冲突规则优先于文本相似度。
3. Embedding 只能作为候选召回或辅助特征，不能单独决定事件合并。
4. LLM 默认保持影子模式，不能直接覆盖正式 Event / Claim / Evidence。
5. PostgreSQL 仍然是正式状态和关系的唯一事实来源。
6. 每日热点 Revision 必须保持不可变和可重现。
7. 所有新算法结果必须能够记录算法版本和判定依据。
8. 现有 API、CLI、worker、迁移机制尽量兼容，避免大范围破坏式重构。

---

# 1. 本轮升级的核心目标

将当前较粗粒度的：

```text
规范化
  -> 去重
  -> 聚类
  -> score
  -> 热点
```

升级为：

```text
原始文档
  -> 内容规范化 / 强标识抽取
  -> 多级候选召回
  -> 文档关系裁决
  -> 增量事件归属
  -> Event 生命周期维护
  -> Claim / Evidence 驱动的事件演化
  -> 传播热度 Heat
  -> 情报重要性 Importance
  -> 证据可信度 Confidence
  -> Rank Score
  -> 不可变 Daily Revision
```

核心思想：

> 不再让“文本相似度”直接决定去重或事件合并，而是让相似度成为关系裁决的证据之一。

---

# 2. 最终希望得到的数据语义

系统内部需要明确区分三个层级：

```text
Document
原始资讯 / 漏洞 / 论文 / 技术内容
        ↓
Duplicate Group
同稿、转载、轻微改写
        ↓
Event
同一个现实事件及其持续演化
```

要求：

- “转载/同稿”进入 Duplicate Group。
- “同一事件的新进展”不能被去重掉。
- “相关但不同的事件”不能因为 embedding 高相似而强行合并。

---

# 3. 实施原则

## 3.1 不一次性重写

必须先检查当前实现，再做增量改造。

Agent 第一阶段需要找到：

- 当前文档模型
- Event / Claim / Evidence / EventVersion 模型
- 当前 dedup 逻辑
- 当前 eventize 逻辑
- 当前 score 计算代码
- 当前每日 snapshot 结构
- 当前 source 配置与 source level
- 当前 embedding 使用位置
- 当前后台 requeue / cluster 接口
- 当前 evaluation 资产
- 当前测试覆盖

禁止先凭本 Plan 新建另一套平行系统。

## 3.2 Precision 优先

对于去重和事件合并：

```text
错误合并 > 漏合并
```

因此所有自动合并机制优先保证 Precision。

## 3.3 强规则优先于软相似度

统一关系判定流程：

```text
Hard Conflict Gate
        ↓
Strong Identity Match
        ↓
Lexical Similarity
        ↓
Semantic Similarity
        ↓
Entity / Claim / Time Features
        ↓
Relationship Adjudication
```

任何软相似度不得绕过明确身份冲突。

---

# 4. Phase 0：代码与数据模型审计

## 目标

在修改算法之前，形成一份最小的现状说明，确认真实代码路径和已有能力。

## Agent 需要完成

检查并记录：

### 当前去重

- URL 去重逻辑在哪里
- 标题去重逻辑在哪里
- 正文 hash 是否存在
- 当前标题/正文相似度算法
- 是否已经使用 SimHash / MinHash / SequenceMatcher / cosine
- 当前重复关系保存在哪里
- 当前重复文档是否仍保留
- 去重是否影响后续 Event 聚合

### 当前事件聚合

- 新文档如何找到候选 Event
- 当前候选窗口大小
- 当前相似度指标
- 当前 merge 条件
- CVE / GHSA / CNVD / version conflict 具体代码
- Event 是否保存代表文档
- Event 是否有 centroid / embedding
- Event 是否支持 merge / split
- EventVersion 在什么时候生成

### 当前热点评分

- `event.score` 或等价字段在哪里计算
- score 使用哪些特征
- 文档数量是否直接影响 score
- source count 如何计算
- 是否存在时间衰减
- 是否存在趋势指标
- daily snapshot 保存哪些 score 信息

### 输出

在仓库中新建：

```text
docs/algorithm-upgrade-audit.md
```

至少记录：

- 当前实现位置
- 当前算法流程
- 数据表 / ORM 字段
- 可复用代码
- 需要迁移的字段
- 风险点

## Phase 0 验收

- 不修改核心算法行为。
- 测试全部通过。
- 给出明确的改造文件清单。
- 后续 Phase 必须基于真实代码，而不是假设目录结构。

---

# 5. Phase 1：建立显式 Document Relation 模型

## 目标

将“重复 / 不重复”升级为可审计的多类型文档关系。

## 建议关系类型

```text
EXACT_DUPLICATE
NEAR_DUPLICATE
SAME_EVENT
RELATED_EVENT
CONFLICT
UNRELATED
```

如现有模型已有类似关系表，应扩展而不是重复创建。

## 推荐保存的关系字段

根据当前 ORM 适配，可考虑：

```text
source_document_id
target_document_id / target_event_id
relation_type
confidence
algorithm_version
created_at
updated_at
is_manual
review_status
reason_codes
feature_snapshot
```

其中 `reason_codes` 例如：

```text
same_canonical_url
same_content_hash
same_cve
same_primary_entity
different_cve
version_conflict
high_title_similarity
high_embedding_similarity
same_claim
time_window_match
```

`feature_snapshot` 建议使用 JSONB 保存关系判定时使用的核心特征，不要只保存一个最终 score。

## Phase 1 迁移要求

- 使用 Alembic。
- 迁移必须向后兼容。
- 不删除原有关系字段。
- 旧数据可映射到默认 relation。
- 迁移必须可 rollback。

## Phase 1 测试

至少覆盖：

- 相同 URL -> EXACT_DUPLICATE
- 相同正文 hash -> EXACT_DUPLICATE
- 不同 CVE -> CONFLICT
- 高相似文本 + 不同 CVE -> 仍为 CONFLICT
- 关系具有 algorithm_version
- 原始 Document 数量不减少

---

# 6. Phase 2：加入 Source Family / Origin Source

## 目标

解决“同一稿源被大量转载导致热度虚高”的问题。

## 数据模型

如果当前 Source 只表示抓取入口，增加或扩展：

```text
source_family
origin_source
source_type
authority_level
```

字段命名应服从现有模型。

支持：

- 配置文件显式声明
- 解析器识别
- 默认 fallback 到 source 自身

## 作用

后续以下指标优先基于独立 source family：

- Volume
- Diversity
- Authority
- Momentum

而不是原始 URL 数量。

## Phase 2 验收

给同一个 Event 构造：

```text
100 条来自同一 source_family 的转载
5 条来自 5 个独立 source_family
```

热度特征中必须明显区分二者。

---

# 7. Phase 3：多级非破坏式去重

## 目标

形成：

```text
精确重复
  -> 词法近重复
  -> 可选语义候选
  -> 关系裁决
```

## 7.1 Level 0：确定性去重

优先复用当前逻辑。

覆盖：

- canonical URL
- normalized URL
- source-native ID
- normalized title hash
- content hash
- CVE / GHSA / CNVD
- DOI
- arXiv ID
- GitHub advisory / issue / PR / commit 等强 ID

原则：

- 高 Precision
- 极低计算成本
- 结果可解释

## 7.2 Level 1：Near-Duplicate

建议实现：

```text
char n-gram
+
MinHash / LSH
```

或在当前项目已有实现基础上增强。

推荐：

- 以标题 + lead + 正文主体为输入
- 清理 boilerplate
- 不使用网站 footer / 推荐阅读 / 免责声明
- 将候选召回与最终 relation 分开

不要直接：

```text
MinHash similarity > T
-> 自动删除
```

应该：

```text
MinHash
-> candidate
-> relation adjudicator
```

## 7.3 Level 2：Embedding

保留当前原则：

> Embedding 只负责召回候选。

流程：

```text
Document
  -> embedding
  -> ANN Top-K
  -> Candidate
  -> Hard Conflict
  -> Relationship Features
  -> Adjudicator
```

Embedding 默认关闭时，整个系统必须仍可正常工作。

---

# 8. Phase 4：Relation Adjudicator

## 目标

建立统一关系裁决组件，避免不同模块各自写相似度逻辑。

建议抽象为类似：

```python
RelationDecision adjudicate(document_a, document_b_or_event)
```

具体类名根据项目风格决定。

## 输入特征

至少考虑：

```text
strong identifiers
title similarity
body / lexical similarity
entity overlap
claim overlap
time distance
source family
category / module compatibility
embedding similarity（可选）
version compatibility
incident identity compatibility
```

## 判定顺序

```text
1. Hard Conflict
2. Exact Identity
3. Near-Duplicate
4. Same Event
5. Related Event
6. Unrelated
```

不要使用一个统一 threshold 解决所有关系。

## 配置

阈值必须集中配置，不要散落在 Python 文件中。

## 解释性

每次正式关系必须记录：

```text
relation
confidence
reason_codes
algorithm_version
feature_snapshot
```

---

# 9. Phase 5：Event 从静态 Cluster 升级为 Event State

## 目标

不再把 Event 仅理解为“一组相似文档”。

## Event 应维护

根据现有模型增量扩展：

```text
canonical title
first_seen_at
last_seen_at
last_meaningful_update_at
last_novel_claim_at
event_state
representative documents
strong identifiers
entities
claims
source families
event version
```

## Event State

建议：

```text
OPEN
ACTIVE
COOLING
DORMANT
CLOSED
```

支持 DORMANT 事件重新激活。

状态阈值应按 module 配置，不要所有事件共用一个生命周期窗口。

---

# 10. Phase 6：防止 Cluster Chaining

## 目标

防止：

```text
A ~ B
B ~ C
C ~ D
```

最终导致 A 与 D 完全不同却进入同一超级 Event。

## 方案

Event 不只维护一个平均 centroid。

至少保留：

```text
event centroid（如果启用 embedding）
+
representative documents
+
canonical entities / identifiers
```

新文档归属时至少检查：

```text
document <-> event representation

以及

document <-> representative documents
```

## 监控指标

新增：

```text
largest_event_size
event_size_p95
event_size_p99
single_document_event_ratio
merge_count
split_count
```

---

# 11. Phase 7：Event Merge / Split / Reactivate

## Merge

候选条件：

```text
共享强 ID
高 Claim 重合
高实体重合
高时间重叠
高代表文档相似度
```

必须继续经过冲突 Gate。

## Split

第一版先支持：

- 管理后台人工 Split
- 产生 Split Candidate
- 不自动执行高风险拆分

后续再基于 Document - Claim - Entity 子图生成 split proposal。

## Reactivate

对于 DORMANT Event，如果出现：

- 新 Claim
- Claim 状态变化
- 新利用状态
- 新版本
- 新官方确认
- 新重大证据

应更新：

```text
last_meaningful_update_at
event state
EventVersion
```

并重新进入热度计算。

---

# 12. Phase 8：重构热点评分数据模型

## 目标

将一个模糊的 `score` 拆成：

```text
heat_score
importance_score
confidence_score
rank_score
```

同时保留旧字段兼容期。

---

# 13. Heat Score：传播热度

建议第一版包含：

```text
Volume
Diversity
Momentum
Burst
Freshness
Novelty
```

统一归一化为 0.0 ~ 1.0，最终映射到 0 ~ 100。

## Volume

优先使用独立 `source_family` 数，而不是 Document 总数。

使用 `log1p(n)` 等饱和增长。

## Diversity

第一版可以使用：

- 独立 source type 数量
- 独立 source family 数量

后续再升级 entropy。

## Momentum

衡量近期增长速度，例如：

```text
最近 1h 新增独立 source_family
vs
之前 1h
```

窗口应可配置。

## Burst

衡量相对于该主题 / 模块历史基线的异常爆发程度。

第一版建议使用：

```text
median + MAD
```

历史不足时回退到 module baseline 或降低权重。

## Freshness

不要只使用：

```text
now - first_seen
```

优先使用：

```text
now - last_meaningful_update_at
```

或：

```text
now - last_novel_claim_at
```

## Novelty

优先利用现有 Claim / Evidence 体系。

可识别：

```text
new Claim
new Evidence
Claim status change
new affected product
new version
new exploit status
new patch status
new official confirmation
```

第一版不要依赖 LLM 判断 novelty。

---

# 14. Importance Score：情报重要性

解决：

```text
很热 ≠ 很重要
```

基础维度：

```text
Authority
Impact
Domain Relevance
Confirmation
Novelty
```

## 模块 Adapter

不要所有模块完全共用一个 Importance 公式。

建议有：

```text
NewsImportanceAdapter
CVEImportanceAdapter
PaperImportanceAdapter
SecurityResearchImportanceAdapter
```

### CVE

优先考虑已有：

```text
CVSS
关注软件命中
官方 / NVD / CISA
KEV
利用状态
PoC
补丁状态
受影响范围
```

没有的数据不要为了本 Phase 强行引入外部依赖。

### News

可以看：

```text
primary source
source authority
cross-source confirmation
domain relevance
novelty
```

### Paper

可以看：

```text
研究主题相关性
机构 / 作者来源
代码 / artifact
跨来源讨论
```

当前没有的数据不要伪造。

---

# 15. Confidence Score：证据可信度

第一版可考虑：

```text
primary source presence
independent source count
supporting evidence count
contradicting evidence count
source authority
claim consistency
```

Confidence 不等于 Heat。

---

# 16. Rank Score

第一版建议：

```text
RankScore =
0.55 * Heat
+ 0.35 * Importance
+ 0.10 * Confidence
```

权重必须配置化，并允许 module-specific override。

---

# 17. Trend 计算

前端已有：

```text
rising
stable
falling
```

建议使用：

```text
短时间窗口 heat delta
+
momentum
```

内部可以支持：

```text
FAST_RISING
RISING
STABLE
FALLING
```

---

# 18. Phase 9：Score Snapshot 与 Algorithm Version

Daily Revision 除了保存 event / score / rank，还应保存：

```text
event_version_id
algorithm_version
feature_version
computed_at
heat_score
importance_score
confidence_score
rank_score
feature_snapshot
```

旧 Snapshot 不能被重新计算后覆盖。

## Algorithm Version

建议统一：

```text
dedup-v2
relation-v1
eventize-v2
heat-v2
importance-v1
ranking-v2
```

---

# 19. Phase 10：评测集建设

使用现有 `evaluation/` 新增：

```text
evaluation/dedup_pairs.jsonl
evaluation/event_pairs.jsonl
evaluation/event_clusters.jsonl
evaluation/ranking_labels.jsonl
```

## 去重指标

至少：

```text
Precision
Recall
F1
False Merge Rate
```

优先关注 False Merge。

## Event 聚类指标

建议：

```text
Pairwise Precision / Recall / F1
B-Cubed Precision / Recall / F1
```

同时监控：

```text
largest_event_size
p95 event size
singleton ratio
merge count
split count
conflict count
```

## Ranking 指标

使用：

```text
NDCG@5
NDCG@10
Precision@10
Time-to-Detect
Ranking Churn
```

---

# 20. Phase 11：后台人工反馈闭环

利用现有 admin 增加最小人工标注入口：

```text
Mark as Exact Duplicate
Mark as Near Duplicate
Same Event
Different Event
Conflict
Should Merge
Should Split
```

人工修改必须：

- 记录操作者
- 记录时间
- 保留原自动判定
- 标记 manual override

人工结果可导出到 evaluation。

---

# 21. Phase 12：Embedding 影子评测

继续保持：

```text
INTEL_EMBEDDING_ENABLED=false
```

为默认值。

开启时：

```text
Embedding
  -> ANN Top-K
  -> 候选关系
  -> shadow decision
```

重点记录：

- 规则未召回但 embedding 找到的候选
- embedding 高相似但被 hard conflict 拒绝的候选
- 对 same-event recall 的提升
- false merge 风险

通过评测后才提高其权重。

---

# 22. Phase 13：LLM 语义能力

不是本轮优先项。

继续保持 LLM shadow。

优先用于：

```text
entity extraction
atomic event extraction
claim extraction
relation explanation
split / merge proposal
```

禁止：

```text
LLM 说是同一个事件
-> 自动 merge
```

---

# 23. 推荐配置结构

尽量集中配置：

```text
config/eventization.yaml
config/ranking.yaml
```

示例：

```yaml
relation:
  near_duplicate:
    title_threshold: 0.90
    lexical_threshold: 0.82

  same_event:
    max_time_hours: 72

ranking:
  default:
    heat_weight: 0.55
    importance_weight: 0.35
    confidence_weight: 0.10

  heat:
    volume: 0.20
    diversity: 0.15
    momentum: 0.20
    burst: 0.20
    freshness: 0.15
    novelty: 0.10
```

具体字段按实际代码调整。

---

# 24. API 与 CLI 兼容

尽量保持：

```text
GET /events?min_score=...
GET /api/overview
GET /api/feed
GET /api/event/{id}
```

兼容期：

```text
score = rank_score
```

CLI 继续保留：

```text
uv run intel eventize
uv run intel daily-snapshot
```

如有必要增加少量评测 CLI，不要创建大量难维护命令。

---

# 25. 自检与可观测性

扩展 `self-check` / `stats`，建议增加：

```text
duplicate_relation_count
near_duplicate_count
conflict_count
same_event_relation_count

largest_event_size
event_size_p95
singleton_event_ratio

active_events
cooling_events
dormant_events

ranking_version
events_scored
score_failures
```

---

# 26. 数据迁移策略

升级必须采用：

```text
先加字段 / 新表
-> 兼容旧代码读取
-> backfill
-> 新旧算法并行
-> 切换读取逻辑
-> 最后决定是否废弃旧字段
```

禁止一次迁移删除旧 score 并全量覆盖历史结果。

---

# 27. 灰度策略

新算法优先 shadow：

```text
old_rank_score
new_rank_score
```

同时保存并观察：

- Top 10 差异
- false merge
- giant cluster
- source-family amplification
- burst detection
- ranking churn

确认后再切换正式排序。

---

# 28. 推荐实施顺序

## Milestone A：关系模型基础

完成：

```text
Phase 0
Phase 1
Phase 2
```

即：

- 审计
- Document Relation
- Source Family

## Milestone B：去重升级

完成：

```text
Phase 3
Phase 4
```

## Milestone C：Event 生命周期

完成：

```text
Phase 5
Phase 6
Phase 7
```

第一版 Split 可以只支持 proposal + manual。

## Milestone D：热点评分 v2

完成：

```text
Phase 8
Phase 9
```

## Milestone E：评测与反馈

完成：

```text
Phase 10
Phase 11
```

## Milestone F：语义增强

最后再做：

```text
Phase 12
Phase 13
```

Embedding / LLM 不是前置依赖。

---

# 29. 第一轮实际开发范围

如果本次 Agent 需要立刻开始编码，第一轮只执行：

```text
1. Phase 0：审计
2. Phase 1：Document Relation
3. Phase 2：Source Family
4. 建立相应 migration
5. 增加测试
6. 保持现有 eventize 行为不变
```

完成后输出：

```text
docs/algorithm-upgrade-audit.md
```

以及：

- 修改文件
- migration
- tests
- 后续 Phase 建议

然后再继续 Milestone B。

---

# 30. 禁止事项

Agent 不得：

- 删除原始文档来实现去重
- 让 embedding cosine threshold 直接触发正式 merge
- 让 LLM 直接修改正式 Event
- 删除强身份冲突保护
- 将不同 CVE 因文本相似强行聚合
- 将 Document count 直接作为主要热点分数
- 将大量转载当作大量独立信源
- 将所有模块强制使用同一个 Importance 公式
- 删除旧 Daily Revision
- 用新算法重写历史 revision
- 在无测试情况下修改核心 eventize
- 为了“算法先进”引入不必要的大模型依赖
- 在代码中散落 score 权重和 threshold
- 对所有历史文档执行无边界 O(N²) 两两比较
- 为一次算法升级重写整个项目技术栈

---

# 31. Definition of Done

## 去重

- 可以区分 Exact Duplicate 与 Near Duplicate。
- 原始文档始终保留。
- 不同强身份对象不会被相似度误合并。
- Near Duplicate 不再重复放大热点。

## Event

- 可以区分 Duplicate 与 Same Event。
- 新文档可以增量归属已有 Event。
- Event 有明确生命周期。
- Event 可以重新激活。
- 具备 Merge / Split 校正能力或候选机制。
- 超级大簇可以被监控。

## Ranking

- 热度不再主要取决于文章数量。
- 使用独立 source family。
- 能识别快速升温事件。
- 能识别相对历史 baseline 的突发事件。
- 旧事件出现重大新进展后能够重新升温。
- Heat 与 Importance 分离。
- 排名结果能够解释。

## Auditability

- 每个关系有 algorithm_version。
- 每次排名有 feature snapshot。
- 每日热点 Revision 可以重现。
- 人工修正不会删除原自动判定历史。

## Evaluation

- 有 dedup benchmark。
- 有 event benchmark。
- 有 ranking benchmark。
- 可以运行自动评测或测试。

---

# 32. Agent 工作方式要求

请直接在当前代码仓中工作。

开始时：

1. 阅读 README。
2. 阅读数据模型。
3. 阅读 eventize / dedup / scoring 代码。
4. 阅读 migration。
5. 阅读现有测试。
6. 阅读 evaluation 目录。

然后先完成 Phase 0。

不要在没有检查现有实现前创建新的架构。

每完成一个 Milestone：

```bash
uv run ruff check .
uv run pyright
uv run pytest -m "not live" -q
uv run alembic check
docker compose config --quiet
```

如果某项当前环境无法运行，要明确说明原因，不要假装成功。

---

# 33. Agent 最终汇报格式

## Completed

- 完成的功能
- 修改的数据模型
- 新增的 migration
- 新增的配置
- 新增的测试

## Compatibility

- 现有 API 是否兼容
- 现有 CLI 是否兼容
- 现有数据库数据是否需要 backfill

## Validation

- ruff
- pyright
- pytest
- alembic
- docker compose config

## Risks

- 尚未解决的误合并风险
- 迁移风险
- 性能风险
- 数据质量风险

## Next

明确指出下一 Milestone 应实施哪些 Phase。

---

# 34. 本次立即执行指令

现在开始执行 **Milestone A**：

```text
Phase 0：代码与数据模型审计
Phase 1：显式 Document Relation
Phase 2：Source Family / Origin Source
```

要求：

- 先审计，后修改。
- 最大限度复用现有模型和关系表。
- 保持当前 eventize 正式行为不变。
- 不开启 Embedding 自动裁决。
- 不修改现有热点算法。
- 所有 schema 变化必须通过 Alembic。
- 为关键逻辑补充测试。
- 将审计结论写入 `docs/algorithm-upgrade-audit.md`。

完成 Milestone A 后停止继续扩大改动范围，先输出实施结果和下一步建议。
