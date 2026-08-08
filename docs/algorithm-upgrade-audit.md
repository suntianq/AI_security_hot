# 算法升级现状审计(Phase 0)

> 依据 `AI_Security_Hot_algorithm_upgrade_plan.md` 的 Phase 0 问题清单,对照真实代码逐条
> 记录当前实现位置、已具备能力、真缺口与已排除项。本文件只做审计与筛选,不含新的算法设计。

## 1. 去重(Deduplication)

| 计划问题 | 实际位置 | 状态 |
|---|---|---|
| URL/标题/正文去重 | `src/ai_security_hot/events/intelligence.py::deduplicate_documents`;`normalize_url_key`/`normalize_title`/`content_fingerprint` | 已有 |
| 相似度算法 | `title_similarity`(SequenceMatcher,标题模糊相似)+ 精确 key(URL/标题 hash/正文 hash);无 MinHash/SimHash/embedding | 已有(粗粒度) |
| 重复关系保存 | `Document.near_dup_of/duplicate_kind/duplicate_score/dedupe_version`;`DuplicateComponent` 表(有 `algorithm_version`) | 已有 |
| 是否物理删除 | 否,`near_dup_of` 非破坏式,原始文档保留 | 已有 |
| 强身份冲突 | `_identifiers_conflict`;`DocumentIdentity` 表;CVE/GHSA/CNVD/incident 硬阻断 | 已有 |
| 候选召回边界 | `_blocking_keys`(标题 blocking)+ 有界局部组件,非 O(N²) | 已有 |
| **缺口** | 无 n-gram/MinHash 近重复召回;`DocumentSignature.simhash/minhash` 列存在但未填充 | **缺口(见 Milestone B)** |

## 2. 事件聚合(Eventize)

| 计划问题 | 实际位置 | 状态 |
|---|---|---|
| 候选 Event 归属 | `build_event_drafts`/`build_event_draft`(intelligence.py);`eventize` CLI→`storage/event_repository.py` | 已有 |
| 强 key | `strong_event_keys`/`_bounded_event_key`(CVE/GHSA/CNVD/incident/arxiv/model release 等) | 已有 |
| 版本/证据 | `Event.current_version`;`EventVersion` 表;`EventDocument`(stance/evidence_level/relation_reason) | 已有 |
| 去重组件→事件 | `DuplicateComponent` + `_iter_dedup_components`/`_iter_staged_event_drafts` | 已有 |
| **缺口** | 无显式 Event 生命周期状态机、无 split、无 reactivate(现有 `Event.status` 仅 detected/superseded) | **排除(过重)** |

## 3. 热点评分(Scoring)

| 计划问题 | 实际位置 | 状态 |
|---|---|---|
| score 字段 | `Event.score`(int 0-100),`_event_score`(intelligence.py:565) | 已有 |
| 特征 | `trust_tier(40/28/15) + identity(kind 分档) + diversity(独立 source×7,上限 20) + quality(parse_quality×15)` | 已有 |
| source count | 原按 `len({doc.source_id})`(**独立 source,非 source_family**) | **本次已改为独立 `source_family`** |
| 时间衰减/趋势 | 无 | **排除(计划称"前端已有 trend"系事实错误;前端无趋势字段)** |
| score 快照 | `DailyHotspotSnapshot`(payload 含 score)+ `DailyHotspotItem` | 已有;**本次已加 `algorithm_version`** |
| **缺口** | heat/importance/confidence/rank 四拆、模块 ImportanceAdapter、权重配置 | **排除(过度设计,保留单一可解释 score)** |

## 4. 数据模型(Source / Relation / Snapshot)

| 对象 | 现状 | 本次/后续 |
|---|---|---|
| `sources` 表 | `id/name/trust_tier/language/org`;`SourceEndpoint` 多端点 | **本次已加 `source_family`/`origin_source`** |
| `DocumentSignature` | 有 `simhash`/`minhash` JSONB 列 | 未填充(Milestone B 复用) |
| `DuplicateComponent` | 有 `algorithm_version`、master | 复用 |
| `RelationCandidate`/`CandidateReview` | 语义候选(shadow)+ 人工评审 | 复用 |
| `DailyHotspotSnapshot` | 不可变 revision + content_hash | **本次已加 `algorithm_version`** |

## 5. 计划各 Phase 裁决

| Phase | 裁决 | 理由 |
|---|---|---|
| 0 审计 | ✅ 本文档 | — |
| 1 Document Relation | 🟡 已基本存在 | duplicate_kind/score/version 已记录;不新建平行关系表 |
| 2 Source Family | ✅ **本次实施** | 修"转载导致热度虚高"真缺口 |
| 3 多级去重(MinHash) | ⏳ Milestone B | `DocumentSignature.minhash` 列已备,未填充 |
| 4 Relation Adjudicator | 🟡 分散于 intelligence.py | 已有硬冲突+裁决,暂不抽象统一组件 |
| 5 Event 生命周期状态机 | ❌ 排除 | 对项目过重,`Event.status` 够用 |
| 6 Cluster Chaining 防护 | 🟡 已有 blocking + 强 key | 有界组件天然缓解;无 embedding centroid |
| 7 Merge/Split/Reactivate | ❌ 排除(第一版) | 人工 requeue 已有,自动 split 超出范围 |
| 8-17 score 四拆/Heat/Importance/Confidence/Rank/Trend | ❌ 排除 | 过度设计;Trend 前提(前端已有)不成立 |
| 9 Score Snapshot + 版本 | ✅ **本次已加 `algorithm_version`** | 可审计、可复现 |
| 10 evaluation 基准 | ⏳ 后续 | `evaluation/` 现有资产可扩展 |
| 11 admin 反馈闭环 | ❌ 排除 | 超出本轮 |
| 12-13 Embedding/LLM | 🟡 已 shadow | 与现有 shadow 机制一致,不主动增强 |

## 6. 本次落地改动(对照)

- **Source Family**:`sources.source_family/origin_source` 迁移 + `sources.yaml` 声明 +
  `sync_registry` 落库;`IntelDocument.source_family`(加载时 join Source);`_event_score`
  多样性改按独立 family(回退 source_id)。`Event.score` 字段与区间不变。
- **Snapshot 版本**:`DailyHotspotSnapshot.algorithm_version = SCORE_VERSION("heat-v1")`。
- **测试**:`tests/test_event_intelligence.py`(family 多样性/回退/registry)、
  `tests/integration/test_snapshot_db.py`(snapshot 版本)。

## 7. 风险

- 旧数据 `source_family` 回填为 source_id(各源独立 family),与旧行为一致,无回归。
- `_event_score` 对同一 source 多端点的多样性可能下降 → 部分事件 score 变化,但均在兼容
  区间(0-100),`GET /events?min_score=` 与前端排序只受影响事件的数量级,不破坏 API。
- Milestone B(MinHash)涉及新候选索引与写入,需另行评估性能与误合并。
