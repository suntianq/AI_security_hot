# 项目当前状态与后续路线

> 状态快照：2026-08-02  
> 用途：本页是“现在做到哪里、哪些尚未完成、接下来按什么顺序做”的唯一状态入口。专题文档负责解释设计和操作细节；若进度表述不一致，以本页为准。

## 1. 当前结论

项目已经具备可持续增量采集、文档生命周期、分类、局部去重、确定性事件聚类、证据与版本审计、LLM 影子语义抽取、跨文档关系裁决、Claim 合并与受控提升预览、日期热点 API。M0、M1、M2.1、M2.2.1、M2.2.2、M2.3、M2.4（影子阶段）与 NVD 隔离均已落地。

当前仍不是完整的“LLM 驱动事件情报产品”。语义结果默认写影子表，不修改正式 `Event`、去重关系或现有分类；影子→正式提升默认为预览（dry-run）。Embedding 召回、LLM 三分类增强、正式提升启用、日报投递尚未实现。

```text
信源
  → 增量抓取 / 规范化 / 正文 / 分类
  → 确定性局部去重与事件聚类（NVD/KEV 单独隔离）
  → Event / EventVersion / Claim / Evidence / 日期热点 API
  → 现有查询 API 与离线 report

当前 duplicate master（非 CVE）
  → LLM 语义抽取（M2.2 平衡样本已评测）
  → DocumentEnrichment / Entity / AtomicEvent / ExtractedClaim
  → M2.3 跨文档关系裁决（RelationVerdict）
  → M2.4 Claim 合并 + 受控提升预览（默认 dry-run）
  ── 正式提升默认关闭，需显式启用
```

## 2. 里程碑完成度

| 里程碑 | 状态 | 已完成 | 尚未包含 |
|---|---|---|---|
| M0 工程骨架 | 完成 | PostgreSQL/Alembic、API/Worker、阶段队列、统一网络出口、BlobStore、测试与 CI | 动态网页 Playwright 仍只是预留位 |
| M1.1 规则分类 | 完成 | CVE 独立标签；新闻/论文主题分类；分类溯源 | 规则不能替代深层语义判断 |
| M1.2.x 增量与生命周期 | 完成 | 19 个 endpoint 配置、18 active；AI HOT changes、NVD 时间窗、CISA 快照、Anthropic 双通道；撤回/退役/修订审计 | 上游保留窗口之外的历史不自动恢复；NVD 120 天以前需独立 backfill |
| M1.3 混合分类 | 机制完成 | 可替换 Provider、严格 Schema、缓存、审计、重试、规则 fallback；CVE bypass | 当前存量及首轮 100 篇实验目标的正式分类仍是 `rule`，尚未做一次受控 HybridClassifier 重放 |
| M2.1 局部事件情报 | 完成 | 持久化签名/强身份/blocking、稳定重复组件、局部重算、硬冲突、候选复核、EventVersion/Claim/Evidence、事件查询 API | 现有非强身份事件主要依赖确定性 fallback，不等同于语义事件合并 |
| M2.2.1 语义稳定化 | 完成 | 失败响应审计（raw_response/finish_reason/usage）、有界修复、本体版本化（benchmark+ONTO_VERSION）、batch 可重放（batch_id） | 延迟 p50/p95 未持久化（需 started_at） |
| M2.2.2 分层评测 | 完成 | 分层抽样（16 源平衡）、语义评测聚合器、`semantic-eval`/`semantic-sample` CLI、报告语义区 | LLM-as-judge 未启用；抽样规模当前 100 篇 |
| M2.2 平衡样本评测 | 完成 | 98 篇平衡样本，相关率 61.2%，证据命中 86%，结构失败 0 | 相关率随来源差异大（arxiv 100% vs google-blog 0%） |
| M2.3 语义候选与裁决 | 完成（影子） | 跨文档原子事件候选召回（共享实体）、确定性三分类裁决、`RelationVerdict` 表、`relation-scan` CLI | Embedding 召回、LLM 三分类增强默认关 |
| M2.4 事实合并与受控提升 | 完成（影子阶段） | Claim 合并（436 合并/139 对）、提升门禁、`event-promote --dry-run` 预览 | 正式提升默认关；与正式事件命名空间对齐待设计 |
| NVD 单独去重/聚类 | 完成 | NVD+KEV 完全隔离、`Event.category`（vuln_db/general）、旧 `cve:` 事件 supersede 清理 | 多 CVE 文档仍合理产生多事件（非 bug） |
| 日期热点 API | 完成 | `/v1/daily-hotspots?date&tz&category` 按天+时区+分类返回 | `as_of` 历史快照未做（仅当前状态按天分组） |
| M3 日报与投递 | 未开始 | 目标和适配器边界已有设计 | 日报冻结/版本化、邮件/飞书、幂等与更正通知 |

“机制完成”不表示所有历史文档已经由 LLM 重跑，也不表示影子结果已经参与生产事件。

## 2.1 本阶段（2026-07-31 至 08-02）关键结果

### 数据口径修复：NVD 过度拆分
- **根因**：NVD 解析器从描述正文扫描次要 CVE/GHSA/CNVD，一个记录 fan-out 成多个事件；且 NVD 隔离迁移后旧 `cve:` 事件未清理，同一 CVE 双事件。
- **修复**：解析器只保留记录自身 CVE 身份；supersede 40,683 个旧 `cve:` 事件（保留 EventVersion 历史）。
- **结果**：vuln_db 活跃事件 64,979 → **24,296**；单 CVE 文档对应活跃事件 1 个（30,984 文档）。

### M2.2.2 平衡样本评测（98 篇）
| 指标 | 值 |
|---|---:|
| 相关率 | 61.2%（60/98） |
| 证据精确命中 | 86%（685 mentions + 322 claims） |
| 结构失败率 | 0% |
| 成本 | 405,681 tokens |
| 按来源相关率 | arxiv 100% · portswigger 100% · anthropic 86% · google-blog 0% |

### M2.3 关系裁决（影子）
- 376 个跨文档候选对 → **139 related_event** + 232 different（共享实体 + 时间窗）。
- `relation_verdicts` 表持久化，`intel relation-scan` 驱动。

### M2.4 Claim 合并与提升预览（影子）
- 139 对相关对 → **436 合并 claims**。
- `event-promote --dry-run` 生成 50 个 promotion 预览，全部 gate_met（≥2 文档）。

### 日期热点 API
- `/v1/daily-hotspots?date&tz&category` 按自然日+时区返回去重热点，general/vuln_db 可分别筛选。

## 3. 首轮 100 篇影子实验说明

本轮固定执行版本为 `662ed8fa2adde5d8e03357aa8131d4a7`，Prompt 为 `m2.2-document-semantic-v2`。目标是 100 篇 current、非 CVE/GHSA/CNVD、当前去重主文档。

| 指标 | 结果 |
|---|---:|
| 成功 / 仍待重试 | 98 / 2 |
| 成功结果中的相关 / 不相关 | 26 / 72 |
| 实体 / 原子事件 / 抽取 Claim | 157 / 106 / 179 |
| 实体证据精确命中率 | 98.4% |
| Claim 证据精确命中率 | 92.2% |
| 已记录成功调用 token | 294,250 |
| 平均 / P95 延迟 | 5,284 ms / 16,148 ms |

这组数据的正确解释是：语义链路已经真实跑通，并暴露了可修复的问题；它不是人工金标 F1，也不能证明语义事件聚类已完成。样本中 90 篇来自 ITHome，来源分层不足。两篇失败样本稳定输出了当前本体不接受的 `benchmark` 实体类型，说明本体和 Schema 的演进需要版本化治理。完整实验记录见 [DeepSeek V4 Flash 首轮 100 篇影子实验](./semantic-experiment-2026-07-31.md)。

离线 `report.html` 的语义总数可能包含首轮实验之前的诊断调用，因此全库报告数字不应直接当作这 100 篇固定批次的实验指标。

## 4. 当前明确边界

- `INTEL_SEMANTIC_ENRICHMENT_ENABLED=false` 应继续保持默认值；除非显式执行命令，否则 Worker 不持续调用模型。
- LLM 只处理当前非 CVE 去重主文档。结构化 CVE 保持规则与强标识路径，不交给语义模型合并。
- LLM 输出当前不能修改正式分类、`near_dup_of` 或 `Event`，也不能越过不同漏洞、版本、发布、事故等强身份冲突。
- 人工双人金标不是继续开发的前置条件；可选 reviewed 样本用于困难案例诊断。LLM-as-judge 只能作为代理指标，不能命名为真实 precision/recall/F1。
- `report.html` 是离线观察面，不是稳定业务 API；它展示全库状态和影子结果，但不承担按日期冻结热点的语义。
- 当前 API 未认证，且含运维写入口，不能直接暴露到公网。
- API key 只能从环境变量或部署 Secret 注入，不能写入 YAML、Markdown、日志或 Git。

## 5. 已知不足

### 5.1 语义运行时

- 当前实体本体缺少已在真实输出中出现的 `benchmark` 类型；新增类型前需要明确语义、规范化规则以及是否只作候选 token。
- 失败调用没有完整持久化原始无效响应、`finish_reason` 和失败调用 token，问题复盘与成本核算不完整。
- Schema 校验失败后只有整次重试，尚无受约束的 JSON/枚举修复步骤。
- `execution_version` 已覆盖任务、Prompt、Provider namespace 和模型，但本体/Schema 版本还需成为显式指纹的一部分。

### 5.2 评测与样本

- 首轮 100 篇按最新顺序选取，90% 来自单一来源，不能代表 18 个 active endpoint。
- 当前没有持久化的实验 `batch_id`/样本清单；执行版本可以识别任务版本，但不能单独表达一次固定抽样。
- 严格 Schema、证据定位、成本和延迟已有数据；独立 LLM-as-judge 及其聚合报告尚未实现。
- 失败调用用量未保存，因此实验 token 是成功调用的下界，不是完整账单值。

### 5.3 事件智能

- 语义实体和原子事件尚未用于候选召回。
- 没有向量/Embedding 层，也没有跨文档三分类关系裁决。
- 没有把多个文档 Claim 合成为支持、反驳和随时间变化的正式事实。
- 没有新颖性、影响、紧急性和可信度的独立判断与排序门禁。
- 72 篇被影子模型判为不相关的文档仍保留确定性 fallback Event，说明生产事件与语义相关性之间尚未建立受控桥梁。

## 6. 推荐实施顺序

### M2.2.1：语义运行稳定化

1. 版本化 Entity/Claim 本体与 Schema，并决定 `benchmark` 等实体的边界。
2. 保存失败原始响应、`finish_reason`、用量与可安全展示的错误摘要。
3. 增加一次有界结构修复；修复仍失败才进入退避重试。
4. 增加显式实验 batch、固定样本清单和可重复导出。

完成条件：失败可解释、成本可完整核算、同一固定批次可重放，且本体升级不会污染旧结果。

### M2.2.2：分层影子评测

1. 按来源、内容类型、主题和发布时间分层抽取 300～500 篇，继续排除 CVE。
2. 实现独立 judge 任务与聚合器，报告相关性代理分、证据命中、无证据 Claim、结构失败、成本和延迟。
3. 保留少量人工抽查作为诊断，不把人工金标设为开发阻塞项。

完成条件：样本不再由单一来源主导，关键指标可以按来源和内容类型拆解。

### M2.3：候选召回与关系裁决

1. 由强标识、实体、时间窗和 Embedding 共同召回候选；任何一种弱信号都不直接合并。
2. 对候选输出 `same_event / related_event / different_event`、置信度、理由和证据。
3. 强身份冲突始终硬阻断；中置信结果进入复核队列。

完成条件：候选和裁决全程影子运行，能统计召回规模、裁决分布、冲突率、成本与延迟。

### M2.4：Claim 合并与受控提升

1. 合并同一事件中的支持、反驳和更新 Claim，保留来源及时间线。
2. 分别计算影响、新颖性、紧急性和可信度，禁止用一个总分掩盖不同含义。
3. 设计影子 AtomicEvent 到正式 Event 的可回滚提升策略，并只在达到门禁后启用。

完成条件：任一正式结论都可追溯到原文证据；更正或撤回生成新的 EventVersion，不覆盖历史。

### 日期热点 API 与 M3

语义事件和排序语义稳定后，实现按自然日、时区和 `as_of` 返回去重聚类后的热点快照，再建设日报冻结、生成和投递。API 契约应先于邮件/飞书适配器，避免展示层反向定义事件模型。

## 7. 下一次开发启动条件

下一次动手建议只启动 **M2.2.1 语义运行稳定化**，不同时铺开 Embedding、关系裁决和日期 API。开始前确认：

- 本页的里程碑排序获得认可；
- `benchmark` 是通用评测/基准实体，还是仅作为模型/数据集的属性；
- 失败原始响应的保存期限和脱敏要求；
- 下一轮实验仍使用 `deepseek-v4-flash`，且继续保持 Worker 自动语义调度关闭。

## 8. 相关文档

- [README](../README.md)：安装、运行、命令和能力概览。
- [M1 增量采集与分类](./m1-data-pipeline.md)：采集、生命周期和 HybridClassifier 契约。
- [M2.1 事件情报](./event-intelligence.md)：确定性局部去重、事件、版本和证据。
- [M2.2 语义富化](./semantic-enrichment.md)：影子表、任务契约和安全边界。
- [模型与 DeepSeek 配置](./model-configuration.md)：Profile、环境变量和密钥规则。
- [100 篇影子实验](./semantic-experiment-2026-07-31.md)：固定实验口径与实测结果。
- [评测目录说明](../evaluation/README.md)：确定性回归、可选 reviewed 样本和语义标注模板。
