# 项目当前状态与后续路线

> 状态快照：2026-08-03
> 本页是项目完成度、已知边界和实施顺序的唯一状态入口。

## 1. 当前结论

项目已经具备 19 个 endpoint 配置（18 active + 1 retired）、增量采集、文档生命周期、规则/混合分类、M2.1 局部去重与确定性事件聚类、M2.2 LLM 影子抽取，以及经过生命周期加固的 M2.3/M2.4：

- 每次 LLM initial/repair 调用均可记录安全响应正文、usage、finish reason、校验错误和 provider 错误。
- ontology_version 由代码中的 semantic-onto-v1 Literal/JSON-Schema const 强制约束。
- M2.3 使用带游标、租约、fencing token、指数退避和版本隔离的有界增量队列；worker 自动调度。
- same-event 图已物化为稳定 relation component：成员扩展/局部分裂尽量保留 ID，membership 保留历史，generation queue 保证处理中再次失效不会丢任务，周期发现不会反复增加未完成 generation 或重置终态失败。
- 只有当前文档和当前 relation-v2 的 same_event 边能进入正式提升组件；related_event 只保留关联语义，不能误合并。
- Claim 的置信度不再表示正反立场；只有显式布尔冲突或已知相反命题才成为 disputed。
- event-promote 默认预览；显式 --apply 才事务化写 Event、Document、Claim、Evidence 和 EventVersion。重复执行幂等，回滚受事件版本保护并恢复完整旧状态。
- worker 定期冻结当天和前一天的热点 revision；API 的 as_of 读取对应时点以前已存储的快照，不从当前 Event 反推历史。

M2.2 仍默认是影子模式，不会自动修改正式分类或 Event；正式提升仍是显式人工/运维动作，不会被 worker 自动执行。

~~~text
Source
  → fetch / normalize / fulltext / classify
  → M2.1 local dedupe / deterministic cluster
  → Event / EventVersion / Claim / Evidence
  → frozen daily snapshot → as_of API

current non-CVE duplicate master
  → M2.2 LLM shadow extraction
  → Entity / AtomicEvent / ExtractedClaim
  → M2.3 durable candidate queue → versioned relation verdict
  → same_event connected component → Claim merge
  → preview
  → explicit --apply → formal versioned Event
  → guarded rollback when required
~~~

## 2. 里程碑完成度

| 里程碑 | 状态 | 已完成 | 主要边界 |
|---|---|---|---|
| M0 工程与部署 | 基础完成，持续硬化 | PostgreSQL/Alembic、API、worker、CLI、CI；统一镜像、独立 migrate、健康探针、macOS DB-free CI | Playwright 仍只是预留；发布时仍需用同一 Git SHA 重建 API/worker |
| M1.1 规则分类 | 完成 | CVE 独立类别；新闻/论文主题分类；分类溯源 | 深层语义仍需模型 |
| M1.2 增量与生命周期 | 完成 | AI HOT changes、NVD cursor、CISA 快照、Anthropic 双通道、修订/撤回/退役审计 | RSS 等源无法恢复上游窗口外历史 |
| M1.3 混合分类 | 机制完成 | Provider、Schema、缓存、运行审计、租约、fallback；CVE bypass | 存量正式分类没有全部经 LLM 重跑 |
| M2.1 局部事件情报 | 完成 | 持久签名/强身份/blocking、稳定组件、局部重算、硬冲突、EventVersion/Claim/Evidence | fallback 事件不等同于语义事件合并 |
| M2.2 语义抽取 | 影子机制完成并加固 | 严格输出契约、完整逐次调用审计、本体常量、证据定位、租约、缓存、实体/原子事件/Claim、分层抽样和聚合评测 | 无独立 judge；抽样和时延统计仍可扩展 |
| M2.3 关系裁决 | 持久组件版 | 强实体过滤、持久游标、候选队列、租约恢复、稳定组件 ID、历史 membership、局部拆分合并、版本化裁决和 worker 调度 | 尚无 Embedding 与 LLM 三分类；完全消失后再出现的组件历史复用仍可增强 |
| M2.4 Claim 与提升 | revision 化正式提升 | 命题级冲突、稳定 component key/revision、基于真实 AtomicEvent/Document 的预览、事务 apply、幂等、完整版本和安全回滚 | 重要性、新颖性、紧急性仍需专门判断层；自动提升未开放 |
| NVD/KEV 隔离 | 完成 | vuln_db/general 隔离，旧 cve 事件 supersede | min_cve_year 会漏掉最近更新的旧编号 CVE |
| 日期热点 API | 冻结快照完成 | 不可变 revision、并发锁、worker 定期生成、as_of 查询 | as_of 只能选择当时已生成的快照，不做任意时点事件重建；无游标分页 |
| M3 日报与投递 | 未开始 | 已有冻结热点输入 | 日报文案、投递、更正通知尚未实现 |

“机制完成”不表示历史数据已全部用模型重跑，也不表示每个影子结果都已提升为正式事件。

## 3. 部署硬化

代码仓已经实现：

- API、worker、migrate 使用同一镜像和 INTEL_BUILD_SHA。
- Alembic 与 source sync 归独立一次性 migrate 服务；失败时 API/worker 不启动。
- API 提供 liveness/readiness，readiness 校验数据库和 Alembic head。
- worker heartbeat 可发现调度器停止派发。
- PostgreSQL/API 默认只绑定 127.0.0.1；读取和运维 Token 分离且 fail-closed。
- 抓取器跨 origin 重定向会删除 Authorization/Cookie，代理路线也执行 DNS 私网校验。
- 默认 CI 使用 PostgreSQL 18；真实信源测试为手工工作流；另有 macOS DB-free 门禁。
- 当前迁移 head 为 6f23c8a1d4b7，已在隔离 PostgreSQL 18 验证 upgrade、downgrade、再次 upgrade 和 ORM metadata check。

运行中的 API/worker 不会因工作区文件变化自动升级。发布时必须先备份需要保留的数据，再由 migrate 升级 schema，并用同一 Git SHA 重建 API/worker。新服务器若不需要旧数据，可以直接从空数据库冷启动，不必搬迁现有数据。

## 4. 仍需改进

### 4.1 部署和 API

- /ops/tick 仍在 HTTP 请求内同步执行完整流水线；应改为持久任务入队并返回 202。
- heartbeat 尚无跨实例历史和主动告警。
- Python/PostgreSQL 基础镜像仍应进一步固定 digest。
- API response schema、游标分页和统一版本化路径仍需收敛。
- 需要在 Apple Silicon 上做一次真实 cold-start、抓取、快照和报告验收。

### 4.2 语义抽取与评测

- 来源平衡抽样仍会把较多 eligible 文档加载到 Python，应改为数据库分层抽样。
- 每篇调用的 started/finished 时间尚未形成稳定 p50/p95 数据。
- LLM-as-judge 可作为代理质量信号，但不能冒充人工 precision/recall/F1。
- 原子事件指纹仍依赖规范化后的模型字段；稳定 component 已隔离普通成员增删，但模型重抽取产生全新原子事件且旧组件完全消失时，还需要历史身份复用策略。

### 4.3 候选召回与裁决

- 目前只有强实体 + 确定性规则召回，没有 Embedding/pgvector。
- 缺少带完整 prompt/响应审计的 LLM same_event / related_event / different_event 裁决器。
- relation component 已改为 seed + 旧 membership + 当前 same-event 边的有界局部闭包；超限会保留队列失败审计，不会截断后误提交。
- 仍需把强身份冲突原因完整带入关系裁决和人工复核界面。

### 4.4 正式事件与日报

- 自动正式提升未开放；当前必须审阅 preview 后显式 --apply。
- 正式 Event 已使用持久 component key；若两个已经正式提升的组件后来合并，旧 Event 的自动 supersede 仍应保持人工门禁。
- 标题、摘要、事件类型、主题、重要性、新颖性和紧急性需要专门判断层，不能长期使用通用占位推导。
- 快照目前冻结 Event payload 和 event_version；后续日报产品还要冻结生成参数/算法版本、文案、投递批次和更正记录。
- 数据库增长仍需 raw/blob 保留、候选归档和大表监控策略。

## 5. 已完成的真实实验

DeepSeek V4 Flash 首轮固定 100 篇 current、非 CVE duplicate master：

| 指标 | 结果 |
|---|---:|
| 成功 / retry | 98 / 2 |
| 相关 / 不相关 | 26 / 72 |
| 实体 / 原子事件 / Claim | 157 / 106 / 179 |
| 已记录成功调用 token | 294,250 |
| 平均 / P95 延迟 | 5,284 ms / 16,148 ms |

后续 98 篇来源平衡样本：相关率 61.2%、证据精确命中 86%、结构失败 0。这些是工程与代理质量指标，不是人工金标 precision/recall/F1。

## 6. 推荐后续顺序

1. 完成本批全量 CI 等价测试、文档收敛和 clean-database 验证。
2. 实现 Embedding/pgvector 候选召回，只生成候选，不绕过强冲突。
3. 增加可审计的 LLM 关系裁决和中置信人工复核。
4. 增加事件判断层：标题/摘要、影响、新颖性、紧急性、可信度和证据充分性。
5. 增强冻结日报：算法参数、生成文案、更正记录、分页与投递批次。
6. 实现数据保留/归档和容量监控。
7. 在 Apple Silicon 新服务器完成空库冷启动演练。
8. 进入 M3 邮件/飞书投递和更正通知。

## 7. 冷启动迁移门槛

新服务器不恢复旧数据库是推荐路径，但发布版本必须满足：

- clean clone 中 report 模板存在且可生成页面；
- 空 PostgreSQL 18 可从零升级到 Alembic head；
- migrate 成功后 API/worker 使用相同 Git SHA；
- API/worker 均 healthy，worker 能持续抓取、生成关系候选和冻结快照；
- PostgreSQL 不暴露公网，read/admin Token 分离；
- Linux、macOS DB-free CI 和全部非 live 数据库测试通过。

操作说明见 [部署与冷启动](./deployment.md)。

## 8. 相关文档

- [README](../README.md)：能力概览、常用命令。
- [部署与冷启动](./deployment.md)：Linux/macOS 配置、启动、升级、验收。
- [M1 增量采集与分类](./m1-data-pipeline.md)：采集、生命周期和分类契约。
- [M2 事件情报](./event-intelligence.md)：局部去重、语义关系、正式提升、版本和快照。
- [模型与 DeepSeek 配置](./model-configuration.md)：Profile、环境变量和密钥规则。
- [评测目录](../evaluation/README.md)：确定性回归与可选 reviewed 样本。
