# 项目当前状态与后续路线

> 状态快照：2026-08-03
> 本页是项目完成度、已知边界和实施顺序的唯一状态入口。

## 1. 当前结论

项目已经具备 19 个 endpoint 配置（18 active + 1 retired）、增量采集、文档
生命周期、规则/混合分类、M2.1 局部去重与确定性事件聚类、EventVersion /
Claim / Evidence、M2.2 LLM 影子抽取、M2.3 关系裁决骨架、M2.4 提升预览和
日期热点查询。

当前还不能称为完整的 LLM 事件情报产品：

- M2.2 默认只写影子表，不修改正式分类、去重或 Event。
- M2.3 只有共享实体 + 时间窗的确定性候选/裁决，没有 Embedding 或 LLM 裁决。
- M2.4 只有 pair 级 Claim 合并和 dry-run 提升预览，没有正式持久化提升。
- 日期热点 API 查询当前 Event 状态，不是冻结的历史日报快照。
- M2.3/M2.4 主要由手工 CLI 驱动，尚未进入 durable 自动任务链。

```text
Source
  → fetch / normalize / fulltext / classify
  → M2.1 local dedupe / deterministic cluster
  → Event / EventVersion / Claim / Evidence
  → query API / offline report

current non-CVE duplicate master
  → M2.2 LLM shadow extraction
  → Entity / AtomicEvent / ExtractedClaim
  → M2.3 candidate + relation verdict (shadow)
  → M2.4 claim merge + promotion preview (shadow)
  ── formal event promotion not implemented
```

## 2. 里程碑完成度

| 里程碑 | 状态 | 已完成 | 主要边界 |
|---|---|---|---|
| M0 工程与部署 | 基础完成，正在硬化 | PostgreSQL/Alembic、API、worker、CLI、CI；统一镜像、独立 migrate、健康探针、macOS DB-free CI | Playwright 仍只是预留；当前旧容器需在本批代码完成后重新部署 |
| M1.1 规则分类 | 完成 | CVE 独立类别；新闻/论文主题分类；分类溯源 | 深层语义仍需模型 |
| M1.2 增量与生命周期 | 完成 | AI HOT changes、NVD cursor、CISA 快照、Anthropic 双通道、修订/撤回/退役审计 | RSS 等源无法恢复上游窗口外历史 |
| M1.3 混合分类 | 机制完成 | Provider、Schema、缓存、运行审计、租约、fallback；CVE bypass | 存量正式分类没有全部经 LLM 重跑 |
| M2.1 局部事件情报 | 完成 | 持久签名/强身份/blocking、稳定组件、局部重算、硬冲突、EventVersion/Claim/Evidence | fallback 事件不等同于语义事件合并 |
| M2.2 语义抽取 | 影子机制完成 | 严格输出契约、证据定位、租约、缓存、实体/原子事件/Claim、分层抽样和聚合评测 | 失败调用审计不完整；本体版本未在输出字段上强约束；无独立 judge |
| M2.3 关系裁决 | 早期影子版 | 共享实体候选、same/related/different 确定性裁决、RelationVerdict | 候选扫描非增量且大桶 O(n²)；无 Embedding/LLM；审计字段不足 |
| M2.4 Claim 与提升 | 预览版 | exact-value Claim 合并、提升门禁、dry-run preview | 当前“置信度差=矛盾”语义错误；无事件组件合并、正式写入、回滚 |
| NVD/KEV 隔离 | 完成 | vuln_db/general 隔离，旧 cve 事件 supersede | `min_cve_year` 会漏掉最近更新的旧编号 CVE |
| 日期热点 API | 当前态查询完成 | `/v1/daily-hotspots?date&tz&category` | 无日报冻结、`as_of`、历史排名和分页 |
| M3 日报与投递 | 未开始 | 设计边界已存在 | 快照、生成、投递、更正通知均未实现 |

“机制完成”不表示历史数据全部用模型重跑，也不表示影子结果已进入正式事件。

## 3. 2026-08-03 部署硬化

本批已在代码仓实现：

- API、worker、migrate 使用同一镜像和 `INTEL_BUILD_SHA`。
- Alembic 与 source sync 归独立一次性 `migrate` 服务；失败时 API/worker 不启动。
- API 增加 `/health/live`、`/health/ready`，readiness 校验数据库和 Alembic head。
- worker 每 30 秒刷新 heartbeat，Compose 可发现调度器停止派发。
- PostgreSQL/API 默认只绑定 `127.0.0.1`，容器增加重启策略。
- 读取与 `/ops/*` 分别使用 `INTEL_API_TOKEN`、`INTEL_ADMIN_API_TOKEN`。
- 抓取器跨 origin 重定向会删除 Authorization/Cookie；代理路线也执行 DNS 私网校验。
- report 模板正式进入 Git，并对嵌入 JSON 做 script 终止字符转义。
- 默认 CI 使用 PostgreSQL 18；真实信源测试改为手工工作流；增加 macOS DB-free 门禁。

运行中的旧 API/worker 不会因代码文件变化自动升级。完成测试和提交后必须用同一
Git SHA 重建整套应用服务，不能只重建其中一个。

## 4. 已知问题

### 4.1 部署和 API

- `/ops/tick` 虽已使用管理员 Token，仍在 HTTP 请求内同步执行完整流水线；
  后续应改成持久任务入队并返回 202，同时禁止重复并发执行。
- 健康检查可以发现 worker 停止派发，但尚未提供跨实例历史 heartbeat/告警表。
- Docker 基础镜像已固定 uv 版本，但 Python/PostgreSQL 仍是浮动 minor tag；
  发布流程还应记录最终镜像 digest。
- 当前没有稳定的 API response schema、游标分页和统一 `/v1` 路径。

### 4.2 M2.2 语义运行

- Schema 修复最终失败时，异常没有携带全部原始无效响应、finish reason 和 usage；
  失败成本与模型行为无法完整审计。
- `ontology_version` 仍由模型输出普通字符串，应由服务端固定或使用 Literal 校验。
- 抽样会将大量 eligible 文档加载进 Python；真正的大库抽样应转为数据库分层查询。
- 语义评测 p50/p95 尚未稳定持久化，LLM-as-judge 仍未实现。

### 4.3 M2.3 候选和裁决

- 当前先读取所有共享实体，再在桶内两两配对；高频实体会造成 O(n²)。
- 缺少实体类型/角色/置信度过滤、候选时间窗预过滤、大桶保护和扫描游标。
- 没有优先排除已裁决 pair，候选顺序也不稳定。
- pair 没有统一 canonical orientation，algorithm_version 更新审计不完整。
- 没有强身份冲突解释、Embedding 候选和 LLM 三分类审计。

### 4.4 M2.4 Claim 和正式事件

- 相同规范值只因置信度差距大就标记 contradict，这是错误语义。
- 真正不同的规范值被分到不同组，反而不会进行冲突判断。
- 只处理单个 pair，没有 relation component 的传递合并。
- preview 使用临时事件属性和当前时间；无正式 apply、幂等、回滚和版本审计。

### 4.5 日期热点和存储

- 日期接口按当前 `last_seen_at` 过滤，后续更新可能使事件从旧日期移动到新日期。
- 需要 `daily_hotspot_snapshot/items` 保存排名、EventVersion、证据和算法版本。
- 当前数据库约 6.3 GB；最大表是 block token、raw item、document 和 event version。
  冷启动前应实现 raw 保留、无变化版本抑制、候选复核归档和大表增长监控。

## 5. 已完成的真实实验

DeepSeek V4 Flash 首轮固定 100 篇 current、非 CVE duplicate master：

| 指标 | 结果 |
|---|---:|
| 成功 / retry | 98 / 2 |
| 相关 / 不相关 | 26 / 72 |
| 实体 / 原子事件 / Claim | 157 / 106 / 179 |
| 已记录成功调用 token | 294,250 |
| 平均 / P95 延迟 | 5,284 ms / 16,148 ms |

后续 98 篇来源平衡样本：相关率 61.2%、证据精确命中 86%、结构失败 0。
这些是工程与代理质量指标，不是人工金标 precision/recall/F1。

## 6. 后续实施顺序

1. 完成本批部署硬化测试、clean-clone 验证和文档收敛。
2. 修复 M2.2 失败审计与本体版本强约束。
3. 将 M2.3 改为有界、确定性、可恢复的增量候选队列，再加入 Embedding。
4. 增加有审计记录的 LLM relation adjudicator，强冲突继续硬阻断。
5. 重写 Claim 冲突/支持语义，按 relation component 合并并持久化。
6. 实现 shadow → formal Event 的幂等提升、版本、回滚与门禁。
7. 实现每日热点快照和 `as_of` API。
8. 增加数据保留/归档策略，完成一次 Apple Silicon 冷启动演练。
9. M3 再接日报生成、邮件/飞书投递和更正通知。

## 7. 冷启动迁移门槛

新服务器不恢复旧数据库是推荐路径，但发布版本必须满足：

- clean clone 中 report 模板存在且可生成页面；
- 空 PostgreSQL 18 可从零升级到 Alembic head；
- migrate 成功后 API/worker 使用相同 Git SHA；
- API/worker 均 healthy，worker 能持续刷新来源状态；
- PostgreSQL 不暴露公网，read/admin Token 分离；
- Linux、macOS DB-free CI 和全部非 live 数据库测试通过；
- 最高严重级别抓取与报告注入问题已修复。

操作说明见 [部署与冷启动](./deployment.md)。

## 8. 相关文档

- [README](../README.md)：能力概览、常用命令。
- [部署与冷启动](./deployment.md)：Linux/macOS 配置、启动、升级、验收。
- [M1 增量采集与分类](./m1-data-pipeline.md)：采集、生命周期和分类契约。
- [M2.1 事件情报](./event-intelligence.md)：局部去重、事件、版本和证据。
- [模型与 DeepSeek 配置](./model-configuration.md)：Profile、环境变量和密钥规则。
- [评测目录](../evaluation/README.md)：确定性回归与可选 reviewed 样本。


## 2026-08-03 hardening status

Implemented in code and migration `33e4be894d94`: complete semantic call-attempt audit, strict ontology version, incremental recoverable relation queue, proposition-aware Claim conflicts, transactional/idempotent/version-guarded promotion rollback, and immutable daily snapshots with as-of lookup. The production/runtime database has not been migrated or restarted by this change.
