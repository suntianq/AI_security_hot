# DeepSeek V4 Flash 首轮 100 篇影子实验

> 日期：2026-07-31  
> 模型：`deepseek-v4-flash`  
> 执行版本：`662ed8fa2adde5d8e03357aa8131d4a7`  
> Prompt：`m2.2-document-semantic-v2`  
> 模式：`json_object` + `thinking=disabled` + `shadow`  
> 后续路线：[项目当前状态与后续路线](./current-status.md)

## 范围与边界

正式实验固定选择 100 篇当前有效、已完成规则分类和 M2.1 去重的主文档。
查询同时硬排除：

- `tech_directions == ["cve"]`；
- 非空 CVE、GHSA、CNVD 标识；
- 已指向其他主文档的 duplicate child；
- 未完成确定性去重的文档。

因此 100 篇均为新闻/文章候选，CVE/GHSA/CNVD 命中数均为 0，且全部已有
`dedupe-v2`。本轮没有让影子结果修改正式 Event；收尾时 `dedupe` 和 `cluster`
均报告 `current`。

## 结果

| 指标 | 结果 |
|---|---:|
| 目标文档 | 100 |
| 严格校验成功 | 98 |
| 两次仍被拒绝 | 2 |
| API 尝试 | 103 |
| LLM 判定相关 | 26 |
| LLM 判定不相关 | 72 |
| 文档级实体 | 157 |
| 原子事件 | 106 |
| 抽取 Claim | 179 |
| 已记录 prompt tokens | 220,100 |
| 已记录 completion tokens | 74,150 |
| 已记录 total tokens | 294,250 |
| 平均调用延迟 | 5,284 ms |
| P95 调用延迟 | 16,148 ms |

失败调用在当前实现中没有保存 usage，因此 token 数是成功调用的可审计下界，
不能当作完整账单。

实体证据定位为 body 307、title 53、unknown 6，精确命中率约 98.4%；Claim
证据定位为 body 163、title 2、unknown 14，精确命中率约 92.2%。所有 Claim
都携带证据摘录，但 unknown 表示摘录没有在当前标题/正文中逐字定位。

## 真实问题

1. 最新优先抽样严重偏向单一来源：IT之家 90、AI HOT 6、Hacker News 2、
   OpenAI News 2。该批次能验证工程链路，不能代表全源质量。
2. 100 篇原有分类方法均为 `rule`；本轮 LLM 执行的是更完整的相关性、实体、
   原子事件、Claim 和证据抽取，不是 M1.3 HybridClassifier 重放。
3. 72 篇被 LLM 判为不相关，但确定性 M2.1 中 100 篇仍关联 101 个正式 Event。
   影子相关性尚未成为日报或事件提升门禁。
4. 两篇文章稳定输出 `entity_type=benchmark`，而当前 EntityType 枚举缺少该值，
   因而被严格拒绝。这是本体缺口，不应静默改写为 `other`。
5. DeepSeek V4 默认高强度思考。关闭 thinking 后，验证样本由约 33 秒、3,886
   completion tokens 降为约 1.4 秒、106 completion tokens；结构化抽取应默认
   禁用思考，把思考模式留给复杂事件关系裁决。

## 下一阶段顺序

1. 语义运行稳定化：先界定 `benchmark`（评测、排行榜或测试套件）是否值得作为独立实体；只有对候选召回和关系裁决有用时才加入版本化本体。同时保存无效原始输出、finish reason 和失败 usage，增加一次有界 Schema 修复并完整审计原始与修复结果。
2. 分层批次规划：按来源、语言、发布时间和内容类型设置配额，避免单一高频源
   垄断；提供固定 target batch ID，分类、抽取、评测复用同一批文档。
3. 自动语义评测：证据支持判断、原子事件过拆/漏拆、相关性和 Claim 忠实度由
   独立 judge 任务评分，thinking 可只在 judge 中按需启用。
4. 候选召回与关系裁决：强标识、实体、时间和 Embedding 只生成候选，再由 LLM
   输出 `same_event / related_event / different_event`；强标识冲突继续硬阻断。
5. 受控提升：先让相关性影响“每日热点候选”而不是删除正式证据；再把通过门禁
   的 AtomicEvent、Claim 和关系裁决提升到 EventVersion。
6. 日期热点 API：在受控提升稳定后实现按自然日、时区和 as-of 版本返回热点。

完整可视化结果已写入仓库根目录的本地 `report.html`（该文件被 gitignore）。
