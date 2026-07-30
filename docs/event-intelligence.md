# M2 事件情报实现说明

> 状态：M2.0 确定性基线已实现
> 最后更新：2026-07-30
> 算法版本：`dedupe-v1` / `cluster-v1`

M2.0 的目标是把 `Document` 转成可查询、可追溯、可增量重放的 `Event`，同时保持保守合并：宁可暂时拆成两个事件，也不把两个不同漏洞错误合并。该阶段不依赖 LLM，模型不可用不会阻塞采集和事件化。

## 1. 数据流

```text
RawItem → Document → RuleClassifier
                    ↓
              dedupe-v1
        exact / near duplicate component
                    ↓
              cluster-v1
      strong key or fallback event identity
                    ↓
       Event + EventDocument evidence
                    ↓
         GET /events + GET /events/{id}
```

`raw_items.stage` 仍只表达采集和正文处理状态。M2 使用 `Document.dedupe_version` 与 `Document.cluster_version` 作为独立状态，避免已分类文档因为旧 stage 值被重复处理或漏处理。

## 2. 非破坏式去重

任何规则都不会删除 `Document`。重复文档只写入：

- `near_dup_of`：主文档 ID；主文档本身为 `NULL`。
- `duplicate_kind`：`exact_url / exact_title / exact_content / near_title`。
- `duplicate_score`：精确重复为 `1.0`，近标题为 `0～1`。
- `dedupe_version / deduped_at`：重放版本与处理时间。

主文档按以下顺序选择：来源可信度 A → B → C、解析质量、正文长度、标题长度、文档 ID。所有原始证据仍能单独查询。

### 2.1 合并规则

1. URL 相同：没有强标识时可合并；存在 CVE/GHSA/CNVD 时，只有共享至少一个强标识的文档才合并。
2. 标准化标题相同：标题压缩长度至少 20，发布时间相差不超过 30 天，且强标识不冲突。
3. 标准化正文相同：正文至少 200 字符、标题相似度至少 80、发布时间相差不超过 30 天，且强标识不冲突。
4. 近似标题：使用英文词和中文二元组做候选阻塞，再用 RapidFuzz 比较；要求双方都有发布时间且相差不超过 14 天、标题长度比例至少 0.72、综合相似度至少 94，原序相似度至少 88。

候选阻塞忽略超过 100 条文档的高频 token 桶，避免数据增长后退化成全量两两比较。

### 2.2 强标识冲突保护

不同 CVE/GHSA/CNVD 的标题经常高度相似，CISA KEV 等结构化源还会让很多条目共享同一个目录 URL。因此：

- 两份文档都有强标识且集合互斥时，标题/正文规则禁止合并。
- 共享目录 URL 不被当作条目身份；只在强标识相同或重叠时合并。
- 一个重复组件若意外包含超过 20 个强事件键，聚类会退化为每份文档只关联自身强键，禁止产生“强键数 × 文档数”的关系膨胀。

## 3. 事件身份与证据

事件指纹按强度排序：

| 输入 | Event fingerprint | 类型/主题 |
|---|---|---|
| CVE | `cve:CVE-YYYY-NNNN` | `vulnerability / cve` |
| GHSA | `ghsa:GHSA-...` | `vulnerability / cve` |
| CNVD | `cnvd:CNVD-...` | `vulnerability / cve` |
| arXiv | `arxiv:YYMM.NNNNN`（忽略 `v1/v2`） | `research / 文档主题` |
| 无强键 | `document:<master_document_id>` | 分类结果 / 文档主题 |

同一重复组件中的强键会传播给组件内证据，因此一份未成功抽取 CVE 的转载仍可跟随主证据进入该 CVE 事件。一个包含多个 CVE 的分析文章可以同时作为多个漏洞事件的证据。

`EventDocument` 保留：

- `evidence_level`：来源的 A/B/C 等级。
- `relation_reason`：`identifier:cve` 等强键原因，或具体重复原因。
- `stance`：M2.0 固定为 `support`；争议信息在后续 Claim/Evidence 版本实现。

事件聚合保存稳定指纹、主题、事件类型、确定性摘要、首次/末次观测时间、证据等级、规则分、聚类版本和当前版本号。失去当前指纹的旧派生事件会标记为 `superseded`，其旧证据关系保留用于审计。

## 4. 可解释规则分

当前 `score` 是 0～100 的静态证据质量分，不是紧急度、利用概率或个性化相关性。公式为：

```text
最佳来源等级：A=40，B=28，C=15，未知=10
身份强度：CVE/GHSA/CNVD=25，arXiv=15，fallback=5
独立来源：min(20, (source_count - 1) × 7)
解析质量：round(max(parse_quality) × 15)
总分：min(100, 上述四项之和)
```

事件 `evidence_level` 取全部证据中的最高来源等级。分数没有时间衰减，避免仅因时钟推进就不断创建事件版本；排序层可以在 M3 另行叠加 recency、urgency 和 watchlist relevance。

## 5. 增量、幂等与并发

- 新 `Document` 的版本字段为空，下一次 Worker tick 自动处理。
- 正文更新会清空去重和聚类版本；分类变化会清空聚类版本。
- 去重主记录或算法版本变化会使受影响文档的聚类版本失效。
- 没有待处理文档时，两个阶段直接返回 `status=current`，不会扫描全文。只要出现过期文档，M2.0 会全局重算组件/事件以保证新旧证据能重新选主，但只写入变化记录；持久化候选索引和局部组件重算属于规模增长后的 M2.1 优化。
- 算法版本升级时可全量重放；派生数据以事件 fingerprint 和 `(event_id, document_id)` 唯一约束保持幂等。
- dedupe 与 cluster 分别使用 PostgreSQL transaction advisory lock，手动命令和 Worker 不会并发写同一阶段。

首次回填后，普通重跑和 `cluster --force` 均应报告事件/关系新增、更新、删除为 0。

## 6. 运维命令

```bash
uv run alembic upgrade head  # 升级到 e71a2c9d4f10
uv run intel eventize        # dedupe + cluster
uv run intel dedupe          # 只处理版本过期文档
uv run intel cluster         # 只处理版本过期文档
uv run intel dedupe --force  # 强制重放规则
uv run intel cluster --force
uv run intel stats           # documents / near_duplicates / events / links
uv run intel self-check      # 含 dedupe_due / cluster_due
```

`intel run-once` 和常驻 `intel worker` 的顺序均为：fetch → normalize → fulltext → classify → dedupe → cluster。

## 7. API

```http
GET /events?topic=cve&event_type=vulnerability&evidence_level=A&min_score=80&since=2026-07-01T00:00:00Z&limit=20
GET /events/{event_id}
GET /stats
POST /ops/tick
```

列表接口返回文档数和独立 source 数；详情接口返回每份证据的来源、URL、发布时间、解析质量、来源等级和关联原因。当前接口尚无认证，只能放在可信内网或受保护网关之后。

## 8. 2026-07-30 首次回填快照

该快照只用于验证量级，数据会随采集继续增长：

- 6,066 份文档。
- 35 份近重复，最大重复组件 3 份文档。
- 6,022 个当前事件，6,101 条证据关系。
- 单事件最多 3 份证据；单文档最多关联 5 个事件。
- 去重约 5 秒、峰值约 177 MB；聚类约 4 秒、峰值约 173 MB。
- 普通重跑与强制聚类重跑均为 0 新增、0 更新、0 关系变化。

## 9. M2.0 边界与 M2.1

当前明确未实现：

- 模型+版本、公司+事故等实体强键。
- SimHash/MinHash、向量或 LLM 语义聚类；现阶段只自动合并非常接近的标题。
- 大规模数据下的持久化候选索引和局部组件重算；M2.0 有过期文档时会全局一致性重算。
- LLM 中文摘要、影响分析和不确定性表达。
- Claim/Evidence 争议状态、完整 EventVersion 快照和人工复核队列。
- CVSS/EPSS/KEV 利用状态驱动的 urgency 分，以及用户 Watchlist relevance。

M2.1 应先建立人工标注的“应合并/不应合并”样本和误合并率指标，再逐步扩大语义候选范围。高风险安全事件不应仅凭向量相似度自动合并。
