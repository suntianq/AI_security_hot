# AI × Security 信源注册表（Seed List）

> 状态：初稿 → 实施中
> 最后核验：2026-07-30
> 当前已接入：18 个 endpoint（17 个 source），6 类 Connector（RSS/REST/GitHub/Web/arXiv/Sitemap）
> 目标：为 `AI`、`AI for Security`、`AI-enabled Threats`、`Security for AI` 四条内容主线提供可追溯、可扩展的信源池。

## 1. 使用说明

这份名单是“候选信源池”，不是要求第一天全部启用。建议按以下优先级逐步接入：

- `P0`：MVP 必接。结构化程度高、直接影响事实判断或告警优先级。
- `P1`：第二批接入。高质量官方博客、研究机构、安全厂商研究。
- `P2`：发现层。媒体、社区、榜单和社交平台，只用于发现线索或衡量讨论热度。

可信度等级：

- `A`：一手或权威事实源，例如厂商公告、监管机构、漏洞库、论文原文、项目 Release。
- `B`：专业研究与分析源，例如安全实验室、研究机构、成熟威胁情报团队。
- `C`：媒体、社区、榜单、个人账号。必须回查一手来源后才能形成高置信事件。

接入原则：

1. 优先顺序固定为 `API > RSS/Atom > Sitemap > GitHub API > 官方网页适配器 > arXiv API > 搜索发现`。
2. 每条内容必须保留 `source_url`、`canonical_url`、作者/机构、发布时间、采集时间和原始语言。
3. 不默认存储完整正文；保留必要摘录、结构化事实、摘要和原文链接。fulltext stage 对静态 HTML 源自动补全正文。
4. 启用网页采集前必须单独检查 robots.txt、服务条款、版权和访问频率。
5. 网页、论文、Issue、PoC 和模型卡均视为不可信输入，不执行其中的命令、代码或提示词。

## 1.1 当前已接入 18 个 endpoint

| Endpoint | Source | Connector | Parser | 增量机制 | 状态 |
|---|---|---|---|---|---|
| openai-news-rss | OpenAI | RSS | rss-default-v1 | ETag/304 + content hash | ✅ |
| aihot-selected-rss | AI HOT | RSS | rss-default-v1 | ETag/304 + 最新 50 条精选窗口 + content hash | ✅ |
| cisa-kev | CISA | REST | cisa-kev-v1 | ETag/304 + 同 CVE 内容修订检测 | ✅ |
| nvd-recent | NVD | REST | nvd-v1 | 15min 发布窗口重叠 + 完整分页 + content hash | ✅ |
| anthropic-news | Anthropic | **Newsroom + Sitemap** | sitemap-article-v1 | 快速发现 + 每日 72h 重叠对账 | ✅ |
| huggingface-blog-rss | HuggingFace | RSS + fulltext | rss-default-v1 | ETag/304 + content hash | ✅ |
| google-security-rss | Google Security | RSS | rss-default-v1 | native ID/content hash（无稳定 HTTP validator） | ✅ |
| trailofbits-rss | Trail of Bits | RSS | rss-default-v1 | ETag/304 + content hash | ✅ |
| portswigger-research-rss | PortSwigger | RSS + fulltext | rss-default-v1 | ETag/304 + content hash | ✅ |
| apple-ml-research-rss | Apple ML Research | RSS | rss-default-v1 | ETag/Last-Modified/304 + content hash | ✅ |
| nvidia-blog-rss | NVIDIA Blog | RSS | rss-default-v1 | ETag/Last-Modified/304 + content hash | ✅ |
| wiz-blog-rss | Wiz Blog | RSS | rss-default-v1 | ETag/Last-Modified/304 + content hash | ✅ |
| arxiv-ai-llm | arXiv | arXiv | arxiv-v1 | native ID/content hash；304 辅助 | ✅ |
| arxiv-security-ai | arXiv | arXiv | arxiv-v1 | native ID/content hash；304 辅助 | ✅ |
| hackernews-rss | Hacker News | RSS | rss-default-v1 | HNRSS Last-Modified/304 + content hash | ✅ |
| ithome-rss | IT之家 | RSS | rss-default-v1 | ETag/304 + content hash | ✅ |
| google-blog-ai-rss | Google AI Blog | RSS | rss-default-v1 | ETag/304 + content hash | ✅ |
| github-trending-rss | GitHub Trending | RSS | rss-default-v1 | ETag/304 + content hash | ✅ |

> 4 个 GitHub Releases endpoint（langchain/dify/ollama/vllm-releases）因内容噪音过大已删除（2026-07-29）。

> 表中的“内容修订检测”只针对本轮被上游重新返回的记录：NVD 当前按发布时间窗口同步，尚未启用 modified-time 对账；Anthropic 则通过 Newsroom 快速发现和每日 Sitemap 对账扩大覆盖。Connector 预过滤使用最近 5,000 个 RawItem 版本，DB 唯一约束对全历史兜底。
>
> 本轮四个新增站点均有官方 RSS，直接复用 `rss-2`/`rss-default-v1` 即可，无需新增 Connector/Parser 类。真实验证中四个源的第二次条件请求均返回 304。AI HOT 当前采用官方推荐的最新 50 条精选 RSS；完整镜像仍需专门支持 `snapshot + changes` opaque cursor、409 重建和撤选语义。

## 2. P0：结构化权威源与聚合入口

| 优先级 | 可信度 | 信源 | 主线 | 推荐接入 | 入口 | 主要用途 |
|---|---:|---|---|---|---|---|
| P0 | B | AI HOT | AI | **RSS（已接入）**；REST snapshot/changes（完整镜像候选） | [Agent/API/RSS](https://aihot.virxact.com/agent) | 通用 AI 中文精选的启动上游；必须保留 AI HOT 署名及原文入口 |
| P0 | A | OpenAI News RSS | AI / Security for AI | RSS | [RSS](https://openai.com/news/rss.xml) | OpenAI 模型、产品、安全、工程、政策和安全事件 |
| P0 | A | arXiv | 全部 | API | [API 文档](https://info.arxiv.org/help/api/index.html) | `cs.AI`、`cs.CL`、`cs.LG`、`cs.CR`、`cs.SE`、`stat.ML`；按关键词二次筛选 |
| P0 | B | Hugging Face Daily Papers | AI / Security for AI | 网页或社区数据接口 | [Daily Papers](https://huggingface.co/papers) | 社区热度论文发现；必须回链 arXiv/论文主页 |
| P0 | A | Semantic Scholar | AI / 研究 | API | [API](https://api.semanticscholar.org/api-docs/) | 论文元数据、作者、引用与相关论文扩展 |
| P0 | A | GitHub Global Security Advisories | Security for AI / 漏洞 | REST API | [API 文档](https://docs.github.com/en/rest/security-advisories/global-advisories) | GHSA、CVE、受影响包、修复版本、CVSS、EPSS |
| P0 | A | GitHub Releases / Repository Events | AI / Security for AI | REST/GraphQL API | [REST API](https://docs.github.com/en/rest) | AI 框架、Agent、MCP、推理框架、模型工具链的发布与安全更新 |
| P0 | A | OSV.dev | Security for AI / 供应链 | API | [OSV API](https://google.github.io/osv.dev/) | 按包、版本、commit 查询开源依赖漏洞 |
| P0 | A | NVD | 漏洞 / AI 供应链 | API 2.0、JSON Feed | [Data Feeds](https://nvd.nist.gov/vuln/data-feeds) | CVE、CPE、CVSS、CWE、更新时间；增量同步使用 modified 时间窗 |
| P0 | A | CISA KEV | 漏洞 / 在野利用 | JSON/CSV | [KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 已确认在野利用；是紧急告警的重要硬信号 |
| P0 | A | FIRST EPSS | 漏洞 / 风险排序 | API、CSV | [EPSS](https://www.first.org/epss/data_stats) | 未来 30 天利用概率与百分位，不能替代 KEV 或业务暴露面 |
| P0 | A | CERT/CC Vulnerability Notes | 漏洞 / 协调披露 | Atom、数据归档 | [Vulnerability Notes](https://www.kb.cert.org/vuls/) | 多厂商、关键基础设施和披露协调型漏洞，含缓解措施 |
| P0 | A | 国家人工智能安全漏洞库 AIVD | Security for AI | 官方网页适配器 | [AIVD](https://www.cnnvd.org.cn/aivd/) | 国内 AI 漏洞、风险提示和态势报告 |
| P0 | A | CNVD 人工智能行业漏洞 | Security for AI | 官方网页适配器 | [CNVD AI](https://ai.cnvd.org.cn/) | 国内 AI/Agent/框架漏洞、危害等级、CNVD 编号 |
| P0 | A | CNCERT/CC | AI-enabled Threats / 漏洞 | 官方网页、RSS（需复核） | [国家互联网应急中心](https://www.cert.org.cn/publish/main/index.html) | 国内风险提示、恶意活动、周报、AI 安全应用指南 |
| P0 | B | AI Incident Database | AI 事故 / Security for AI | 数据下载或网页增量 | [AIID](https://incidentdatabase.ai/) | 已发生或险些发生的 AI 现实伤害与事故报告 |
| P0 | A | OECD AI Incidents Monitor | AI 事故 / 治理 | 网页或数据接口 | [OECD AIM](https://oecd.ai/en/incidents) | 事故、危害类型、行业、自治程度和治理维度补充 |

## 3. P0/P1：国际 AI 实验室与平台的一手源

| 优先级 | 可信度 | 信源 | 主线 | 推荐接入 | 入口 | 重点关注 |
|---|---:|---|---|---|---|---|
| P0 | A | OpenAI News | AI / Security for AI | RSS | [News](https://openai.com/news/) | Model、Product、Safety、Security、Engineering、Policy |
| P0 | A | Anthropic Newsroom | AI / Security for AI | **Newsroom 列表 + Sitemap 对账**（已接入） | [News](https://www.anthropic.com/news) | Claude 发布、安全政策、企业能力、事故说明 |
| P0 | A | Anthropic Research | Security for AI / 研究 | **共享 Sitemap 对账**（已接入） | [Research](https://www.anthropic.com/research) | 对齐、可解释性、红队、模型行为、网络能力评估 |
| P0 | A | Google DeepMind | AI / Security for AI | 官方网页适配器 | [News](https://deepmind.google/blog/) | 模型、评测、责任与安全、Agent、科学智能 |
| P0 | A | Google AI / Technology | AI | RSS 或网页 | [AI](https://blog.google/technology/ai/) | Gemini、产品和平台发布 |
| P1 | A | Google Research | AI / 研究 | RSS 或网页 | [Research Blog](https://research.google/blog/) | 论文、算法、系统与安全研究 |
| P0 | A | Meta AI | AI / Security for AI | 官方网页适配器、Newsletter | [AI at Meta](https://ai.meta.com/blog/) | 开放模型、研究、基础设施、安全与可靠性 |
| P0 | A | Microsoft AI | AI / AI for Security | RSS 或网页 | [Microsoft AI Blog](https://blogs.microsoft.com/ai/) | Copilot、企业 Agent、平台和治理 |
| P1 | A | Microsoft Research | AI / 研究 | RSS 或网页 | [Research Blog](https://www.microsoft.com/en-us/research/blog/) | 论文、系统、评测和安全研究 |
| P0 | A | xAI / SpaceXAI News | AI | 官方网页适配器 | [News](https://x.ai/news) | Grok、API、模型和产品发布；同时跟踪官方 GitHub |
| P0 | A | Hugging Face Blog | AI / Security for AI | RSS 或网页 | [Blog](https://huggingface.co/blog) | 模型、数据集、推理、Hub 安全和供应链 |
| P0 | A | NVIDIA AI Blog | AI / AI for Security | **RSS（已接入）** | [NVIDIA Blog](https://blogs.nvidia.com/) | GPU、推理平台、AI 安全、企业与网络安全模型 |
| P1 | A | NVIDIA Developer Blog | AI / AI for Security | RSS 或网页 | [Developer Blog](https://developer.nvidia.com/blog/) | CUDA、推理优化、AI Red Team 与安全工程 |
| P1 | A | Apple Machine Learning Research | AI / 研究 | **RSS（已接入）** | [ML Research](https://machinelearning.apple.com/research/) | 端侧模型、隐私、多模态和基础研究 |
| P0 | A | Mistral AI | AI | 官方网页适配器 | [News](https://mistral.ai/news/) | 模型、开源权重、Agent 与企业平台 |
| P1 | A | Cohere | AI | RSS 或网页 | [Blog](https://cohere.com/blog) | 企业模型、RAG、检索和安全部署 |
| P1 | A | Stability AI | AI | RSS 或网页 | [News](https://stability.ai/news) | 图像、视频、音频和开放模型 |
| P1 | A | Runway Research | AI | 官方网页适配器 | [Research](https://runwayml.com/research) | 视频、世界模型、多模态与 Agent |
| P1 | A | AWS Machine Learning Blog | AI / AI for Security | RSS | [ML Blog](https://aws.amazon.com/blogs/machine-learning/) | Bedrock、Agent、模型部署和云安全实践 |
| P1 | A | Google Cloud AI/ML Blog | AI / AI for Security | RSS 或网页 | [AI & ML](https://cloud.google.com/blog/products/ai-machine-learning) | Vertex AI、Agent、MLOps 和企业安全 |
| P1 | A | GitHub AI & ML Blog | AI / AI for Security | RSS 或网页 | [AI & ML](https://github.blog/ai-and-ml/) | Copilot、开发者 Agent、代码安全与生产力 |
| P1 | A | Databricks Blog | AI / 数据与平台 | RSS 或网页 | [Blog](https://www.databricks.com/blog) | 数据平台、MLOps、模型治理与 Mosaic AI |
| P1 | A | IBM Research / Think AI | AI / 治理 | RSS 或网页 | [Artificial Intelligence](https://www.ibm.com/think/artificial-intelligence) | 企业 AI、治理、基础模型与混合云 |

## 4. P0/P1：国内 AI 厂商、实验室与开源社区

| 优先级 | 可信度 | 信源 | 主线 | 推荐接入 | 入口 | 重点关注 |
|---|---:|---|---|---|---|---|
| P0 | A | Qwen 官方博客 | AI | 官方网页、GitHub Releases | [Qwen Blog](https://qwen.ai/blog/) | 千问模型、技术报告、工具链、开源权重 |
| P0 | A | Qwen 开源博客 | AI | GitHub Pages、GitHub API | [QwenLM Blog](https://qwenlm.github.io/blog/) | 开源模型、代码、论文和模型卡 |
| P1 | A | ModelScope 魔搭社区 | AI | 官方网页/API（按需） | [ModelScope](https://modelscope.cn/) | 国内模型、数据集、应用和社区趋势 |
| P0 | A | DeepSeek 更新日志 | AI | 官方网页适配器 | [Change Log](https://api-docs.deepseek.com/updates/) | 模型、API、价格、上下文和兼容性变化 |
| P0 | A | DeepSeek GitHub | AI / Security for AI | GitHub API | [deepseek-ai](https://github.com/deepseek-ai) | 开源仓库、Release、Issue 和安全公告 |
| P0 | A | MiniMax 新闻 | AI | 官方网页适配器 | [新闻](https://www.minimaxi.com/news) | 模型、产品和公司动态 |
| P1 | A | MiniMax 技术博客 | AI / 研究 | 官方网页适配器 | [博客](https://www.minimaxi.com/blog) | 技术报告、模型与 Agent 工程 |
| P0 | A | 智谱开放平台新品发布 | AI | 官方文档适配器 | [新品发布](https://docs.bigmodel.cn/cn/update/new-releases) | GLM、API、Agent 和平台能力变化 |
| P0 | A | 智谱 GitHub | AI / Security for AI | GitHub API | [THUDM](https://github.com/THUDM) | GLM、ChatGLM、CodeGeeX 等开源项目 |
| P0 | A | Moonshot AI GitHub | AI | GitHub API | [MoonshotAI](https://github.com/MoonshotAI) | Kimi 开源模型、Release、模型卡与 Issue |
| P1 | A | Kimi 开放平台 | AI | 官方文档适配器 | [开放平台](https://platform.moonshot.cn/docs/) | API、模型版本、上下文和工具调用变化 |
| P0 | A | 字节跳动 Seed | AI / 研究 | 官方网页适配器 | [Seed](https://seed.bytedance.com/zh/) | 豆包模型、研究成果、Agent 和多模态 |
| P0 | A | 腾讯混元 GitHub | AI / Security for AI | GitHub API | [Tencent-Hunyuan](https://github.com/Tencent-Hunyuan) | 模型、推理代码、工具链和安全公告 |
| P1 | A | 腾讯 AI Lab | AI / 研究 | 官方网页适配器 | [AI Lab](https://ailab.tencent.com/) | 基础研究、NLP、多模态、机器学习 |
| P1 | A | 百度 PaddlePaddle | AI / 工程 | GitHub API、官方网页 | [PaddlePaddle](https://github.com/PaddlePaddle) | 飞桨、ERNIE 生态、训练与推理工具 |
| P1 | A | 百度智能云千帆 | AI / 企业平台 | 官方文档适配器 | [千帆](https://cloud.baidu.com/product/wenxinworkshop) | 模型、Agent、平台和企业应用 |
| P1 | A | 华为新闻 / 华为云 AI | AI / 基础设施 | 官方网页适配器 | [华为新闻](https://www.huawei.com/cn/news) | 盘古、昇腾、AI 基础设施与治理 |
| P0 | A | 上海 AI 实验室 | AI / 研究 | 官方网页适配器 | [官网](https://www.shlab.org.cn/index) | InternLM、OpenCompass、可信安全 AI |
| P0 | A | InternLM GitHub | AI / Security for AI | GitHub API | [InternLM](https://github.com/InternLM) | 模型、评测、部署工具、Release 和 Issue |
| P1 | A | 01.AI / Yi GitHub | AI | GitHub API | [01-ai](https://github.com/01-ai) | Yi 模型、开源工具与模型卡 |
| P1 | A | 商汤科技新闻 | AI | 官方网页适配器 | [SenseTime News](https://www.sensetime.com/cn/news) | 日日新、多模态、行业模型与治理 |
| P1 | A | 科大讯飞开放平台 | AI | 官方文档/网页 | [讯飞开放平台](https://www.xfyun.cn/) | 星火、语音、多模态和行业应用 |
| P1 | A | 美团 LongCat GitHub | AI / Agent | GitHub API | [meituan-longcat](https://github.com/meituan-longcat) | 长程 Agent、模型、评测与开源发布 |

## 5. P0/P1：Security for AI 专业信源

| 优先级 | 可信度 | 信源 | 推荐接入 | 入口 | 重点关注 |
|---|---:|---|---|---|---|
| P0 | A | MITRE ATLAS | 数据仓库、官方网页 | [ATLAS](https://atlas.mitre.org/) | AI 对抗技术、缓解措施、案例；作为攻击技术映射主标准 |
| P0 | A | OWASP GenAI Security Project | RSS/Newsletter/网页 | [OWASP GenAI](https://genai.owasp.org/) | LLM、Agentic、MCP、数据安全、治理、红队和事件综述 |
| P0 | A | NIST AI RMF / AIRC | 官方网页、出版物 | [AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) | 风险治理、GenAI Profile、TEVV、关键基础设施 |
| P0 | A | NIST CAISI Research Blog | 官方网页 | [CAISI](https://www.nist.gov/caisi) | Agent hijacking、模型评测、AI 安全标准和研究 |
| P0 | A | UK AI Security Institute | 官方网页 | [Research](https://www.aisi.gov.uk/research) | 前沿模型、网络能力、红队、安全案例和自治系统 |
| P0 | A | OpenAI Safety / Security | OpenAI RSS 分类 | [OpenAI News](https://openai.com/news/) | 系统卡、部署安全、Prompt Injection、安全事件 |
| P0 | A | Anthropic Safety / Alignment Research | 官方网页适配器 | [Research](https://www.anthropic.com/research) | 模型行为、对齐、可解释性、能力与风险评估 |
| P0 | A | Google DeepMind Responsibility & Safety | 官方网页适配器 | [Responsibility](https://deepmind.google/responsibility/) | Agent 安全、前沿风险、生物安全、评测 |
| P0 | A | Google Security Blog / SAIF | RSS 或网页 | [Google Security Blog](https://security.googleblog.com/) | Prompt Injection、AI 供应链、Secure AI Framework |
| P0 | A | Microsoft Security AI | RSS 或网页 | [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/) | AI Red Team、Copilot 安全、威胁情报和防御 |
| P1 | B | Protect AI | RSS 或网页 | [Blog](https://protectai.com/blog) | 模型供应链、MLSecOps、漏洞披露和工具 |
| P1 | B | huntr | 官方网页/API（如开放） | [huntr](https://huntr.com/) | AI/ML 开源项目漏洞赏金与披露 |
| P1 | B | HiddenLayer Innovation Hub | RSS 或网页 | [Innovation Hub](https://www.hiddenlayer.com/innovation-hub) | 模型攻击、推理安全、AI 威胁研究 |
| P1 | B | Lakera Research / Blog | RSS 或网页 | [Blog](https://www.lakera.ai/blog) | Prompt Injection、Jailbreak、Agent 安全与评测 |
| P1 | B | Trail of Bits Blog | RSS | [Blog](https://blog.trailofbits.com/) | AI 系统、编译器、供应链和安全审计研究 |
| P1 | B | METR | RSS 或网页 | [Updates](https://metr.org/blog/) | 前沿模型自治能力、长任务评测与风险 |
| P1 | B | Apollo Research | 官方网页适配器 | [Science](https://www.apolloresearch.ai/science/) | 欺骗、Scheming、模型行为与安全评测 |
| P1 | B | Cloud Security Alliance AI | RSS/网页 | [AI Research](https://cloudsecurityalliance.org/research/topics/artificial-intelligence) | 云上 AI、Agent、Promptware 和控制框架 |
| P1 | B | MLCommons AI Safety | 官方网页/GitHub | [AI Safety](https://mlcommons.org/ai-safety/) | 安全基准、测评和行业协作 |
| P1 | B | Stanford HAI | RSS 或网页 | [News](https://hai.stanford.edu/news) | AI Index、政策、治理、安全和社会影响 |
| P1 | B | Epoch AI | RSS 或网页 | [Epoch AI](https://epoch.ai/) | 算力、能力趋势、基准与预测 |

## 6. P0/P1：传统安全权威、威胁研究与 AI for Security

| 优先级 | 可信度 | 信源 | 推荐接入 | 入口 | 重点关注 |
|---|---:|---|---|---|---|
| P0 | A | CISA Cybersecurity Advisories | RSS/网页 | [Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories) | 联合公告、已利用漏洞、关键基础设施 |
| P0 | A | Microsoft Security Response Center | RSS/网页 | [MSRC Blog](https://www.microsoft.com/en-us/msrc/blog) | Microsoft/Copilot/Azure 漏洞与安全更新 |
| P0 | A | Google Project Zero | RSS | [Project Zero](https://projectzero.google/) | 高质量漏洞研究、0day 和利用技术 |
| P0 | B | Google Threat Intelligence / Mandiant | RSS/网页 | [Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence) | APT、恶意软件、在野利用、AI 辅助攻击 |
| P0 | B | Cisco Talos | RSS | [Talos Blog](https://blog.talosintelligence.com/) | 威胁研究、漏洞、恶意活动和 AI 安全 |
| P0 | B | Palo Alto Unit 42 | RSS | [Unit 42](https://unit42.paloaltonetworks.com/) | 云、恶意活动、事件响应、AI 威胁 |
| P1 | B | CrowdStrike Blog | RSS/网页 | [Blog](https://www.crowdstrike.com/en-us/blog/) | 威胁情报、攻击者、AI 驱动 SOC |
| P1 | B | SentinelOne Labs | RSS | [Labs](https://www.sentinelone.com/labs/) | 恶意软件、APT、AI 安全和检测 |
| P1 | B | Elastic Security Labs | RSS | [Labs](https://www.elastic.co/security-labs) | 检测工程、恶意软件、规则与 AI SOC |
| P1 | B | Wiz Blog / Research | **RSS（已接入）** | [Blog](https://www.wiz.io/blog) | 云漏洞、AI 云资产、身份与供应链 |
| P1 | B | Check Point Research | RSS | [Research](https://research.checkpoint.com/) | 恶意软件、攻击活动、生成式 AI 滥用 |
| P1 | B | Trend Micro Research | RSS/网页 | [Research](https://www.trendmicro.com/en_us/research.html) | 云、IoT、AI 威胁和犯罪生态 |
| P1 | B | ESET WeLiveSecurity | RSS | [WeLiveSecurity](https://www.welivesecurity.com/) | 恶意软件、APT 和事件分析 |
| P1 | B | Sophos X-Ops | RSS/网页 | [X-Ops](https://news.sophos.com/en-us/category/threat-research/) | 勒索、攻击活动、AI 滥用 |
| P1 | B | Fortinet FortiGuard Labs | RSS/网页 | [Threat Research](https://www.fortinet.com/blog/threat-research) | 攻击趋势、漏洞、恶意软件和 AI 防御 |
| P1 | B | Rapid7 Research | RSS/网页 | [Blog](https://www.rapid7.com/blog/) | 漏洞研究、Metasploit、在野利用 |
| P1 | B | PortSwigger Research | RSS | [Research](https://portswigger.net/research) | Web/Agent 攻击面、Prompt Injection 与浏览器安全 |
| P1 | B | JFrog Security Research | RSS/网页 | [Security](https://jfrog.com/blog/tag/security/) | 开源供应链、包生态和 AI 开发工具漏洞 |
| P1 | B | Snyk Security Blog | RSS/网页 | [Blog](https://snyk.io/blog/) | 开源依赖、AI 生成代码和开发者安全 |
| P1 | B | Semgrep Blog / Research | RSS/网页 | [Blog](https://semgrep.dev/blog/) | 代码安全、AI 生成代码、规则与研究 |

## 7. P0/P1：国内安全、政策与标准

| 优先级 | 可信度 | 信源 | 推荐接入 | 入口 | 重点关注 |
|---|---:|---|---|---|---|
| P0 | A | 全国网安标委 TC260 | 官方网页适配器 | [TC260](https://www.tc260.org.cn/) | AI 安全、数据安全、生成内容标识、标准征求意见 |
| P0 | A | 国家网信办 CAC | 官方网页适配器 | [CAC](https://www.cac.gov.cn/) | AI 治理、备案、算法、数据和内容安全政策 |
| P1 | A | 工业和信息化部 MIIT | 官方网页适配器 | [MIIT](https://www.miit.gov.cn/) | AI 产业、数据、网络安全和行业政策 |
| P1 | B | 奇安信攻防社区 | RSS/网页 | [攻防社区](https://forum.butian.net/) | 技术研究、漏洞与 AI 安全实践；社区内容需复核 |
| P1 | B | 360 Netlab | RSS | [Netlab Blog](https://blog.netlab.360.com/) | 僵尸网络、恶意活动、网络测量 |
| P1 | B | 腾讯玄武实验室 | 官方网页 | [Xuanwu Lab](https://xlab.tencent.com/cn/) | 漏洞、移动/系统安全和前沿研究 |
| P1 | B | 腾讯科恩实验室 | 官方网页 | [Keen Security Lab](https://keenlab.tencent.com/zh/) | 汽车、系统、浏览器和 AI 相关安全 |
| P1 | B | 长亭科技 Blog | RSS/网页 | [长亭 Blog](https://blog.chaitin.cn/) | 漏洞分析、攻防研究、AI 安全 |
| P1 | B | 绿盟科技博客 | RSS/网页 | [NSFOCUS Blog](https://blog.nsfocus.net/) | 漏洞、威胁情报、行业风险 |
| P1 | C | 先知社区 | 网页 | [先知社区](https://xz.aliyun.com/news) | 漏洞、攻防、CTF 与研究线索 |
| P1 | C | FreeBuf | RSS/网页 | [FreeBuf](https://www.freebuf.com/) | 国内安全资讯与研究发现 |
| P1 | C | 安全内参 | RSS/网页 | [安全内参](https://www.secrss.com/) | 政策、产业和安全事件摘要 |
| P2 | C | 安全客 | 网页 | [安全客](https://www.anquanke.com/) | 技术文章与安全新闻发现 |
| P2 | C | 嘶吼 RoarTalk | 网页 | [嘶吼](https://www.4hou.com/) | 安全新闻、访谈和产业动态 |

## 8. P0：AI/Agent 供应链重点仓库

这些不是普通“新闻源”，而是需要通过 GitHub API 监控 `Release`、`Security Advisory`、默认分支重大提交和高影响 Issue 的资产清单。

| 优先级 | 仓库/组织 | 关注原因 | 入口 |
|---|---|---|---|
| P0 | Model Context Protocol Specification | MCP 规范与协议安全边界 | [modelcontextprotocol/specification](https://github.com/modelcontextprotocol/specification) |
| P0 | MCP Servers | 工具供应链、权限、命令执行与第三方连接器 | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) |
| P0 | OpenAI Agents SDK | Agent 工具调用、Tracing、Guardrails | [openai/openai-agents-python](https://github.com/openai/openai-agents-python) |
| P0 | LangChain | Agent/RAG 生态大、历史攻击面广 | [langchain-ai/langchain](https://github.com/langchain-ai/langchain) |
| P0 | LlamaIndex | RAG、数据连接器与 Agent | [run-llama/llama_index](https://github.com/run-llama/llama_index) |
| P0 | AutoGen | 多 Agent 与代码执行 | [microsoft/autogen](https://github.com/microsoft/autogen) |
| P0 | CrewAI | 多 Agent 编排与工具调用 | [crewAIInc/crewAI](https://github.com/crewAIInc/crewAI) |
| P0 | Dify | 企业 LLM 应用、工作流、插件与凭证 | [langgenius/dify](https://github.com/langgenius/dify) |
| P0 | Flowise | 低代码 Agent/RAG、连接器与凭证 | [FlowiseAI/Flowise](https://github.com/FlowiseAI/Flowise) |
| P0 | Langflow | 可视化 Agent 工作流与代码执行 | [langflow-ai/langflow](https://github.com/langflow-ai/langflow) |
| P0 | Open WebUI | 本地模型前端、插件、工具与鉴权 | [open-webui/open-webui](https://github.com/open-webui/open-webui) |
| P0 | Ollama | 本地模型运行时与网络暴露面 | [ollama/ollama](https://github.com/ollama/ollama) |
| P0 | llama.cpp | 本地推理、模型格式与解析器攻击面 | [ggml-org/llama.cpp](https://github.com/ggml-org/llama.cpp) |
| P0 | vLLM | 生产推理服务、API 和模型加载 | [vllm-project/vllm](https://github.com/vllm-project/vllm) |
| P0 | Transformers | 模型加载、远程代码、供应链与核心生态 | [huggingface/transformers](https://github.com/huggingface/transformers) |
| P0 | safetensors | 模型文件解析与供应链安全 | [huggingface/safetensors](https://github.com/huggingface/safetensors) |
| P1 | ComfyUI | 节点生态、模型文件和第三方扩展 | [Comfy-Org/ComfyUI](https://github.com/Comfy-Org/ComfyUI) |
| P1 | n8n | Agent 工作流、凭证与第三方连接器 | [n8n-io/n8n](https://github.com/n8n-io/n8n) |
| P1 | PyTorch | 训练/推理框架与模型反序列化风险 | [pytorch/pytorch](https://github.com/pytorch/pytorch) |
| P1 | TensorFlow | 模型处理、Serving 和依赖漏洞 | [tensorflow/tensorflow](https://github.com/tensorflow/tensorflow) |

## 9. P2：媒体、社区和热度发现

这些来源不应单独触发“确认事件”或紧急告警。用途是发现线索、补充背景和计算讨论热度。

| 可信度 | 信源 | 入口 | 适合用途 |
|---:|---|---|---|
| C | AI今日热榜 | [aihot.today](https://aihot.today/) | 发现全球 AI 媒体、GitHub、Product Hunt 等来源 |
| C | TechCrunch AI | [AI](https://techcrunch.com/category/artificial-intelligence/) | 创业、融资、产品和行业事件 |
| C | The Verge AI | [AI](https://www.theverge.com/ai-artificial-intelligence) | 消费产品、政策和平台变化 |
| C | Ars Technica AI/Security | [AI](https://arstechnica.com/ai/) | 技术背景与安全事件 |
| C | WIRED AI / Security | [AI](https://www.wired.com/tag/artificial-intelligence/) | 社会影响、政策、调查报道 |
| C | Reuters Technology / AI | [Technology](https://www.reuters.com/technology/) | 公司、政策和重大事件交叉验证 |
| C | AP Technology / AI | [Technology](https://apnews.com/technology) | 国际公司、政策和社会影响 |
| C | BleepingComputer | [News](https://www.bleepingcomputer.com/) | 漏洞、勒索、在野利用线索 |
| C | SecurityWeek | [SecurityWeek](https://www.securityweek.com/) | 企业安全、漏洞和产业 |
| C | The Record | [The Record](https://therecord.media/) | 网络攻击、政策和执法 |
| C | Dark Reading | [Dark Reading](https://www.darkreading.com/) | 企业安全和技术分析 |
| C | Risky Business | [Risky Business](https://risky.biz/) | 安全新闻摘要与专业评论 |
| C | TLDRSec | [tl;dr sec](https://tldrsec.com/) | AppSec、云安全和研究线索 |
| C | Hacker News | [Hacker News](https://news.ycombinator.com/) | 开发者热度、原始项目和讨论 |
| C | GitHub Trending | [Trending](https://github.com/trending) | 新工具、仓库异常增长与供应链发现 |
| C | Product Hunt AI | [AI](https://www.producthunt.com/topics/artificial-intelligence) | 新 AI 产品和安全产品发现 |
| C | Reddit r/LocalLLaMA | [LocalLLaMA](https://www.reddit.com/r/LocalLLaMA/) | 开源模型、部署问题与社区反馈 |
| C | Reddit r/netsec | [netsec](https://www.reddit.com/r/netsec/) | 安全研究与漏洞讨论 |

## 10. 首批候选池与实际 MVP

下面约 35 个逻辑信源是形成较完整主题覆盖的首批候选池，不要求在工程 MVP 中一次接入。**当前已接入 18 个 endpoint（见 §1.1）**，详见[后端 MVP 设计方案](./mvp-design.md#54-当前已接入-18-个-endpoint17-个-source)。在首发稳定并完成 7 天验收后，再从下面的候选池逐步扩展。

### 通用 AI

- AI HOT RSS（已接入）；REST snapshot/changes 完整镜像模式待实现
- OpenAI RSS
- Anthropic News + Research
- Google DeepMind
- Meta AI
- Hugging Face Blog + Daily Papers
- Qwen、DeepSeek、MiniMax、智谱
- arXiv API

### Security for AI

- AIVD、CNVD AI
- GitHub Advisory API、OSV、NVD
- MITRE ATLAS、OWASP GenAI、NIST CAISI、UK AISI
- OpenAI/Anthropic/Google/Microsoft 的 Safety/Security 分类
- Protect AI、HiddenLayer、Lakera、Trail of Bits
- 本文列出的 P0 AI/Agent 供应链仓库

### AI for Security / AI-enabled Threats

- CISA KEV、FIRST EPSS、CERT/CC
- CNCERT
- MSRC、Google Project Zero、Mandiant、Unit 42、Talos
- 360 Netlab、腾讯玄武、长亭

这组约 35 个逻辑信源、约 45 个 endpoint 是 MVP 后的第一阶段扩展目标。具体加入顺序由重复率、漏报率、解析稳定性和维护成本决定。

## 11. 用户补充模板

请按下面格式补充。暂时不知道接入方式也没关系，先写名称、入口和为什么重要：

| 信源名称 | URL/公众号/账号 | 语言 | 归属主线 | 你关注的原因 | 希望优先级 | 备注 |
|---|---|---|---|---|---|---|
| 示例：某安全团队公众号 | 微信公众号：xxx | 中文 | Security for AI | 经常首发 Agent 漏洞复现 | P0 | 目前无 RSS |

补充后需要进行三项审核：

1. 是否有稳定的一手出处或历史准确性。
2. 是否与现有信源高度重复。
3. 是否可合法、稳定、低成本地自动化接入。
