# Agent Working Guide

本文件是自动化 Agent 操作本仓库时的长期记忆和行为约束。README 面向使用者；这里记录
实现与运维中不能被破坏的约定。除非用户明确要求，本仓库不要新增其他 Markdown 文档。

## 项目事实

- 工作目录：`/home/ubuntu/workspace/project-03-AI_security_hot`。
- Python 版本：3.13；依赖与命令统一通过 `uv`。
- 数据库：PostgreSQL 18；Schema 只通过 Alembic 演进。
- 运行单元：`postgres`、一次性 `migrate`、`api`、`worker`。
- 信源真相：`sources/sources.yaml`；分类真相：`sources/taxonomy.yaml`。
- 非敏感模型 profile：`config/models.yaml` 和 `config/embeddings.yaml`。
- 密钥只允许来自环境变量或本地 `.env`，不得出现在代码、YAML、日志、提交或回复中。
- 当前 Alembic head 为 `7a91d2e4f6b8`；新增迁移后同步更新本节。
- 当前注册表包含 18 个 source、20 个 endpoint（含 Black Hat Briefings，使用
  playwright connector 通过独立容器抓取）。

## 开始任何任务前

1. 先运行 `git status --short --branch`，识别用户已有的未提交修改。
2. 使用 `rg`、`rg --files` 定位代码；不要根据旧对话猜测当前实现。
3. 阅读将要修改模块、相关模型、迁移和测试，再决定改动范围。
4. 检查当前运行容器的镜像 SHA 与 Alembic head；工作区变化不会自动进入容器。
5. 若任务只是审查或诊断，保持只读，不顺手修改代码或部署。

保护用户已有修改。不要执行 `git reset --hard`、`git checkout --`、宽泛递归删除或
其他难以恢复的操作。发生重叠修改时先理解差异，不得覆盖。

## 架构不变量

- RawItem 和历史 Document 是审计证据，不因去重、撤回或来源退役而物理删除。
- “当前文档”必须统一使用 storage 层的 current-document 条件，同时考虑本地来源状态和
  上游记录状态；不要在 API、报告或事件代码中另造不同口径。
- `sources/sources.yaml` 是 endpoint 启停的唯一真相。正式替代使用
  `enabled: false` 与 `replaced_by`，保留历史关系。
- 增量水位只有在完整成功后推进。分页不完整、租约丢失、fencing token 失效时必须失败，
  不能把部分结果标记为完成。
- 去重是非破坏式关系。不同 CVE/GHSA/CNVD、模型版本、发布版本或事故强身份冲突必须
  硬阻断，不能被标题、向量或人工批准越过。
- 普通更新走有界局部队列；全库重算只允许显式 replay，不能回退到每次全局扫描。
- CVE/漏洞库与普通新闻事件保持隔离。CVE 不调用通用新闻分类模型。
- LLM 输出必须经过严格 Schema/Pydantic 校验，并保留响应、usage、finish reason、错误和
  repair 尝试审计。`ontology_version` 必须与代码常量一致。
- 语义富化默认是 shadow，不自动修改正式 Event。
- Embedding 使用独立 provider/config。向量只生成候选；vector-only 结果不得自动成为
  `same_event`，强身份冲突仍优先。
- 正式提升默认 preview，只有显式 `--apply` 才可写 Event；重复执行必须幂等，回滚必须受
  事件版本保护。
- 每日热点读取冻结 revision；`as_of` 不得从当前 Event 临时伪造历史状态。
- API 读取 Token 与 `/ops/*` 管理 Token 分离并 fail-closed；健康探针保持无认证。
- 只读路由接受 read token 或 admin token（后台用一个凭证读取）；`/ops/*` 写操作只认
  admin token。
- 公开前端页面（`/`、`/admin.html`、`/login.html`、`/assets/`）与 `/api/*` 聚合接口
  无需 token；后台页面在登录后把 admin token 存 localStorage，前端 JS 调 `/ops/*`
  时带上 Bearer。不能把密钥写进前端代码。
- 公开前端源码在 `web-src/`（Vite + TypeScript，MPA），`npm run build` 产出
  `web/dist`（Dockerfile 多阶段构建自动执行）；admin/login 等遗留页面逐字拷贝在
  `web-src/public/`，不要直接改 `web/dist`（生成物）。
- 前端聚合服务在 `services/overview.py`（`build_overview`）与 `services/feed.py`
  （`build_feed` / `search_documents`），取代旧 gen_daily 脚本；页面数据来自
  `GET /api/overview`、`GET /api/feed`、`GET /api/search`，不要为前端新增旁路 SQL。

## 修改代码的习惯

- 使用补丁工具做人工文件修改；机械格式化可使用对应格式化工具。
- 优先扩展已有 provider、connector、parser、repository 和 stage 接口，不复制平行流程。
- Connector 负责请求和增量协议，Parser 负责内容结构，Pipeline 负责编排，Repository 负责
  持久化与锁；不要跨层混放职责。
- 网络请求必须复用统一 fetch/provider 层，保留超时、响应大小、重试、限速、SSRF 和重定向
  检查，不能在 parser 或 job 中直接临时请求。
- 新配置同时更新 Settings、`.env.example`、必要的非敏感 YAML 和自检；默认值应安全且
  不产生付费调用。
- ORM 变化必须附带 Alembic 迁移和 PostgreSQL 集成测试。不要修改已经发布的迁移；新增
  后继 revision。
- 数据量相关查询必须有批次、时间窗、候选池或分页上限，并考虑可恢复租约和幂等重试。
- README 只描述当前产品、真实使用方式和当前边界，不记录里程碑流水账或已完成待办。
- 评测说明优先使用 JSON schema、CLI help 或代码注释；除非用户明确要求，不新增 `.md`。

## 验证门禁

普通代码修改至少执行：

```bash
uv run ruff check .
uv run pyright
docker compose config --quiet
uv run pytest -m "not live" -q
```

涉及 ORM、Repository、迁移或 PostgreSQL 行为时，必须使用隔离 PostgreSQL 18：

```bash
uv run alembic upgrade head
uv run alembic check
uv run pytest -m "not live" -q
```

测试必须实际设置 `INTEL_DATABASE_URL`，不能把数据库测试的 skip 当作通过。迁移应至少
验证空库到 head；高风险迁移还要验证 downgrade/upgrade 或真实数据副本。

真实网站测试仅在用户要求、信源修改或发布验收时运行：

```bash
INTEL_RUN_LIVE=1 uv run pytest -m live -v
```

外部网站失败需要区分代码回归、上游限流、地区网络和代理问题，不能为了让测试变绿而削弱
正确性检查。

## Git 与 CI

- 除非用户明确要求，不自动 commit、push、创建分支或改写历史。
- 用户已指定使用 Git，不使用 `gh`。提交到现有 `main`，推送命令为
  `git push origin main`。
- 提交前检查 staged diff、`git diff --check`、密钥和生成文件；`.env`、`data/`、
  `report*.html` 不得进入提交。
- 推送后通过 GitHub Actions 页面或公共 REST API 跟踪对应 head SHA，直到 Linux 和 macOS
  job 都完成。CI 失败时读取具体 step 日志，修复、复测、重新提交并继续跟踪。
- 不使用 force push，除非用户明确授权且风险已经说明。

## 部署习惯

- API、worker、migrate 必须来自同一 Git SHA 和同一镜像，构建时设置
  `INTEL_BUILD_SHA=$(git rev-parse --short HEAD)`。
- `migrate` 必须先执行 `alembic upgrade head` 和 `intel sync`；迁移失败时不得启动
  新 API/worker。
- 仅重启容器不会加载新的工作区代码；代码升级必须重新构建镜像并重新创建服务。
- 保留旧数据的升级应先做可恢复备份；明确采用空库冷启动时不要求复制旧数据库。
- PostgreSQL 和 API 默认只绑定 `127.0.0.1`。对外 API 使用 TLS 反向代理，数据库不暴露
  公网。
- macOS 容器访问宿主代理使用 `host.docker.internal`；Linux 使用受限 Docker gateway，
  不允许宿主代理监听 `0.0.0.0`。
- 部署后检查 `docker compose ps -a`、migrate/api/worker 日志、`/health/ready`、
  `intel self-check`、首次抓取和每日快照。

## 当前已知边界

- Black Hat Briefings 通过独立 playwright 容器抓取（compose `--profile playwright`
  门控）；主 worker 镜像不含浏览器，普通信源不受影响。
- worker heartbeat 只证明调度器在运行，主动告警和跨实例任务健康仍需增强。
- 后台管理提供文档/事件增删改查、打标签、一键分类/聚类；完整用户体系、多管理员
  和操作审计尚未实现（单一 admin token）。
- LLM 关系三分类、重要性/新颖性/紧急性判断和自动正式提升尚未开放。
- 邮件、飞书投递和自动日报文案尚未实现；前端网站 + 后台管理已取代旧的
  `gen_report.py` / `gen_daily.py` 静态报告脚本。
- RSS 等窗口型信源无法从空库恢复上游窗口外的历史。
- Embedding 默认关闭；在未完成真实模型校准前保持关闭。
