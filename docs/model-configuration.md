# 模型配置与 DeepSeek 接入

> 项目进度与下一步：[当前状态与路线](./current-status.md)

M1.3 HybridClassifier 与 M2.2 影子语义富化共用同一个模型 Provider。当前内置
`openai-compatible` 适配器，可连接 DeepSeek、OpenAI 或私有兼容网关；采集、
去重和确定性事件流程不依赖模型，也不会因为模型不可用而停止。

## 1. 配置优先级

最终配置按以下顺序合并，靠前者优先：

1. `INTEL_LLM_*` 环境变量或 `.env`；
2. `INTEL_LLM_PROFILE` 指定的 `config/models.yaml` Profile；
3. YAML 的 `active_profile`；
4. 代码中的离线安全默认值。

仓库已提供 `deepseek-v4` Profile：

```yaml
version: 1
active_profile: deepseek-v4

profiles:
  deepseek-v4:
    provider: openai-compatible
    base_url: https://api.deepseek.com
    model: deepseek-v4-flash
    response_format: json_object
    thinking_mode: disabled
    timeout_seconds: 60
    max_input_chars: 12000
    classification_max_output_tokens: 500
    semantic_max_output_tokens: 4000
```

如果 `deepseek-v4` 位于私有网关，可直接修改 `base_url`，也可以在 `.env` 覆盖：

```dotenv
INTEL_LLM_CONFIG_FILE=config/models.yaml
INTEL_LLM_PROFILE=deepseek-v4
INTEL_LLM_BASE_URL=https://your-gateway.example/v1
INTEL_LLM_MODEL=deepseek-v4-flash
INTEL_LLM_API_KEY=replace-with-real-key
```

`base_url` 可以是 API 根地址（例如以 `/v1` 结尾），也可以是完整的
`/chat/completions` 地址，适配器不会重复拼接路径。

## 2. 密钥边界

YAML Schema 不存在 `api_key` 字段，额外字段会被拒绝。密钥只能通过
`INTEL_LLM_API_KEY` 注入，不能写入 `config/models.yaml`、日志、模型缓存或
自检结果。`intel llm-config` 只显示 `api_key_configured: true/false`。

## 3. 输出兼容模式

不同 OpenAI-compatible 端点对结构化输出的实现不同，可配置：

| 值 | 请求行为 | 适用场景 |
|---|---|---|
| `json_schema` | 发送严格 JSON Schema | 完整支持 Structured Outputs 的端点 |
| `json_object` | 只要求 JSON Object | DeepSeek 或多数兼容网关的推荐起点 |
| `prompt_only` | 不发送 `response_format` | 不识别该参数的旧网关 |

DeepSeek V4 默认开启思考。结构化分类和抽取建议设置 `thinking_mode: disabled`，也可用 `INTEL_LLM_THINKING_MODE=disabled` 覆盖，以避免 reasoning token 挤占 JSON 输出预算；需要复杂关系裁决时可单独启用。参数含义见 [DeepSeek 官方 Thinking Mode](https://api-docs.deepseek.com/guides/thinking_mode)。

无论使用哪种模式，返回内容都必须再次通过 Pydantic 严格 Schema、枚举和业务
规则校验；`prompt_only` 不会降低落库门槛。适配器只额外容忍一层 Markdown JSON 代码围栏。

## 4. 无付费调用检查

先检查最终生效值：

```bash
uv run intel llm-config
```

这个命令不访问模型端点。输出中的 `field_sources` 会说明每个字段来自 YAML
Profile 还是某个环境变量；只有 `ready`、`provider_registered` 都为 `true`
时，模型阶段才具备调用条件。

模型调用还有独立功能门：

```dotenv
# M1.3 新闻/论文混合分类；结构化 CVE 始终跳过模型
INTEL_CLASSIFICATION_MODE=hybrid

# M2.2 影子语义抽取；默认 false，开启后仍不影响正式 Event
INTEL_SEMANTIC_ENRICHMENT_ENABLED=true
INTEL_SEMANTIC_ENRICHMENT_MODE=shadow
```

仅想做一轮小规模影子验证时，不要打开常驻调度，可执行：

```bash
uv run intel semantic-enrich --limit 5 --force

# 只领取已到期 retry，不新增目标文档
uv run intel semantic-enrich --limit 5 --force --retry-only
```

这条命令会产生真实 API 调用和费用；应在配置检查通过并确认预算后执行。

## 5. Docker Compose

镜像内包含默认配置，同时 Compose 把宿主机 `./config` 只读挂载到
`/app/config`。修改 `config/models.yaml` 后重启进程即可重新加载：

```bash
docker compose restart api worker
```

修改 `.env` 后需要重建容器环境，而不是只 restart：

```bash
docker compose up -d --force-recreate api worker
```

模型 Profile、URL 或输出模式变化会产生新的端点感知缓存命名空间和语义
`execution_version`，不会错误复用旧网关的模型结果；历史审计和旧缓存仍保留。
