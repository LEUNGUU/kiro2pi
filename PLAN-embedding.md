# PLAN: Bedrock Embedding Endpoint

## 目标

在 kiro2pi 中新增 `/v1/embeddings` 端点（OpenAI 兼容格式），直接调用 AWS Bedrock 的 embedding 模型，去掉对 litellm proxy 的依赖。

## 背景

当前 vault 语义搜索（vsearch）通过 litellm proxy（localhost:18780）转发到 Bedrock Cohere embed-multilingual-v3。kiro2pi 已经有 AWS credentials 管理（SSO token），可以直接复用，不需要额外的中间层。

## 需求

### 端点规格

```
POST /v1/embeddings
Content-Type: application/json

{
  "model": "cohere.embed-multilingual-v3",   // 或其他 Bedrock embedding model ID
  "input": "单条文本" | ["文本1", "文本2"],   // 字符串或字符串数组
  "encoding_format": "float",                 // 可选，默认 float
  "input_type": "search_query"                // 可选，Cohere 特有参数
}
```

### 响应格式（OpenAI 兼容）

```json
{
  "object": "list",
  "model": "cohere.embed-multilingual-v3",
  "data": [
    {
      "object": "embedding",
      "index": 0,
      "embedding": [0.123, -0.456, ...]
    }
  ],
  "usage": {
    "prompt_tokens": 5,
    "total_tokens": 5
  }
}
```

### 支持的模型

| Model ID | 维度 | 说明 |
|----------|------|------|
| `cohere.embed-multilingual-v3` | 1024 | 主力，中英文都好 |
| `cohere.embed-english-v3` | 1024 | 纯英文场景 |
| `amazon.titan-embed-text-v2:0` | 1024 | AWS 原生，备选 |

### Bedrock 调用方式

```go
// Bedrock InvokeModel for Cohere
payload := map[string]interface{}{
    "texts":      texts,        // []string
    "input_type": inputType,    // "search_query" | "search_document"
    "truncate":   "END",
}

resp, err := bedrockClient.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
    ModelId:     aws.String(modelId),
    ContentType: aws.String("application/json"),
    Body:        payloadBytes,
})
```

Cohere 响应格式：
```json
{
  "embeddings": [[0.123, -0.456, ...], ...],
  "id": "...",
  "texts": ["..."]
}
```

Titan 响应格式：
```json
{
  "embedding": [0.123, -0.456, ...],
  "inputTextTokenCount": 5
}
```
注意：Titan 单次只接受一条文本，批量需要循环调用。

### 实现要点

1. **条件启用（Opt-in）** — 整个 embedding 功能通过环境变量控制：
   - 设置 `BEDROCK_AWS_PROFILE=liangy` → 使用指定 SSO profile 的凭证，启用端点
   - 设置 `BEDROCK_ENABLED=1` → 使用默认凭证链（~/.aws/credentials 或环境变量），启用端点
   - 两者都不设置 → 不初始化 Bedrock client，不注册 `/v1/embeddings` 端点，零开销

2. **AWS 凭证（与现有 Q API token 完全独立）** — Bedrock 需要 SigV4 签名，使用 `aws-sdk-go-v2/config.LoadDefaultConfig()`：
   - 如果设置了 `BEDROCK_AWS_PROFILE`，传入 `config.WithSharedConfigProfile(profile)`
   - 否则走默认链（env vars → ~/.aws/credentials → instance role）
   - Region 通过 `BEDROCK_REGION` 环境变量指定，默认 `us-west-2`

3. **Bedrock SDK 依赖** — 需要新增：
   ```
   github.com/aws/aws-sdk-go-v2/config
   github.com/aws/aws-sdk-go-v2/service/bedrockruntime
   github.com/aws/aws-sdk-go-v2 (core, for aws.String etc.)
   ```

4. **input_type 映射** — 通过请求体额外字段 `input_type` 传入（非标准但实用），默认 `search_query`。

5. **批量处理** — Cohere 单次最多 96 条文本。超过时自动分批，合并结果。Titan 单次一条，循环调用。

6. **可观测性** — 复用现有 `call_log` 表，endpoint 记为 `/v1/embeddings`，记录 model、input token 数、延迟。

7. **错误处理** — Bedrock throttling（429）时返回 OpenAI 格式的 error response。

### 实现步骤

1. `go get` 添加 aws-sdk-go-v2 依赖
2. 在 `main.go` 顶部添加全局 `bedrockClient *bedrockruntime.Client` 变量
3. 在 `startServer()` 中，检查环境变量，条件初始化 Bedrock client 并注册 `/v1/embeddings` handler
4. 实现 handler：解析请求 → 按模型分发（Cohere/Titan）→ 调用 Bedrock → 组装 OpenAI 响应
5. 记录 observability log
6. 更新 `/v1/models` 端点，条件性地包含 embedding 模型
7. 更新启动日志，显示 embedding 端点状态

### 不做的事

- 不做 embedding 缓存（vsearch 自己有缓存层）
- 不做向量存储
- 不支持 `dimensions` 参数裁剪（Cohere v3 不支持）

## vsearch 迁移

完成后修改 vsearch 配置，将 litellm proxy 替换为 kiro2pi：

```python
# 之前
# base_url = "http://localhost:18780"
# model = "cohere/embed-multilingual-v3"

# 之后
base_url = "http://localhost:9090/v1"
model = "cohere.embed-multilingual-v3"
```

验证通过后可以停掉 litellm proxy 进程。

## References

- [Bedrock Cohere Embed API](https://docs.aws.amazon.com/bedrock/latest/userguide/model-parameters-embed.html)
- [Cohere Embed v3 文档](https://docs.cohere.com/reference/embed)
- [OpenAI Embeddings API 规格](https://platform.openai.com/docs/api-reference/embeddings/create)
- [AWS SDK Go v2 - BedrockRuntime](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/bedrockruntime)
- [Bedrock Titan Embeddings](https://docs.aws.amazon.com/bedrock/latest/userguide/titan-embedding-models.html)
- [TensorZero Embeddings 实现参考](https://www.tensorzero.com/docs/gateway/generate-embeddings)
