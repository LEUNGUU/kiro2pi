# kiro2pi

A proxy server that enables [pi-coding-agent](https://github.com/badlogic/pi-mono) to use AWS CodeWhisperer/Kiro as a backend.

## Overview

```
┌─────────────────┐     ┌─────────────┐     ┌──────────────────┐
│ pi-coding-agent │────▶│   kiro2pi   │────▶│  CodeWhisperer   │
│  (Anthropic API)│     │   (proxy)   │     │    (Q API)       │
└─────────────────┘     └─────────────┘     └──────────────────┘

┌─────────────────┐     ┌─────────────┐     ┌──────────────────┐
│  OpenAI client  │────▶│   kiro2pi   │────▶│  CodeWhisperer   │
│ (OpenAI API)    │     │   (proxy)   │     │    (Q API)       │
└─────────────────┘     └─────────────┘     └──────────────────┘
```

kiro2pi translates Anthropic and OpenAI API requests to CodeWhisperer Q API format, allowing you to use pi-coding-agent or any OpenAI-compatible client with your Kiro/CodeWhisperer subscription.

## Features

- Anthropic Messages API compatible proxy
- OpenAI-compatible endpoints (`/v1/chat/completions`, `/v1/completions`)
- Automatic token management (reads from kiro-cli)
- Streaming support (both Anthropic SSE and OpenAI SSE formats)
- Tool use / function calling support
- Extended thinking support (thinking tool and native adaptive reasoning)
- Automatic token refresh on 403 errors
- Retry with exponential backoff for rate limits
- Image/multimodal support (base64 PNG, JPEG, WebP, GIF)
- Hyphenated model name aliases (e.g. `claude-opus-4-8` → `claude-opus-4.8`)

## Prerequisites

1. **kiro-cli** must be installed and authenticated
   - The proxy reads tokens from kiro-cli's SQLite database
   - Run `kiro-cli auth login` to authenticate

2. **Profile ARN** - Set via environment variable or kiro-cli config:
   ```bash
   export CODEWHISPERER_PROFILE_ARN="arn:aws:codewhisperer:us-east-1:ACCOUNT_ID:profile/PROFILE_ID"
   ```

## Installation

### From source

```bash
go build -o kiro2pi .
```

### From releases

Download the latest release for your platform from the [Releases](https://github.com/LEUNGUU/kiro2pi/releases) page.

## Project Layout

Single `main` package split by concern:

| File | Responsibility |
|------|----------------|
| `main.go` | Entry point, CLI dispatch |
| `server.go` | HTTP server, routing, middleware, retry policy |
| `handlers.go` | `/v1/messages` stream/non-stream handlers, OpenAI-compat handlers, SSE, content-filter fallback |
| `request.go` | Anthropic → CodeWhisperer request building and history validation |
| `models.go` | Model mapping, thinking/effort/max_tokens forwarding, context windows, payload limits |
| `types.go` | Request/response structs |
| `token.go` | kiro-cli token retrieval and refresh |
| `bedrock.go` | Bedrock embeddings/rerank endpoints |
| `observability.go` | Call logging to SQLite (`/stats`, `/logs`) |
| `parser/` | Upstream event-stream (SSE) response parsing |

## Usage

### Start the proxy server

```bash
# Default port 9090
./kiro2pi server

# Custom port
./kiro2pi server 8080
```

### Configure pi-coding-agent

Add to `~/.pi/agent/models.json`:

```json
{
  "providers": {
    "kiro": {
      "baseUrl": "http://localhost:9090",
      "apiKey": "dummy",
      "api": "anthropic-messages",
      "models": [
        {
          "id": "claude-opus-5",
          "name": "Claude Opus 5 (Kiro)",
          "reasoning": true,
          "input": ["text", "image"],
          "cost": { "input": 5, "output": 25, "cacheRead": 0, "cacheWrite": 0 },
          "contextWindow": 400000,
          "maxTokens": 128000
        },
        {
          "id": "claude-sonnet-5",
          "name": "Claude Sonnet 5 (Kiro)",
          "reasoning": true,
          "input": ["text", "image"],
          "cost": { "input": 3, "output": 15, "cacheRead": 0, "cacheWrite": 0 },
          "contextWindow": 400000,
          "maxTokens": 64000
        }
      ]
    }
  }
}
```

Set as default in `~/.pi/agent/settings.json`:

```json
{
  "defaultProvider": "kiro",
  "defaultModel": "claude-opus-5"
}
```

### Other commands

```bash
# Read token info
./kiro2pi read

# Refresh token
./kiro2pi refresh

# Export environment variables
eval $(./kiro2pi export)
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CODEWHISPERER_PROFILE_ARN` | Required if not using kiro-cli. Your CodeWhisperer profile ARN |
| `DEBUG_SAVE_RAW` | Set to `1` or `true` to save raw API responses for debugging |
| `DEBUG_ACCESS_LOG` | Set to `1` or `true` to enable detailed HTTP access logging |
| `BEDROCK_ENABLED` | Set to `1` to enable the Bedrock-backed `/v1/embeddings` and `/v1/rerank` endpoints |
| `BEDROCK_AWS_PROFILE` | AWS shared-config profile to use for Bedrock (also enables the Bedrock endpoints) |
| `BEDROCK_REGION` | AWS region for Bedrock (default `us-west-2`) |

## Platform Support

- **Linux** — Can run as a systemd service
- **macOS** — Can run as a launchd service (see below)

The kiro-cli database path is detected automatically based on the platform.

### macOS launchd Setup

Create `~/Library/LaunchAgents/com.leunguu.kiro2pi.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.leunguu.kiro2pi</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/kiro2pi</string>
        <string>server</string>
        <string>9090</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/Users/<username>/Library/Logs/kiro2pi.log</string>
    <key>StandardErrorPath</key>
    <string>/Users/<username>/Library/Logs/kiro2pi.error.log</string>
</dict>
</plist>
```

Then load it:

```bash
launchctl load ~/Library/LaunchAgents/com.leunguu.kiro2pi.plist
```

### Linux systemd Setup

See [AGENTS.md](AGENTS.md) for systemd service configuration.

## Supported Models

The proxy maps model names to CodeWhisperer models:

| Request Model | CodeWhisperer Model |
|---------------|---------------------|
| `claude-opus-5` | `claude-opus-5` |
| `claude-sonnet-5` | `claude-sonnet-5` |
| `claude-fable-5` | `claude-fable-5` (experimental preview) |
| `claude-opus-4.8` | `claude-opus-4.8` |
| `claude-opus-4.7` | `claude-opus-4.7` |
| `claude-opus-4.6` | `claude-opus-4.6` |
| `claude-sonnet-4.6` | `claude-sonnet-4.6` |
| `gpt-5.6-sol` | `gpt-5.6-sol` |
| `gpt-5.6-terra` | `gpt-5.6-terra` |
| `gpt-5.6-luna` | `gpt-5.6-luna` |
| `minimax-m2.5` | `minimax-m2.5` |
| `glm-5` | `glm-5` |

Hyphenated aliases are also supported (e.g. `claude-opus-4-8` → `claude-opus-4.8`), since the Anthropic SDK normalizes dots to hyphens.

## Bedrock Endpoints (optional)

When Bedrock is enabled (`BEDROCK_ENABLED=1` or `BEDROCK_AWS_PROFILE=...`), two extra endpoints are served using AWS credentials from the configured profile/region.

### `POST /v1/rerank` (Cohere-compatible)

Proxies to AWS Bedrock **Cohere Rerank 3.5** (`cohere.rerank-v3-5:0`). The `model` field is optional; if provided it must equal `cohere.rerank-v3-5:0` or the request is rejected with `400`. Documents may be strings or `{"text": "..."}` objects (max 1000).

```bash
curl http://localhost:9090/v1/rerank \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "What is the capital of France?",
    "documents": ["Paris is the capital of France.", "Berlin is in Germany."],
    "top_n": 1,
    "return_documents": true
  }'
```

Response: `{ "id", "model", "results": [{ "index", "relevance_score", "document"? }], "meta" }`.

Region note: Cohere Rerank 3.5 is available in `us-east-1`, `us-west-2`, `ap-northeast-1`, `ca-central-1`, and `eu-central-1`.

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /v1/messages` | Anthropic Messages API (main endpoint) |
| `POST /v1/chat/completions` | OpenAI Chat Completions API (streaming & non-streaming) |
| `POST /v1/completions` | OpenAI legacy Completions API |
| `GET /v1/models` | List available models |
| `POST /v1/embeddings` | Bedrock embeddings, OpenAI-compatible (requires Bedrock enabled) |
| `POST /v1/rerank` | Bedrock Cohere Rerank 3.5, Cohere-compatible (requires Bedrock enabled) |
| `GET /health` | Health check |
| `GET /stats` | Call statistics (aggregated by model/day) |
| `GET /logs` | Call log entries (paginated) |

## Observability

Every LLM call is automatically logged to a local SQLite database at `~/.kiro2pi/observability.db`.

### What's recorded

| Field | Description |
|-------|-------------|
| `model` | Requested model name |
| `endpoint` | `/v1/messages` or `/v1/chat/completions` |
| `stream` | Whether the request was streaming |
| `latency_ms` | End-to-end request latency |
| `ttft_ms` | Time to first token (streaming only) |
| `status_code` | HTTP response status |
| `request_hash` | SHA256 of request body (for dedup, no raw content stored) |
| `has_tools` | Whether the request included tool definitions |
| `has_thinking` | Whether extended thinking was enabled |

### Query endpoints

```bash
# Stats aggregated by model and day
curl http://localhost:9090/stats
curl "http://localhost:9090/stats?model=claude-opus-4.7"
curl "http://localhost:9090/stats?since=2026-04-01"

# Paginated call logs
curl http://localhost:9090/logs
curl "http://localhost:9090/logs?limit=20&offset=0"
```

No full request/response bodies are stored. Use `DEBUG_SAVE_RAW=1` for raw response debugging.

## Known Limitations

- Q API request payload hard limit is ~1.9MB for Claude/GPT models and ~600KB for minimax/glm (measured 2026-08). The proxy pre-checks the serialized request and returns an Anthropic-style 413 `request_too_large` instead of an opaque upstream 400
- `input_tokens` in responses is derived from the upstream `contextUsageEvent` (percentage of the model's real window) when present, falling back to a chars/4 estimate; per-request credit usage from `meteringEvent` is logged
- claude-fable-5 (experimental preview) runs an aggressive content filter: large inputs (~280K+ tokens, lower for code-heavy content) may return 200 with `stopReason: CONTENT_FILTERED` and no output. The filter is probabilistic, so the proxy retries once on the same model, then falls back to `claude-opus-4.8` (mirroring Anthropic's official automatic-fallback behavior; Opus 4.8's classifiers intervene ~85% less often), and only surfaces an error if all attempts are filtered. Other Claude/GPT models are not affected
- `max_tokens` is forwarded via `additionalModelRequestFields` for adaptive Claude models, but upstream currently accepts without enforcing it (output is not truncated)
- A `cachePoint` checkpoint is set on the tools array, the last history user message, and the current message for prompt-caching-capable models (schema allows 4 per request); the API accepts them but exposes no cache usage metrics, so the benefit cannot be confirmed client-side
- Input token counts fall back to a chars/4 estimate when the upstream reports no context usage
- URL-based image sources are not supported (only base64)
- `output_config.effort` and `thinking` are forwarded natively via `additionalModelRequestFields` for models whose `ListAvailableModels` schema supports it (adaptive Claude models: opus-5, sonnet-5, fable-5, opus-4.6/4.7/4.8, sonnet-4.6; GPT models map effort to `reasoning.effort`). Older models fall back to the synthetic thinking tool and ignore effort.

## Credits

Based on [kiro2cc](https://github.com/bestK/kiro2cc) by bestK.

## License

MIT
