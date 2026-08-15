# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.

## Project Overview

kiro2pi is a proxy server that translates Anthropic API requests to AWS CodeWhisperer/Q Developer API, enabling tools like kiro-cli to use AWS Q Developer as a backend.

## Architecture

- **Package `main`** (split across files):
  - `main.go`: Entry point, CLI dispatch, small shared helpers
  - `server.go`: HTTP server setup, endpoint registration, middleware, retry policy, shared upstream client
  - `handlers.go`: `/v1/messages` stream/non-stream handlers, OpenAI-compat handlers, SSE helpers, CONTENT_FILTERED retry/fallback
  - `request.go`: Anthropic → CodeWhisperer request building (history, tools, images, validation pipeline)
  - `models.go`: Model mapping, additionalModelRequestFields (thinking/effort/max_tokens), context windows, payload limits, token estimation
  - `types.go`: Request/response structs (Anthropic + CodeWhisperer)
  - `token.go`: kiro-cli SQLite token retrieval and refresh
  - `bedrock.go`: Bedrock embeddings/rerank endpoints
  - `observability.go`: Call logging to SQLite (`/stats`, `/logs`)
- **`parser/`**: Event-stream (SSE) response parsing
- **Endpoints**:
  - `POST /v1/messages` - Anthropic API proxy (main endpoint)
  - `POST /v1/embeddings` - Bedrock embeddings, OpenAI-compatible (only when Bedrock enabled)
  - `POST /v1/rerank` - Bedrock Cohere Rerank 3.5, Cohere-compatible (only when Bedrock enabled)
  - `GET /health` - Health check
  - `/` - Catch-all (returns 404)

## Development Commands

```bash
# Build
go build -o kiro2pi .

# Run server
./kiro2pi server 9090

# Run as systemd service
sudo systemctl start kiro2pi
sudo systemctl status kiro2pi
journalctl -u kiro2pi -f
```

## Environment Variables

### Required
- `CODEWHISPERER_PROFILE_ARN`: AWS CodeWhisperer profile ARN

### Debug Options
- `DEBUG_SAVE_RAW=1`: Save raw API responses to `.raw` files
- `DEBUG_ACCESS_LOG=1`: Enable detailed HTTP access logging (method, path, client IP)

### Bedrock (optional, for `/v1/embeddings` and `/v1/rerank`)
- `BEDROCK_ENABLED=1`: Enable the Bedrock-backed endpoints
- `BEDROCK_AWS_PROFILE`: AWS shared-config profile (also enables the Bedrock endpoints)
- `BEDROCK_REGION`: AWS region (default `us-west-2`). Rerank model is pinned to `cohere.rerank-v3-5:0`

## Systemd Service

Service file: `/etc/systemd/system/kiro2pi.service`
Override config: `/etc/systemd/system/kiro2pi.service.d/override.conf`

```bash
# Edit override config
sudo systemctl edit kiro2pi

# Reload and restart after changes
sudo systemctl daemon-reload
sudo systemctl restart kiro2pi
```

## Checking Logs

```bash
# View recent logs
journalctl -u kiro2pi -n 50 --no-pager

# Follow logs in real-time
journalctl -u kiro2pi -f

# Filter access logs (when DEBUG_ACCESS_LOG=1)
journalctl -u kiro2pi | grep "请求路径:"

# Count requests by endpoint
journalctl -u kiro2pi --since "1 hour ago" | grep "请求路径:" | awk '{print $NF}' | sort | uniq -c
```

## Key Code Locations

- `logMiddleware`, `startServer`: server.go
- `handleStreamRequest`, `handleNonStreamRequest`: handlers.go
- `buildCodeWhispererRequest`: request.go
- `getToken`, `tryRefreshToken`: token.go
- `ModelMap`, `buildAdditionalModelRequestFields`: models.go

## Model Mapping

The server maps Anthropic model names to CodeWhisperer models (see `ModelMap` in models.go).
