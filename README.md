# kiro2pi

A proxy server that enables [pi-coding-agent](https://github.com/badlogic/pi-mono) to use AWS CodeWhisperer/Kiro as a backend.

## Overview

```
┌─────────────────┐     ┌─────────────┐     ┌──────────────────┐
│ pi-coding-agent │────▶│   kiro2pi   │────▶│  CodeWhisperer   │
│  (Anthropic API)│     │   (proxy)   │     │    (Q API)       │
└─────────────────┘     └─────────────┘     └──────────────────┘
```

kiro2pi translates Anthropic API requests to CodeWhisperer Q API format, allowing you to use pi-coding-agent with your Kiro/CodeWhisperer subscription.

## Features

- Anthropic Messages API compatible proxy
- Automatic token management (reads from kiro-cli)
- Streaming support
- Tool use / function calling support
- Extended thinking support (via thinking tool)
- Automatic token refresh on 403 errors
- Retry with exponential backoff for rate limits

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
go build -o kiro2pi main.go
```

### From releases

Download the latest release for your platform from the [Releases](https://github.com/LEUNGUU/kiro2pi/releases) page.

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
          "id": "claude-opus-4.5",
          "name": "Claude Opus 4.5 (Kiro)",
          "reasoning": true,
          "input": ["text", "image"],
          "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 },
          "contextWindow": 128000,
          "maxTokens": 64000
        },
        {
          "id": "claude-sonnet-4.5",
          "name": "Claude Sonnet 4.5 (Kiro)",
          "reasoning": true,
          "input": ["text", "image"],
          "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 },
          "contextWindow": 128000,
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
  "defaultModel": "claude-opus-4.5"
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
| `DEBUG_SAVE_RAW` | Set to `true` to save raw API responses for debugging |

## Supported Models

The proxy maps model names to CodeWhisperer models:

| Request Model | CodeWhisperer Model |
|---------------|---------------------|
| `claude-opus-4.5` | `claude-opus-4.5` |
| `claude-sonnet-4.5` | `claude-sonnet-4.5` |
| `claude-sonnet-4` | `claude-sonnet-4` |
| `claude-haiku-4.5` | `claude-haiku-4.5` |

## Known Limitations

- Context window is limited by CodeWhisperer (use 128K in config to be safe)
- Input token counts are estimated (chars/4 heuristic)

## Credits

Based on [kiro2cc](https://github.com/bestK/kiro2cc) by bestK.

## License

MIT
