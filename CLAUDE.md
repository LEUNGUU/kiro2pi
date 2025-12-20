# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go CLI tool called `kiro2cc` that manages Kiro authentication tokens and provides an Anthropic API proxy service. The tool acts as a bridge between Anthropic API requests and AWS CodeWhisperer, translating requests and responses between the two formats.

## Build and Development Commands

```bash
# Build the application
go build -o kiro2cc main.go

# Run tests
go test ./...

# Run specific test in parser package (requires parser/response.raw test fixture)
go test ./parser -v

# Run the application
./kiro2cc [command]
```

## Application Commands

- `./kiro2cc read` - Read and display token information
- `./kiro2cc refresh` - Refresh the access token using refresh token
- `./kiro2cc export` - Export environment variables for other tools
- `./kiro2cc claude` - Update Claude Code config to bypass region restrictions
- `./kiro2cc server [port]` - Start HTTP proxy server (default port 8080)

## Architecture

### Core Components

1. **Token Management** (`main.go`)
   - Reads tokens from `~/.aws/sso/cache/kiro-auth-token.json`
   - Handles token refresh via `https://prod.us-east-1.auth.desktop.kiro.dev/refreshToken`
   - Cross-platform environment variable export (Windows CMD/PowerShell, Linux/macOS)

2. **API Translation** (`main.go:buildCodeWhispererRequest`)
   - Converts Anthropic API requests to CodeWhisperer format
   - Maps model names via `ModelMap` constant
   - Handles conversation history, system messages, and tool definitions

3. **HTTP Proxy Server** (`main.go:startServer`)
   - Serves on `/v1/messages` endpoint (POST) and `/health` endpoint (GET)
   - Supports both streaming (`handleStreamRequest`) and non-streaming (`handleNonStreamRequest`) requests
   - Automatic token refresh on 403 errors

4. **Response Parser** (`parser/sse_parser.go`)
   - Parses binary-framed CodeWhisperer responses (custom wire format with length/header/payload/CRC32)
   - Converts to Anthropic-compatible SSE events
   - Handles text content and tool use blocks

### Key Data Structures

- `AnthropicRequest` / `AnthropicRequestMessage` - Incoming API request format
- `CodeWhispererRequest` - Outgoing AWS request format with nested conversation state
- `TokenData` - Authentication token storage (accessToken, refreshToken, expiresAt)
- `SSEEvent` - Streaming response event (in parser package)

### Request Flow

1. Client sends Anthropic API request to `/v1/messages`
2. Server reads token from `~/.aws/sso/cache/kiro-auth-token.json`
3. Request converted to CodeWhisperer format via `buildCodeWhispererRequest`
4. Proxied to `https://codewhisperer.us-east-1.amazonaws.com/generateAssistantResponse`
5. Binary response parsed via `parser.ParseEvents`
6. Converted to Anthropic SSE format and streamed/returned to client

## Development Notes

- Model mapping required between Anthropic and CodeWhisperer model IDs (see `ModelMap`)
- Currently supported models: `claude-sonnet-4-20250514`, `claude-3-5-haiku-20241022`
- Streaming responses include random delays (0-300ms) between events
- Automatic token refresh on 403 authentication failures