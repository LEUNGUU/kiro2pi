# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.

## Project Overview

kiro2pi is a proxy server that translates Anthropic API requests to AWS CodeWhisperer/Q Developer API, enabling tools like kiro-cli to use AWS Q Developer as a backend.

## Architecture

- **main.go**: Single-file Go application containing all proxy logic
- **Endpoints**:
  - `POST /v1/messages` - Anthropic API proxy (main endpoint)
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

- `logMiddleware` (~line 1496): HTTP request logging middleware
- `startServer` (~line 1520): Server setup and endpoint registration
- `handleStreamRequest` (~line 1656): Streaming response handler
- `handleNonStreamRequest` (~line 1938): Non-streaming response handler
- `getToken` (~line 1440): Token retrieval from kiro-cli database

## Model Mapping

The server maps Anthropic model names to CodeWhisperer models (see `modelMapping` around line 629).
