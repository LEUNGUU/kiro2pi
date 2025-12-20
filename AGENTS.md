# AGENTS.md

This file provides guidance to OpenAI Codex and GPT-based agents when working with code in this repository.

## Project Overview

DevSecOps MCP Server with three main capabilities:
1. **Seeker IAST Integration**: Security testing with smart project resolution
2. **ServiceNow Integration**: Automated approval record creation
3. **MongoDB Caching**: Atomic project caching with concurrent access protection

Built with FastMCP 2.0, production-ready with Gunicorn, optional Entra ID auth.

## Architecture

- **FastMCP Server** (`app/main.py`): HTTP server with MongoDB caching
- **Seeker IAST Tool** (`app/tools/iast_tool.py`): Security testing integration
- **MongoDB Cache** (`app/cache/seeker_cache.py`): Atomic collection swaps
- **ServiceNow Client** (`app/services/snow_client.py`): Approval records with attachments
- **Client Auth** (`app/middleware/client_auth.py`): Entra ID token validation

## Available Tools (10 total)

### Vulnerability Management
- `check_iast_results`: Retrieve Seeker IAST scan results
- `get_vulnerability_details`: Get vulnerability details by ID
- `get_aspm_finding_details`: Get ASPM security finding details

### Project Management
- `get_seeker_project_info`: Get project info and stats
- `search_seeker_projects`: Search projects via MongoDB cache
- `get_project_by_name`: Get project by exact name

### Configuration & Cache
- `validate_seeker_configuration`: Validate Seeker connectivity
- `refresh_project_cache`: Trigger MongoDB cache refresh
- `get_cache_status`: Get cache statistics

### ServiceNow
- `create_snow_approval_record`: Create approval records with attachments

## Development Commands

```bash
# Setup
uv venv --python 3.11
source .venv/bin/activate
uv add fastmcp structlog httpx pydantic pydantic-settings pyyaml

# Testing
python -m pytest
python -m pytest -v
python -m pytest --cov=app tests/

# Run Server
gunicorn app.main:app -c gunicorn_config.py
LOG_LEVEL=debug gunicorn app.main:app -c gunicorn_config.py

# Code Quality
black app/ tests/
isort app/ tests/
mypy app/
ruff check app/ tests/
```

## Key Patterns

### FastMCP Tool Pattern
```python
@mcp.tool
def my_tool(param: str, optional_param: str = "default") -> str:
    """Tool description"""
    try:
        return json.dumps({"success": True, "result": "data"})
    except Exception as error:
        return json.dumps({"success": False, "error": str(error)})
```

### Atomic MongoDB Caching
- Active collection: `{name}_active`
- Temp collection: `{name}_{timestamp}`
- Atomic rename for thread-safe swaps

## Environment Variables

### Required
- `CX_SEEKER_SERVER_URL`, `SEEKER_API_TOKEN`: Seeker IAST
- `MONGODB_CONNECTION_STRING`, `MONGODB_DATABASE_NAME`: MongoDB

### Optional
- `MCP_PORT`: Server port (default: 3000)
- `LOG_LEVEL`: debug/info/warning/error
- `ENABLE_ENTRA_AUTH`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`: Auth
- `ASPM_BASE_URL`, `ASPM_API_KEY`: ASPM integration

## Testing

Test files in `tests/`:
- `test_iast_tool.py`: Seeker integration
- `test_mcp_real.py`: Real integration tests
- `test_concurrent_cache.py`: Atomic caching
- `test_snow_tool.py`: ServiceNow integration
- `test_models.py`: Pydantic validation

## Security

- Use environment variables for credentials
- Pydantic for input validation
- Optional Entra ID JWT validation
- Structured logging for audit trails
