# Sentinel-AI MCP Server

Python-based Model Context Protocol (MCP) server for Sentinel-AI SIEM system. Provides specialized security analysis tools for AI assistants like Claude Desktop.

## Features

- **Advanced SIEM Search** - DQL detection, field boosting, multi-strategy search
- **Agent-Specific Queries** - Get logs by specific agent name
- **Major Alerts** - Critical security events (rule level ≥ 12)
- **Network Analytics** - Flow analysis with protocol normalization
- **Compliance Tools** - HIPAA, GDPR, NIST, PCI DSS, TSC
- **MITRE ATT&CK** - Threat intelligence framework analysis
- **File Integrity Monitoring** - Track file changes
- **Vulnerability Tracking** - CVE detection and analysis
- **Authentication Analysis** - Session and login monitoring

## Installation

### 🚀 Recommended: WSL + Docker (Easiest)

For the simplest setup, use Docker in WSL2. This eliminates Python environment issues.

**Quick Start:**
```bash
# From WSL terminal
cd ~/sentinel-mcp
./wsl-setup.sh
```

📖 **Full Guide:** See [WSL_SETUP.md](WSL_SETUP.md) for complete WSL + Docker instructions

📋 **Quick Reference:** See [WSL_QUICK_REFERENCE.md](WSL_QUICK_REFERENCE.md) for common commands

---

### Alternative: Docker Desktop

If you prefer Docker Desktop on Windows:

**Quick Start:**
```bash
# From PowerShell
cd "e:\CyberSentinal All\Sentinel-AI\mcp-server"
.\docker-setup.bat
```

📖 **Full Guide:** See [DOCKER_SETUP.md](DOCKER_SETUP.md)

---

### Alternative: Python Virtual Environment

<details>
<summary>Click to expand Python venv instructions</summary>

#### 1. Create Virtual Environment

```bash
cd "e:\CyberSentinal All\Sentinel-AI\mcp-server"
python -m venv venv
```

#### 2. Activate Virtual Environment

**Windows:**
```bash
.\venv\Scripts\activate
```

**Linux/Mac:**
```bash
source venv/bin/activate
```

#### 3. Install Package

```bash
pip install -e .
```

📖 **Full Guide:** See [CLAUDE_SETUP.md](CLAUDE_SETUP.md) for Python venv setup

</details>

## Configuration

Create a `config.yaml` file in the mcp-server directory:

```yaml
opensearch:
  hosts: "http://192.168.38.130:9200"
  username: "mcp_service"
  password: "MCPReadOnly123!"
  verify_certs: false
  use_ssl: false

security:
  field_level_security:
    excluded_fields:
      - "*password*"
      - "*secret*"
      - "*token*"
      - "*credential*"
      - "*key*"

tools:
  limits:
    max_page_size: 1000
    default_page_size: 100
    max_flow_limit: 5000
```

## Claude Desktop Integration

### For WSL + Docker Setup

Add to `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sentinel-ai": {
      "command": "wsl",
      "args": [
        "-e",
        "docker",
        "exec",
        "-i",
        "sentinel-mcp-server",
        "python",
        "-m",
        "sentinel_mcp.server",
        "--config",
        "config.yaml"
      ]
    }
  }
}
```

### For Docker Desktop Setup

```json
{
  "mcpServers": {
    "sentinel-ai": {
      "command": "docker",
      "args": [
        "exec",
        "-i",
        "sentinel-mcp-server",
        "python",
        "-m",
        "sentinel_mcp.server",
        "--config",
        "config.yaml"
      ]
    }
  }
}
```

### For Python venv Setup

```json
{
  "mcpServers": {
    "sentinel-ai": {
      "command": "E:\\CyberSentinal All\\Sentinel-AI\\mcp-server\\venv\\Scripts\\python.exe",
      "args": [
        "-m",
        "sentinel_mcp.server",
        "--config",
        "E:\\CyberSentinal All\\Sentinel-AI\\mcp-server\\config.yaml"
      ]
    }
  }
}
```

Restart Claude Desktop to load the MCP server.

## Usage with Claude Desktop

Once configured, you can ask Claude:

- "Search for critical alerts in the last 24 hours"
- "Show me logs from agent SOC_GPU_SRV in the last 12 hours"
- "What network flows occurred in the last 6 hours?"
- "Find all MITRE T1110 brute force attempts"
- "List HIPAA compliance violations today"
- "Show file changes on agent MDM-189"

## Available Tools

| Tool | Description |
|------|-------------|
| `search_logs` | Advanced search with DQL support and field boosting |
| `get_agent_logs` | Query logs by specific agent name |
| `get_major_alerts` | Critical alerts (rule level ≥ 12) |
| `get_network_flows` | Network traffic analysis |
| `get_mitre_attacks` | MITRE ATT&CK framework analysis |
| `get_hipaa_logs` | HIPAA compliance events |
| `get_gdpr_logs` | GDPR compliance events |
| `get_nist_logs` | NIST framework events |
| `get_fim_events` | File integrity monitoring |
| `get_vulnerabilities` | CVE tracking |
| `get_auth_sessions` | Authentication analysis |
| `list_indices` | List available log indices |
| `get_index_mapping` | Get field mappings for indices |
| `investigate_ip` | Deep correlation analysis for IP addresses |
| `investigate_user` | Comprehensive UEBA for users/agents |
| `threat_hunt` | Hunter-style queries for threats |

## Development

Run tests:
```bash
pytest
```

Format code:
```bash
black src/
```

Lint:
```bash
ruff check src/
```

## Troubleshooting

### Connection Issues
- Verify OpenSearch is running at the configured host
- Check credentials in config.yaml
- Ensure OpenSearch allows connections from your IP

### No Tools Visible in Claude Desktop
- Restart Claude Desktop after configuration changes
- Check Claude Desktop logs: `%APPDATA%\Claude\logs`
- Verify Python path in config matches your installation

### Query Performance
- Adjust `max_page_size` in config.yaml for smaller result sets
- Use more specific time ranges (e.g., "last 1 hour" vs "last 7 days")
- Filter by agent or log type for focused queries

## License
This Project was made for internel project
