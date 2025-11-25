# Claude Desktop Configuration Guide

## Setup Instructions

### 1. Install Dependencies

First, activate the virtual environment and install the package:

```bash
cd "e:\CyberSentinal All\Sentinel-AI\mcp-server"
.\venv\Scripts\activate
pip install -e .
```

### 2. Configure Claude Desktop

Add the following to your Claude Desktop configuration file:

**File Location:** `%APPDATA%\Claude\claude_desktop_config.json`

**Configuration:**
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

> **Note:** Make sure to use the full path to the Python executable in the venv!

### 3. Verify Configuration

Ensure your `config.yaml` has the correct OpenSearch credentials:
- Host: `http://192.168.38.130:9200`
- Username: `admin`
- Password: `admin`

### 4. Restart Claude Desktop

Close and restart Claude Desktop completely for the changes to take effect.

### 5. Test the Connection

Once Claude Desktop restarts, you should see the Sentinel-AI MCP tools available. Try these test queries:

```
1. "Search for critical alerts in the last 24 hours"
2. "Show me logs from agent SOC_GPU_SRV"
3. "List available log indices"
4. "What major alerts occurred in the last 12 hours?"
```

## Troubleshooting

### Tools Not Showing
- Check Claude Desktop logs: `%APPDATA%\Claude\logs`
- Verify Python path is correct in config
- Ensure venv is activated when testing manually

### Connection Errors
- Test OpenSearch connection: `curl http://192.168.38.130:9200`
- Verify credentials in `config.yaml`
- Check firewall settings

### Manual Testing

Test the MCP server manually:

```bash
cd "e:\CyberSentinal All\Sentinel-AI\mcp-server"
.\venv\Scripts\activate
python -m sentinel_mcp.server --config config.yaml
```

The server should start and wait for MCP protocol messages on stdin.

## Available Tools

| Tool | Description | Example Usage |
|------|-------------|---------------|
| `search_logs` | Advanced search with DQL | "Search for rule.level:12" |
| `get_agent_logs` | Get logs by agent name | "Show logs from MDM-189" |
| `get_major_alerts` | Critical alerts (level ≥ 12) | "What major alerts happened today?" |
| `list_indices` | List log indices | "List all available indices" |
| `get_index_mapping` | Get field mappings | "Show me available fields" |
| `get_network_flows` | Analyze network traffic | "Show top network flows" |
| `get_mitre_attacks` | MITRE ATT&CK analysis | "Show MITRE tactics detected" |
| `get_endpoint_analytics` | Endpoint behavior | "Analyze agent SOC_SRV behavior" |
| `threat_hunt` | Proactive threat hunting | "Hunt for brute force attempts" |

## Next Steps

Once basic tools are working:
1. Test with real queries against your OpenSearch data
2. Add more tools (network analytics, compliance, MITRE)
3. Tune page sizes and timeouts in `config.yaml`
