# Sentinel-AI MCP Server - Quick Start Guide

## 🚀 Quick Setup (3 Steps)

### 1. Configure Claude Desktop

Edit: `%APPDATA%\Claude\claude_desktop_config.json`

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

### 2. Verify OpenSearch Settings

Check `E:\CyberSentinal All\Sentinel-AI\mcp-server\config.yaml`:
- Host: `http://192.168.38.130:9200`
- Username: `mcp_service`
- Password: `MCPReadOnly123!`

### 3. Restart Claude Desktop

Close and restart Claude Desktop completely.

---

## 🧪 Test Queries  

Try these in Claude:

```
1. "Search for critical alerts in the last 24 hours"
2. "Show me logs from agent SOC_GPU_SRV"
3. "List all available log indices"
4. "What major alerts occurred today?"
5. "Search for rule.mitre.id:T1110"
```

---

## Available Tools

| Tool | Purpose |
|------|---------|
| `search_logs` | Advanced search with DQL support |
| `get_agent_logs` | Query logs by agent name |
| `get_major_alerts` | Critical alerts (level ≥ 12) |
| `list_indices` | List available indices |
| `get_index_mapping` | Show queryable fields |

---

## 🔧 Troubleshooting

**Tools not showing?**
- Check logs: `%APPDATA%\Claude\logs`
- Verify Python path in config
- Restart Claude Desktop

**Connection errors?**
- Test: `curl http://192.168.38.130:9200`
- Check credentials in `config.yaml`

**Manual test:**
```bash
cd "E:\CyberSentinal All\Sentinel-AI\mcp-server"
venv\Scripts\activate  
python -m sentinel_mcp.server --config config.yaml
```

---

## 📚 Full Documentation

- `README.md` - Complete documentation
- `CLAUDE_SETUP.md` - Detailed setup guide
- `walkthrough.md` - Implementation details
