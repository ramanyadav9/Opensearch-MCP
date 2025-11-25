# Docker Setup for Sentinel-AI MCP Server

This guide explains how to run the Sentinel-AI MCP server using Docker and connect it to Claude Desktop or CLI.

## 🚀 Quick Start

### Prerequisites
- Docker Desktop installed and running
- OpenSearch accessible at `192.168.1.133:9200`

### 1. Configure Your Environment

Create `config.yaml` from the example:

```bash
cd "E:\CyberSentinal All\Sentinel-AI\mcp-server"
copy config.yaml.example config.yaml
```

Edit `config.yaml` with your OpenSearch credentials:
```yaml
opensearch:
  hosts: "http://192.168.1.133:9200"
  username: "admin"
  password: "admin"
  verify_certs: false
  use_ssl: false
```

### 2. Build the Docker Image

```bash
docker-compose build
```

Or manually:
```bash
docker build -t sentinel-mcp:latest .
```

### 3. Run the MCP Server

Using docker-compose (recommended):
```bash
docker-compose up -d
```

Or manually:
```bash
docker run -d \
  --name sentinel-mcp-server \
  --network host \
  -v "E:\CyberSentinal All\Sentinel-AI\mcp-server\config.yaml:/app/config.yaml:ro" \
  sentinel-mcp:latest
```

### 4. Verify the Container is Running

```bash
docker ps | findstr sentinel-mcp
docker logs sentinel-mcp-server
```

---

## 🔌 Connect to Claude Desktop

Edit: `%APPDATA%\Claude\claude_desktop_config.json`

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

**Restart Claude Desktop** completely for changes to take effect.

---

## 🔌 Connect to CLI Claude (VS Code Extension)

Edit: `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`

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

**Restart VS Code** completely for changes to take effect.

---

## 🧪 Test Queries

Once connected, try these queries in Claude:

```
1. "Search for critical alerts in the last 24 hours"
2. "Show me logs from agent SOC_GPU_SRV"
3. "List all available log indices"
4. "What major alerts occurred today?"
5. "Search for rule.mitre.id:T1110"
```

---

## 🛠️ Docker Commands Reference

### Start the server
```bash
docker-compose up -d
```

### Stop the server
```bash
docker-compose down
```

### View logs
```bash
docker logs -f sentinel-mcp-server
```

### Restart the server
```bash
docker-compose restart
```

### Rebuild after code changes
```bash
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Access container shell (for debugging)
```bash
docker exec -it sentinel-mcp-server /bin/bash
```

### Test MCP server manually inside container
```bash
docker exec -i sentinel-mcp-server python -m sentinel_mcp.server --config config.yaml
```

---

## 🔧 Troubleshooting

### Container won't start
```bash
# Check Docker Desktop is running
docker ps

# Check container logs
docker logs sentinel-mcp-server

# Check if port is available
netstat -an | findstr :3000
```

### Can't connect to OpenSearch
```bash
# Test from container
docker exec -it sentinel-mcp-server curl http://192.168.1.133:9200

# Test from host
curl http://192.168.1.133:9200

# Check network mode
docker inspect sentinel-mcp-server | findstr NetworkMode
```

### Claude not showing MCP tools
1. Verify container is running: `docker ps`
2. Check Claude logs: `%APPDATA%\Claude\logs`
3. Restart Claude Desktop completely
4. Test manually: `docker exec -i sentinel-mcp-server python -m sentinel_mcp.server --config config.yaml`

### Configuration changes not taking effect
```bash
# Restart container to reload config
docker-compose restart

# Or rebuild if you changed Dockerfile
docker-compose down
docker-compose build
docker-compose up -d
```

---

## 🔒 Security Notes

- The `config.yaml` file contains sensitive credentials
- It's mounted read-only (`:ro`) in the container
- Never commit `config.yaml` to version control
- Use environment variables for production deployments

---

## 📊 Network Modes Explained

### Host Network (Current Setup)
```yaml
network_mode: host
```
- Container uses host's network stack
- Best for accessing services on host machine (like local OpenSearch)
- No port mapping needed

### Bridge Network (Alternative)
```yaml
networks:
  - sentinel-network
```
- Isolated network for containers
- Requires explicit port mapping
- Better for containerized OpenSearch

---

## 🎯 Benefits of Docker Approach

✅ **No Python environment issues** - Everything is containerized  
✅ **Consistent setup** - Works the same on any machine  
✅ **Easy updates** - Rebuild and restart container  
✅ **Portable** - Share the entire setup easily  
✅ **Isolated** - Doesn't affect host Python installation  
✅ **Simple Claude config** - Just point to Docker container

---

## 📚 Next Steps

1. ✅ Configure and start Docker container
2. ✅ Update Claude Desktop/CLI config
3. ✅ Test basic queries
4. 🔄 Customize tools in `config.yaml`
5. 🔄 Add more SIEM analytics tools
6. 🔄 Set up production deployment
