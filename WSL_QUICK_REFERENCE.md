# Quick Reference: WSL + Docker Commands

## 🚀 Initial Setup (One-time)

### From Windows PowerShell (as Administrator)
```powershell
# Install WSL2
wsl --install -d Ubuntu-22.04

# After restart, verify
wsl --status
```

### From WSL Terminal (Ubuntu)
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Copy project files
cp -r "/mnt/e/CyberSentinal All/Sentinel-AI/mcp-server/"* ~/sentinel-mcp/
cd ~/sentinel-mcp

# Configure and run setup
cp config.yaml.example config.yaml
nano config.yaml  # Edit your OpenSearch credentials
chmod +x wsl-setup.sh
./wsl-setup.sh
```

---

## 🔄 Daily Usage

### Start MCP Server (from WSL)
```bash
cd ~/sentinel-mcp
sudo service docker start
docker compose up -d
```

### Check Status (from Windows)
```powershell
wsl -e docker ps
```

---

## 🔌 Claude Configuration

### Claude Desktop
**File:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "sentinel-ai": {
      "command": "wsl",
      "args": ["-e", "docker", "exec", "-i", "sentinel-mcp-server", 
               "python", "-m", "sentinel_mcp.server", "--config", "config.yaml"]
    }
  }
}
```

### CLI Claude (VS Code)
**File:** `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`

```json
{
  "mcpServers": {
    "sentinel-ai": {
      "command": "wsl",
      "args": ["-e", "docker", "exec", "-i", "sentinel-mcp-server",
               "python", "-m", "sentinel_mcp.server", "--config", "config.yaml"]
    }
  }
}
```

---

## 🛠️ Common Commands

| Task | Windows PowerShell | WSL Terminal |
|------|-------------------|--------------|
| **Start Docker** | `wsl -e sudo service docker start` | `sudo service docker start` |
| **Start Server** | `wsl -e docker compose -f ~/sentinel-mcp/docker-compose.yml up -d` | `cd ~/sentinel-mcp && docker compose up -d` |
| **Stop Server** | `wsl -e docker compose -f ~/sentinel-mcp/docker-compose.yml down` | `cd ~/sentinel-mcp && docker compose down` |
| **View Logs** | `wsl -e docker logs -f sentinel-mcp-server` | `docker logs -f sentinel-mcp-server` |
| **Check Status** | `wsl -e docker ps` | `docker ps` |
| **Restart** | `wsl -e docker restart sentinel-mcp-server` | `docker restart sentinel-mcp-server` |
| **Shell Access** | `wsl -e docker exec -it sentinel-mcp-server bash` | `docker exec -it sentinel-mcp-server bash` |

---

## 📁 File Locations

| What | Where |
|------|-------|
| **WSL Project** | `~/sentinel-mcp` |
| **Windows Access** | `\\wsl$\Ubuntu-22.04\home\<user>\sentinel-mcp` |
| **Original Files** | `E:\CyberSentinal All\Sentinel-AI\mcp-server` |

---

## 🔧 Troubleshooting

```bash
# Docker not running
sudo service docker status
sudo service docker start

# Container not found
docker ps -a
docker logs sentinel-mcp-server

# Permission denied
sudo usermod -aG docker $USER
newgrp docker

# Can't connect to OpenSearch
curl http://192.168.1.12:9200
```

---

## 🎯 Auto-start Docker

Add to `~/.bashrc`:
```bash
# Auto-start Docker
if ! service docker status > /dev/null 2>&1; then
    sudo service docker start > /dev/null 2>&1
fi
```

---

## 📊 Full Setup Flow

```
1. [Windows] Install WSL2
          ↓
2. [WSL] Install Docker
          ↓
3. [WSL] Copy project → ~/sentinel-mcp
          ↓
4. [WSL] Edit config.yaml
          ↓
5. [WSL] Run ./wsl-setup.sh
          ↓
6. [Windows] Edit Claude config
          ↓
7. [Windows] Restart Claude
          ↓
8. ✅ DONE!
```
