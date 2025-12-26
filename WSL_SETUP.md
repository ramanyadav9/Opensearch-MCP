# WSL Docker Setup for Sentinel-AI MCP Server

This guide shows how to run the Sentinel-AI MCP server using Docker in WSL2 and connect it to Claude Desktop/CLI on Windows.

## ✅ Why WSL + Docker?

- ✅ Lighter than Docker Desktop
- ✅ No Hyper-V issues
- ✅ Better performance
- ✅ Works seamlessly with Windows Claude
- ✅ Easier to troubleshoot

---

## 🚀 Quick Setup

### Step 1: Enable WSL2 (if not already enabled)

Open **PowerShell as Administrator** and run:

```powershell
wsl --install
```

Or if WSL is already installed, set WSL2 as default:

```powershell
wsl --set-default-version 2
```

**Restart your computer** after installation.

### Step 2: Install Ubuntu in WSL

```powershell
wsl --install -d Ubuntu-22.04
```

Or install from Microsoft Store: Ubuntu 22.04 LTS

Launch Ubuntu and create a username/password when prompted.

### Step 3: Install Docker in WSL

Open your WSL terminal (Ubuntu) and run:

```bash
# Update packages
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y apt-transport-https ca-certificates curl software-properties-common

# Add Docker GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Add Docker repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Add your user to docker group (avoid sudo)
sudo usermod -aG docker $USER

# Start Docker service
sudo service docker start

# Enable Docker to start on boot
echo "sudo service docker start" >> ~/.bashrc
```

**Log out and log back in** to WSL for group changes to take effect.

### Step 4: Verify Docker Installation

```bash
docker --version
docker compose version
```

### Step 5: Copy MCP Server Files to WSL

From **Windows PowerShell**, copy your project to WSL:

```powershell
# Navigate to your project
cd "E:\CyberSentinal All\Sentinel-AI\mcp-server"

# Copy to WSL home directory
wsl -e bash -c "mkdir -p ~/sentinel-mcp"
wsl -e bash -c "cp -r /mnt/e/CyberSentinal\ All/Sentinel-AI/mcp-server/* ~/sentinel-mcp/"
```

Or manually from **WSL terminal**:

```bash
# Create directory
mkdir -p ~/sentinel-mcp

# Copy files
cp -r "/mnt/e/CyberSentinal All/Sentinel-AI/mcp-server/"* ~/sentinel-mcp/

# Navigate to the directory
cd ~/sentinel-mcp
```

### Step 6: Configure OpenSearch Connection

In **WSL terminal**:

```bash
cd ~/sentinel-mcp

# Copy example config
cp config.yaml.example config.yaml

# Edit config
nano config.yaml
```

Update these values:
```yaml
opensearch:
  hosts: "http://192.168.1.12:9200"
  username: "admin"
  password: "admin"
  verify_certs: false
  use_ssl: false
```

Press `Ctrl+X`, then `Y`, then `Enter` to save.

### Step 7: Build and Run Docker Container

In **WSL terminal**:

```bash
cd ~/sentinel-mcp

# Make sure Docker is running
sudo service docker start

# Build the image
docker compose build

# Start the container
docker compose up -d

# Verify it's running
docker ps | grep sentinel-mcp
```

### Step 8: Configure Claude Desktop for WSL

Edit on **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

**Full path:** `C:\Users\91916\AppData\Roaming\Claude\claude_desktop_config.json`

**Configuration:**
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

### Step 9: Configure CLI Claude (VS Code) for WSL

Edit on **Windows**: `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`

**Full path:** `C:\Users\91916\AppData\Roaming\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`

**Configuration:**
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

### Step 10: Restart Claude

**Restart Claude Desktop or VS Code completely** for changes to take effect.

---

## 🧪 Testing

### Test from Windows PowerShell

```powershell
# Check if WSL Docker is running
wsl -e docker ps

# View container logs
wsl -e docker logs sentinel-mcp-server

# Test MCP server manually
wsl -e docker exec -i sentinel-mcp-server python -m sentinel_mcp.server --config config.yaml
```

### Test Queries in Claude

```
1. "List all available log indices"
2. "Search for critical alerts in the last 24 hours"
3. "Show me logs from agent SOC_GPU_SRV"
4. "What major alerts occurred today?"
```

---

## 🛠️ Common Commands

### Starting/Stopping (from WSL terminal)

```bash
# Start Docker service
sudo service docker start

# Start MCP container
cd ~/sentinel-mcp
docker compose up -d

# Stop MCP container
docker compose down

# Restart container
docker compose restart

# View logs
docker logs -f sentinel-mcp-server
```

### From Windows PowerShell

```powershell
# Start Docker in WSL
wsl -e sudo service docker start

# Check container status
wsl -e docker ps

# View logs
wsl -e docker logs sentinel-mcp-server

# Restart container
wsl -e docker compose -f ~/sentinel-mcp/docker-compose.yml restart
```

### Auto-start Docker on WSL Boot

Add to `~/.bashrc` in WSL:

```bash
# Start Docker automatically
if ! service docker status > /dev/null 2>&1; then
    sudo service docker start
fi
```

---

## 🔧 Troubleshooting

### Docker Service Not Running

```bash
# Check status
sudo service docker status

# Start manually
sudo service docker start

# Check for errors
sudo journalctl -u docker
```

### Permission Denied

```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Log out and back in, or run:
newgrp docker
```

### Can't Access OpenSearch from WSL

```bash
# Test connection
curl http://192.168.1.133:9200

# If that fails, try accessing through Windows networking
curl http://192.168.1.133:9200
```

### WSL Command Not Found in Windows

Make sure WSL2 is properly installed:

```powershell
wsl --status
wsl --list --verbose
```

### Config File Not Found

Make sure the path in `docker-compose.yml` is correct:

```yaml
volumes:
  - ./config.yaml:/app/config.yaml:ro
```

---

## 📁 File Locations

| Item | Location |
|------|----------|
| **WSL Project** | `~/sentinel-mcp` (in WSL) |
| **Windows Project** | `E:\CyberSentinal All\Sentinel-AI\mcp-server` |
| **WSL from Windows** | `\\wsl$\Ubuntu-22.04\home\<username>\sentinel-mcp` |
| **Claude Desktop Config** | `%APPDATA%\Claude\claude_desktop_config.json` |
| **CLI Claude Config** | `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json` |

---

## 🔄 Syncing Files Windows ↔ WSL

### Option 1: Access WSL files from Windows

In Windows Explorer, navigate to:
```
\\wsl$\Ubuntu-22.04\home\<your-username>\sentinel-mcp
```

You can edit files directly here with VS Code or any Windows editor.

### Option 2: Work in Windows, sync to WSL

```powershell
# Sync from Windows to WSL
wsl -e rsync -av /mnt/e/CyberSentinal\ All/Sentinel-AI/mcp-server/ ~/sentinel-mcp/
```

### Option 3: Use VS Code Remote-WSL

Install **Remote - WSL** extension in VS Code, then:
```powershell
# Open project in VS Code from WSL
wsl -e code ~/sentinel-mcp
```

---

## 🎯 Automated Setup Script

Create `wsl-setup.sh` in your WSL project directory:

```bash
#!/bin/bash
# Save as ~/sentinel-mcp/wsl-setup.sh

echo "========================================="
echo "Sentinel-AI MCP Server - WSL Setup"
echo "========================================="

# Start Docker
echo "[1/4] Starting Docker service..."
sudo service docker start

# Navigate to project
cd ~/sentinel-mcp

# Check config
echo "[2/4] Checking configuration..."
if [ ! -f config.yaml ]; then
    echo "Creating config.yaml from example..."
    cp config.yaml.example config.yaml
    echo "⚠️  Please edit config.yaml with your OpenSearch credentials"
    exit 1
fi

# Build image
echo "[3/4] Building Docker image..."
docker compose build

# Start container
echo "[4/4] Starting container..."
docker compose up -d

# Verify
echo ""
echo "Checking container status..."
sleep 2
docker ps | grep sentinel-mcp

echo ""
echo "========================================="
echo "✅ Setup complete!"
echo "========================================="
echo ""
echo "Container logs: docker logs -f sentinel-mcp-server"
echo ""
```

Make it executable and run:

```bash
chmod +x ~/sentinel-mcp/wsl-setup.sh
./wsl-setup.sh
```

---

## 📊 Architecture

```
Windows (Claude Desktop/CLI)
        ↓
    WSL Command
        ↓
WSL2 (Ubuntu) → Docker Container → OpenSearch
                     ↓
              MCP Server (Python)
```

---

## ✅ Benefits of WSL Approach

| Benefit | Description |
|---------|-------------|
| 🚀 **No Docker Desktop** | Lighter and faster |
| 🔧 **Better Control** | Full Linux environment |
| 💾 **Less Resource** | More efficient than Hyper-V |
| 🛠️ **Easy Debug** | Direct shell access |
| 🔄 **Flexible** | Works with all WSL distros |

---

## 🎉 Summary

Setup in **5 commands** (from WSL terminal):

```bash
# 1. Copy project
cp -r "/mnt/e/CyberSentinal All/Sentinel-AI/mcp-server/"* ~/sentinel-mcp/

# 2. Configure
cd ~/sentinel-mcp && cp config.yaml.example config.yaml && nano config.yaml

# 3. Start Docker
sudo service docker start

# 4. Build and run
docker compose build && docker compose up -d

# 5. Verify
docker ps | grep sentinel-mcp
```

Then configure Claude with `"command": "wsl"` and restart! 🎯
