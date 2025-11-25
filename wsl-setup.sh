#!/bin/bash
# Sentinel-AI MCP Server - WSL Setup Script

echo "========================================="
echo "Sentinel-AI MCP Server - WSL Setup"
echo "========================================="
echo ""

# Check if running in WSL
if ! grep -qEi "(Microsoft|WSL)" /proc/version &> /dev/null ; then
    echo "❌ This script must be run in WSL!"
    exit 1
fi

# Start Docker
echo "[1/5] Starting Docker service..."
sudo service docker start
if [ $? -ne 0 ]; then
    echo "❌ Failed to start Docker. Please install Docker first."
    exit 1
fi

# Navigate to project directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "[2/5] Current directory: $SCRIPT_DIR"

# Check if config.yaml exists
echo "[3/5] Checking configuration..."
if [ ! -f config.yaml ]; then
    if [ -f config.yaml.example ]; then
        echo "📝 Creating config.yaml from example..."
        cp config.yaml.example config.yaml
        echo ""
        echo "⚠️  IMPORTANT: Please edit config.yaml with your OpenSearch credentials!"
        echo "   Run: nano config.yaml"
        echo ""
        read -p "Press Enter after editing config.yaml..." 
    else
        echo "❌ config.yaml.example not found!"
        exit 1
    fi
fi

# Build Docker image
echo "[4/5] Building Docker image..."
docker compose build
if [ $? -ne 0 ]; then
    echo "❌ Failed to build Docker image!"
    exit 1
fi

# Start container
echo "[5/5] Starting MCP server container..."
docker compose up -d
if [ $? -ne 0 ]; then
    echo "❌ Failed to start container!"
    exit 1
fi

# Wait for container to start
echo ""
echo "Waiting for container to start..."
sleep 3

# Verify container is running
echo ""
echo "========================================="
if docker ps | grep -q sentinel-mcp-server; then
    echo "✅ SUCCESS! MCP Server is running"
    echo "========================================="
    echo ""
    docker ps | grep sentinel-mcp-server
    echo ""
    echo "📋 Next steps:"
    echo "1. Configure Claude Desktop (Windows):"
    echo "   - Edit: %APPDATA%\\Claude\\claude_desktop_config.json"
    echo "   - Add: \"command\": \"wsl\""
    echo "   - See WSL_SETUP.md for full config"
    echo ""
    echo "2. Or configure CLI Claude (VS Code):"
    echo "   - Edit: %APPDATA%\\Code\\User\\globalStorage\\saoudrizwan.claude-dev\\settings\\cline_mcp_settings.json"
    echo "   - Add: \"command\": \"wsl\""
    echo ""
    echo "3. Restart Claude Desktop or VS Code"
    echo ""
    echo "🔍 Useful commands:"
    echo "   - View logs:    docker logs -f sentinel-mcp-server"
    echo "   - Stop server:  docker compose down"
    echo "   - Restart:      docker compose restart"
    echo ""
else
    echo "❌ FAILED! Container is not running"
    echo "========================================="
    echo ""
    echo "Checking logs..."
    docker logs sentinel-mcp-server
    echo ""
    exit 1
fi
