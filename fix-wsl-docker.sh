#!/bin/bash

echo "=========================================="
echo "Fixing WSL Docker for Sentinel-AI MCP"
echo "=========================================="
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed!"
    echo "Please run the installation steps from WSL_SETUP.md"
    exit 1
fi

echo "✅ Docker is installed"
echo ""

# Start Docker service
echo "Starting Docker service..."
sudo service docker start
sleep 2

# Check Docker status
if sudo service docker status | grep -q "running"; then
    echo "✅ Docker is running"
else
    echo "❌ Docker failed to start"
    echo "Check logs: sudo journalctl -u docker"
    exit 1
fi

echo ""

# Add user to docker group if not already added
if ! groups | grep -q docker; then
    echo "Adding current user to docker group..."
    sudo usermod -aG docker $USER
    echo "⚠️  You need to log out and back in for group changes to take effect"
    echo "⚠️  Or run: newgrp docker"
else
    echo "✅ User already in docker group"
fi

echo ""

# Navigate to sentinel-mcp directory
if [ -d ~/sentinel-mcp ]; then
    cd ~/sentinel-mcp
    echo "✅ Found ~/sentinel-mcp directory"
else
    echo "❌ ~/sentinel-mcp directory not found!"
    echo "Please copy files: cp -r '/mnt/e/CyberSentinal All/Sentinel-AI/mcp-server/'* ~/sentinel-mcp/"
    exit 1
fi

echo ""

# Check if container exists
if docker ps -a | grep -q sentinel-mcp-server; then
    echo "Container exists. Checking status..."
    
    # Check if running
    if docker ps | grep -q sentinel-mcp-server; then
        echo "✅ Container is already running"
    else
        echo "Starting existing container..."
        docker start sentinel-mcp-server
        sleep 2
        
        if docker ps | grep -q sentinel-mcp-server; then
            echo "✅ Container started successfully"
        else
            echo "❌ Container failed to start. Checking logs:"
            docker logs sentinel-mcp-server
            exit 1
        fi
    fi
else
    echo "Container doesn't exist. Building and starting..."
    
    # Build and run
    docker compose build
    docker compose up -d
    
    sleep 3
    
    if docker ps | grep -q sentinel-mcp-server; then
        echo "✅ Container built and started successfully"
    else
        echo "❌ Container failed to start. Checking logs:"
        docker logs sentinel-mcp-server 2>&1 || echo "No logs available"
        exit 1
    fi
fi

echo ""
echo "=========================================="
echo "Docker Status:"
echo "=========================================="
docker ps | grep sentinel-mcp-server

echo ""
echo "=========================================="
echo "✅ WSL Docker Setup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Update Claude Desktop config at:"
echo "   C:\\Users\\91916\\AppData\\Roaming\\Claude\\claude_desktop_config.json"
echo ""
echo "2. Use this configuration:"
echo '   {
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
   }'
echo ""
echo "3. Restart Claude Desktop completely"
echo ""
echo "Container logs: docker logs -f sentinel-mcp-server"
echo ""
