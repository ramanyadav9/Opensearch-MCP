@echo off
echo ========================================
echo Sentinel-AI MCP Server - Docker Setup
echo ========================================
echo.

REM Check if Docker is running
docker ps >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not running!
    echo Please start Docker Desktop and try again.
    pause
    exit /b 1
)

echo [1/4] Checking config.yaml...
if not exist "config.yaml" (
    echo Config file not found. Copying from example...
    copy config.yaml.example config.yaml
    echo.
    echo [!] Please edit config.yaml with your OpenSearch credentials
    echo     Location: %CD%\config.yaml
    echo.
    pause
)

echo [2/4] Building Docker image...
docker-compose build
if errorlevel 1 (
    echo [ERROR] Failed to build Docker image!
    pause
    exit /b 1
)

echo [3/4] Starting MCP server container...
docker-compose up -d
if errorlevel 1 (
    echo [ERROR] Failed to start container!
    pause
    exit /b 1
)

echo [4/4] Verifying container status...
timeout /t 3 /nobreak >nul
docker ps | findstr sentinel-mcp-server
if errorlevel 1 (
    echo [ERROR] Container is not running!
    echo Checking logs...
    docker logs sentinel-mcp-server
    pause
    exit /b 1
)

echo.
echo ========================================
echo SUCCESS! MCP Server is running
echo ========================================
echo.
echo Next steps:
echo 1. Configure Claude Desktop:
echo    - Edit: %%APPDATA%%\Claude\claude_desktop_config.json
echo    - See DOCKER_SETUP.md for configuration
echo.
echo 2. Or configure CLI Claude (VS Code):
echo    - Edit: %%APPDATA%%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json
echo    - See DOCKER_SETUP.md for configuration
echo.
echo 3. Restart Claude Desktop or VS Code
echo.
echo Useful commands:
echo   - View logs:    docker logs -f sentinel-mcp-server
echo   - Stop server:  docker-compose down
echo   - Restart:      docker-compose restart
echo.
pause
