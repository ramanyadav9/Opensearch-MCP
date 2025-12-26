@echo off
echo ======================================
echo Testing Sentinel-AI MCP Server
echo ======================================
echo.

echo [1/2] Testing OpenSearch Connection...
curl -u admin:admin http://192.168.1.12:9200 > nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo    SUCCESS: OpenSearch is accessible
) else (
    echo    ERROR: Cannot connect to OpenSearch
    exit /b 1
)

echo.
echo [2/2] Testing MCP Server Startup...
echo Press Ctrl+C to stop after you see "Connected to OpenSearch" or tools listed
echo.

"E:\CyberSentinal All\Sentinel-AI\mcp-server\venv\Scripts\python.exe" -m sentinel_mcp.server --config "E:\CyberSentinal All\Sentinel-AI\mcp-server\config.yaml"
