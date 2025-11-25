@echo off
REM Installation script for Sentinel-AI MCP Server

echo ============================================
echo Sentinel-AI MCP Server Installation
echo ============================================
echo.

REM Check if venv exists
if not exist "venv\" (
    echo Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment
        pause
        exit /b 1
    )
    echo Virtual environment created successfully!
    echo.
)

echo Activating virtual environment...
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo ERROR: Failed to activate virtual environment
    pause
    exit /b 1
)

echo.
echo Installing dependencies...
pip install --upgrade pip
pip install -e .
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo ============================================
echo Installation complete!
echo ============================================
echo.
echo Next steps:
echo 1. Edit config.yaml with your OpenSearch credentials
echo 2. Follow CLAUDE_SETUP.md to configure Claude Desktop
echo 3. Restart Claude Desktop
echo.
echo To test manually, run:
echo   venv\Scripts\activate
echo   python -m sentinel_mcp.server --config config.yaml
echo.
pause
