@echo off
title IOC Enrichment Pipeline
cd /d "%~dp0"

echo.
echo  ============================================
echo   IOC Enrichment Pipeline
echo   Threat Intelligence Lookup
echo  ============================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Python is not installed.
    echo.
    echo  Download it from: https://www.python.org/downloads/
    echo  Make sure to check "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)

echo  [1/3] Installing dependencies...
pip install -r requirements.txt streamlit --quiet 2>nul
if %errorlevel% neq 0 (
    echo  [WARNING] Some packages may have failed. Trying again...
    pip install requests rich pyyaml python-dotenv pydantic streamlit --quiet
)

echo  [2/3] Starting server...
echo.
echo  The web interface will open at:
echo.
echo       http://localhost:8501
echo.
echo  Keep this window open while using the tool.
echo  Press Ctrl+C to stop.
echo.
echo  ============================================

:: Wait a moment for the server to start, then open browser
start "" http://localhost:8501

:: Launch Streamlit
streamlit run app.py --server.headless true --server.port 8501 --browser.serverAddress localhost 2>nul

:: If streamlit fails, show error
if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] Failed to start. Try running manually:
    echo       pip install streamlit
    echo       streamlit run app.py
    echo.
)

pause
