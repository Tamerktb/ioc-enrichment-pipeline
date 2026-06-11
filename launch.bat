@echo off
title IOC Enrichment Pipeline
cd /d "%~dp0"

echo.
echo  ╔══════════════════════════════════════════╗
echo  ║      IOC Enrichment Pipeline             ║
echo  ║      Threat Intelligence Lookup          ║
echo  ╚══════════════════════════════════════════╝
echo.

:: Check Python
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
    pip install requests rich pyyaml python-dotenv pydantic streamlit --quiet
)

echo  [2/3] Checking API keys...
if exist ".env" (
    echo         .env file found
) else (
    if exist ".env.example" (
        echo         No .env file — copy .env.example to .env and add API keys for full enrichment
    )
)

echo  [3/3] Starting server...
echo.
echo  Open:  http://localhost:8501
echo  Exit:  Press Ctrl+C in this window
echo.
echo  ═══════════════════════════════════════════
echo.

:: Open browser after a short delay
timeout /t 2 /nobreak >nul
start "" http://localhost:8501

:: Launch Streamlit
streamlit run app.py --server.headless true --server.port 8501

:: If streamlit fails
if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] Failed to start. Try running manually:
    echo       pip install streamlit
    echo       streamlit run app.py
    echo.
)

pause
