@echo off
cd /d "%~dp0"
if exist "venv\Scripts\pythonw.exe" (
    start "AgentShield" "venv\Scripts\pythonw.exe" "dashboard.py"
) else (
    python dashboard.py
    if errorlevel 1 pause
)
