@echo off
title AegisShield - Threat Hunter & Process Monitor
color 0B
echo =====================================================================
echo       AEGISSHIELD - CYBER PROCESS MONITOR & THREAT ERADICATOR
echo =====================================================================
echo.
echo [*] Checking Python environment...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH!
    echo Please install Python 3.9+ and try again.
    pause
    exit /b 1
)

echo [*] Starting AegisShield EDR Backend Server on http://127.0.0.1:8888 ...
python run_server.py

pause

