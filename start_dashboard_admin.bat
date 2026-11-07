@echo off
title AegisShield EDR Dashboard (ADMINISTRATOR)
color 0C
echo =====================================================================
echo    AEGISSHIELD EDR DASHBOARD - ADMINISTRATOR PRIVILEGED LAUNCHER
echo =====================================================================
echo.
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [*] Elevation required to terminate SYSTEM services and protected processes.
    echo [*] Requesting Windows Administrator UAC Approval...
    powershell -NoProfile -Command "Start-Process cmd -ArgumentList '/k cd /d ""%CD%"" && python run_server.py' -Verb RunAs"
    exit /b 0
)

echo [*] Running with verified Windows Administrator privileges!
python run_server.py
pause
