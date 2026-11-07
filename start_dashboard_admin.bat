@echo off
title AegisShield EDR - Administrator Elevated Launcher
color 0C
echo =====================================================================
echo    AEGISSHIELD EDR - ADMINISTRATOR PRIVILEGED LAUNCHER
echo =====================================================================
echo.
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [*] Elevation required to terminate system services and protected processes.
    echo [*] Requesting Windows Administrator Approval...
    powershell -NoProfile -Command "Start-Process cmd -ArgumentList '/c cd /d ""%CD%"" && start_dashboard.bat' -Verb RunAs"
    exit /b 0
)

call start_dashboard.bat

