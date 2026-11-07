@echo off
title AegisShield EDR & AdBlocker - Administrator Elevated Launcher
color 0C
echo =====================================================================
echo    AEGISSHIELD EDR & ADBLOCKER - ADMINISTRATOR PRIVILEGED LAUNCHER
echo =====================================================================
echo.
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [*] Elevation required to terminate system services and manage firewall rules.
    echo [*] Requesting Windows Administrator Approval...
    powershell -NoProfile -Command "Start-Process cmd -ArgumentList '/c cd /d ""%CD%"" && start_all.bat' -Verb RunAs"
    exit /b 0
)

call start_all.bat

