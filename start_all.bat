@echo off
title AegisShield EDR & Network AdBlocker Suite
color 0A
echo =====================================================================
echo    AEGISSHIELD EDR & NETWORK ADBLOCKER - DUAL-ENGINE LAUNCHER
echo =====================================================================
echo.
echo [*] Launching AdBlock Intercepting Proxy (:8080) in background window...
start "AegisShield AdBlock Proxy (:8080)" cmd /c "start_adblocker.bat"

timeout /t 2 /nobreak >nul

echo [*] Launching AegisShield EDR Cyber Dashboard (:8888)...
start "AegisShield EDR Dashboard (:8888)" cmd /c "start_dashboard.bat"

echo.
echo [✓] Both AegisShield subsystems are launching!
echo     - EDR Cyber Dashboard: http://127.0.0.1:8888
echo     - AdBlock Proxy:       127.0.0.1:8080
echo.

