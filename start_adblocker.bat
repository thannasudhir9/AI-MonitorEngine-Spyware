@echo off
title AegisShield - Network AdBlocker & Traffic Inspector Proxy
color 0D
echo =====================================================================
echo    AEGISSHIELD - SYSTEM-WIDE NETWORK ADBLOCKER & WEB PROXY (:8080)
echo =====================================================================
echo.
echo [*] Starting AegisShield AdBlock Proxy Server on 127.0.0.1:8080 ...
echo [*] Press Ctrl+C in this window to stop the proxy.
echo.
python -c "from backend.adblock_proxy import AdBlockProxyServer; import time; p = AdBlockProxyServer(host='127.0.0.1', port=8080); p.start(); print('[✓] AegisShield Proxy running on 127.0.0.1:8080. Press Ctrl+C to exit.'); [time.sleep(1) for _ in iter(int, 1)]"
pause

