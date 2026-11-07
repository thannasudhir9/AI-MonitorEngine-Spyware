"""
AegisShield - Server Launcher Script
Starts the FastAPI application and opens the Cyber SOC Dashboard in the browser.
"""

import sys
import time
import webbrowser
import threading
import uvicorn
from backend.config import SERVER_HOST, SERVER_PORT


def open_browser():
    """Wait for server startup and launch dashboard in user's browser."""
    time.sleep(1.2)
    url = f"http://{SERVER_HOST}:{SERVER_PORT}"
    print(f"\n[✓] Launching AegisShield Dashboard: {url}")
    try:
        webbrowser.open(url)
    except Exception:
        pass


def main():
    print("""
    ===============================================================
       AEGISSHIELD - CYBER PROCESS MONITOR & THREAT ERADICATOR
    ===============================================================
    [*] Dashboard Web UI: http://127.0.0.1:8888
    [*] API Docs:         http://127.0.0.1:8888/docs
    [*] Press Ctrl+C to stop the monitoring server.
    ===============================================================
    """)

    # Open browser automatically in a background thread
    threading.Thread(target=open_browser, daemon=True).start()

    # Start Uvicorn ASGI server
    uvicorn.run(
        "backend.server:app",
        host=SERVER_HOST,
        port=SERVER_PORT,
        log_level="info",
        reload=False
    )


if __name__ == "__main__":
    main()

