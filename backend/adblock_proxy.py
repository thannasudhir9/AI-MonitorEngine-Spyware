"""
AegisShield - Intercepting Ad Blocker & Web Traffic Proxy
Multi-threaded HTTP & HTTPS CONNECT proxy running on 127.0.0.1:8080.
Intercepts all browser web traffic, blocks ads/trackers, and logs browsing history.
"""

import socket
import select
import threading
from typing import Optional

from .adblock_rules import check_domain_reputation
from .web_traffic_logger import WebTrafficLogger


class AdBlockProxyServer:
    """Multi-threaded HTTP/HTTPS Ad-Blocking Proxy Server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.logger = WebTrafficLogger()
        self._running = False
        self._server_socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None

    def is_running(self) -> bool:
        """Check if proxy server is active."""
        return self._running

    def start(self):
        """Start proxy server in background thread."""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop proxy server and close listening socket."""
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
            self._server_socket = None

    def _run(self):
        """Main listening loop."""
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind((self.host, self.port))
            self._server_socket.listen(128)
            print(f"[✓] AegisShield AdBlock Proxy active on {self.host}:{self.port}")

            while self._running:
                try:
                    self._server_socket.settimeout(1.5)
                    client_socket, client_addr = self._server_socket.accept()
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_addr[0]),
                        daemon=True
                    )
                    client_thread.start()
                except socket.timeout:
                    continue
                except OSError:
                    break
        except Exception as e:
            print(f"AdBlock Proxy startup notice: {e}")
        finally:
            self._running = False

    def _handle_client(self, client_socket: socket.socket, client_ip: str):
        """Process incoming client HTTP/HTTPS request."""
        try:
            client_socket.settimeout(6.0)
            request_data = client_socket.recv(8192)
            if not request_data:
                client_socket.close()
                return

            request_line = request_data.decode("utf-8", errors="ignore").splitlines()[0]
            parts = request_line.split()
            if len(parts) < 2:
                client_socket.close()
                return

            method, target = parts[0], parts[1]

            # Parse domain and port
            if method.upper() == "CONNECT":
                # HTTPS Tunnel: target is "host:port", e.g. "ad.doubleclick.net:443"
                if ":" in target:
                    target_host, target_port = target.split(":")
                    target_port = int(target_port)
                else:
                    target_host = target
                    target_port = 443
            else:
                # Standard HTTP request (e.g. "http://example.com/path")
                target_port = 80
                target_host = target
                if "://" in target:
                    target_host = target.split("://")[1].split("/")[0]
                if ":" in target_host:
                    target_host, p_str = target_host.split(":")
                    target_port = int(p_str)

            # Evaluate ad/tracker reputation
            is_blocked, category, reason = check_domain_reputation(target_host)

            # Record in Web Traffic Log
            self.logger.log_request(
                domain=target_host,
                method=method,
                port=target_port,
                is_blocked=is_blocked,
                category=category,
                reason=reason,
                bytes_transferred=0,
                client_ip=client_ip
            )

            # Handle Action
            if is_blocked:
                # Return HTTP 403 Forbidden block page
                block_body = (
                    f"<html><head><title>AegisShield - Blocked</title></head>"
                    f"<body style='font-family:sans-serif;background:#080c14;color:#f8fafc;padding:40px;text-align:center;'>"
                    f"<h2 style='color:#ef4444;'>🛡️ Advertisement / Tracker Blocked by AegisShield</h2>"
                    f"<p style='color:#94a3b8;'>Domain: <b style='color:#ffffff;'>{target_host}</b></p>"
                    f"<p style='color:#f59e0b;'>Category: {category}</p>"
                    f"<p style='color:#64748b;font-size:12px;'>Reason: {reason}</p>"
                    f"</body></html>"
                )
                response = (
                    f"HTTP/1.1 403 Forbidden\r\n"
                    f"Content-Type: text/html\r\n"
                    f"Content-Length: {len(block_body)}\r\n"
                    f"Connection: close\r\n\r\n"
                    f"{block_body}"
                )
                try:
                    client_socket.sendall(response.encode("utf-8"))
                except Exception:
                    pass
                client_socket.close()
                return

            # If Allowed: Establish Tunnel
            if method.upper() == "CONNECT":
                self._tunnel_https(client_socket, target_host, target_port)
            else:
                self._forward_http(client_socket, target_host, target_port, request_data)

        except Exception:
            try:
                client_socket.close()
            except Exception:
                pass

    def _tunnel_https(self, client_socket: socket.socket, host: str, port: int):
        """Establish bi-directional TCP tunnel for HTTPS CONNECT requests."""
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            remote_socket.settimeout(6.0)
            remote_socket.connect((host, port))

            # Send 200 Connection Established to client
            client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            # Relay data bi-directionally
            self._stream_sockets(client_socket, remote_socket)
        except Exception:
            try:
                client_socket.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except Exception:
                pass
        finally:
            try:
                client_socket.close()
            except Exception:
                pass
            try:
                remote_socket.close()
            except Exception:
                pass

    def _forward_http(self, client_socket: socket.socket, host: str, port: int, initial_data: bytes):
        """Forward standard HTTP request to destination server."""
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            remote_socket.settimeout(6.0)
            remote_socket.connect((host, port))
            remote_socket.sendall(initial_data)
            self._stream_sockets(client_socket, remote_socket)
        except Exception:
            try:
                client_socket.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except Exception:
                pass
        finally:
            try:
                client_socket.close()
            except Exception:
                pass
            try:
                remote_socket.close()
            except Exception:
                pass

    def _stream_sockets(self, s1: socket.socket, s2: socket.socket):
        """Bidirectional streaming between two sockets with select()."""
        sockets = [s1, s2]
        s1.setblocking(False)
        s2.setblocking(False)

        idle_cycles = 0
        while idle_cycles < 80:  # Timeout after ~8 seconds of inactivity
            readable, _, exceptional = select.select(sockets, [], sockets, 0.1)
            if exceptional:
                break
            if not readable:
                idle_cycles += 1
                continue

            idle_cycles = 0
            for s in readable:
                other = s2 if s is s1 else s1
                try:
                    data = s.recv(16384)
                    if not data:
                        return
                    other.sendall(data)
                except (BlockingIOError, ssl.SSLError if 'ssl' in globals() else OSError):
                    pass
                except Exception:
                    return

