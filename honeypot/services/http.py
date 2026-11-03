"""Serviço falso de HTTP — registra requests completos e payloads de ataque.

Responde sempre com uma página simples imitando um painel admin.
Captura: método, caminho, headers (User-Agent, etc.) e corpo (POST).
"""

from __future__ import annotations

import socket
from typing import Any

from honeypot.core.session import Session
from honeypot.core.server import register_service
from honeypot.services.base_service import BaseService

FAKE_PAGE = (
    "<html><head><title>Router Admin</title></head>"
    "<body><h1>Router Management Interface</h1>"
    "<p>Login required.</p></body></html>"
)

MAX_REQUEST_SIZE = 65536  # 64 KB


@register_service("http")
class HTTPFake(BaseService):
    """Simula um servidor HTTP simples com página admin falsa."""

    name = "http"

    def handle(self, session: Session, sock: socket.socket) -> None:
        raw = b""
        while b"\r\n\r\n" not in raw and len(raw) < MAX_REQUEST_SIZE:
            chunk = self.recv(sock)
            if chunk is None:
                return
            raw += chunk
            session.add_payload(chunk)

        request_text = raw.decode("utf-8", errors="replace")
        head, _, body = request_text.partition("\r\n\r\n")
        lines = head.split("\r\n")

        method, path, _protocol = (lines[0].split(" ", 2) + ["", ""])[:3] if lines else ("", "", "")
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ": " in line:
                key, value = line.split(": ", 1)
                headers[key] = value

        session.add_event("http_request", {
            "method": method,
            "path": path,
            "headers": headers,
            "body": body[:2048],  # trunca corpos enormes no log
        })

        if "Content-Length" in headers and body and len(body) < int(headers["Content-Length"] or 0):
            # Continua lendo o corpo declarado (payloads de ataque comuns)
            remaining = int(headers["Content-Length"]) - len(body)
            while remaining > 0:
                chunk = self.recv(sock, min(remaining, 8192))
                if chunk is None:
                    break
                session.add_payload(chunk)
                remaining -= len(chunk)

        response = (
            "HTTP/1.1 200 OK\r\n"
            f"Server: {self.config.get('banner', 'Apache')}\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            f"Content-Length: {len(FAKE_PAGE)}\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{FAKE_PAGE}"
        )
        self.send(sock, response.encode("utf-8"))