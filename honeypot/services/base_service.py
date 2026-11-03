"""Interface comum a todos os serviços falsos do honeypot.

Serviços herdam BaseService e implementam handle(). O envio de banner
é padronizado; o comportamento após o banner é específico de cada serviço.
"""

from __future__ import annotations

import socket
from abc import ABC, abstractmethod
from typing import Any

from honeypot.core.session import Session

RECV_BUFFER = 4096


class BaseService(ABC):
    """Classe base para um serviço falso (Telnet, FTP, HTTP, SSH...)."""

    name: str = "base"

    def __init__(self, config: dict[str, Any]):
        self.config = config

    @property
    def banner(self) -> bytes:
        """Banner enviado ao atacante ao conectar."""
        text = self.config.get("banner", "")
        return text.encode("utf-8")

    def send(self, sock: socket.socket, data: bytes) -> None:
        """Envia bytes ao atacante com tratamento básico de erro."""
        try:
            sock.sendall(data)
        except (BrokenPipeError, ConnectionResetError):
            raise ConnectionError("conexão encerrada pelo atacante")

    def recv(self, sock: socket.socket, size: int = RECV_BUFFER) -> bytes | None:
        """Recebe bytes do atacante; None se desconectou ou timeout."""
        try:
            data = sock.recv(size)
        except socket.timeout:
            return None
        if not data:
            return None
        return data

    def recv_line(self, sock: socket.socket, max_lines: int = 100) -> str | None:
        """Acumula bytes até \\n ou \\r\\n — típico de protocolos de linha.

        Retorna None quando a conexão encerra.
        """
        buf = b""
        for _ in range(max_lines):
            chunk = self.recv(sock, 1)
            if chunk is None:
                if buf:
                    return buf.decode("utf-8", errors="replace")
                return None
            if chunk in (b"\n",):
                line = buf.decode("utf-8", errors="replace")
                return line.rstrip("\r")
            buf += chunk
            if len(buf) > RECV_BUFFER:
                return buf.decode("utf-8", errors="replace")
        return buf.decode("utf-8", errors="replace")

    @abstractmethod
    def handle(self, session: Session, sock: socket.socket) -> None:
        """Lógica do serviço falso: interagir e registrar a sessão.

        Implementações devem:
        1. Enviar o banner;
        2. Ler dados e registrar via session.add_payload/add_command/add_credential;
        3. Nunca executar nada recebido do atacante (é um honeypot!).
        """
        raise NotImplementedError

    def start(self, session: Session, sock: socket.socket) -> None:
        """Fluxo padrão: envia banner e chama handle()."""
        if self.banner:
            self.send(sock, self.banner)
            session.banner_sent = self.config.get("banner")
        self.handle(session, sock)