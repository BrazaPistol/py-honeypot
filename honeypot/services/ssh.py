"""Serviço falso de SSH — placeholder (desativado por padrão).

O protocolo SSH exige troca de chaves e criptografia real. Um banner
grabber simples registra a versão do cliente do atacante, mas implementar
um handshake completo requer bibliotecas específicas (ex: paramiko).

TODO (roadmap):
- Capturar o banner do cliente SSH (SSH-2.0-...)
- Implementar falha lenta de autenticação via paramiko
- Registrar algoritmos oferecidos pelo atacante
"""

from __future__ import annotations

import socket

from honeypot.core.session import Session
from honeypot.core.server import register_service
from honeypot.services.base_service import BaseService


@register_service("ssh")
class SSHFake(BaseService):
    """Simula apenas o banner SSH — sem handshake (baixa interação)."""

    name = "ssh"

    def handle(self, session: Session, sock: socket.socket) -> None:
        # Envia o banner do "servidor"
        self.send(sock, self.banner + b"\r\n")

        # Lê e registra o banner do cliente (ex: SSH-2.0-libssh_0.9.6)
        client_banner = self.recv_line(sock)
        if client_banner:
            session.add_command(client_banner)
            session.add_event("client_banner", {"value": client_banner})

        # Deliberadamente não responde ao handshake — conexão morre,
        # mas o banner do cliente já foi capturado (tática de banner grab).
        self.send(sock, b"Protocol mismatch.\r\n")