"""Serviço falso de Telnet — captura tentativas de login e comandos.

Fluxo simulado:
    Login: <usuario>
    Password: <senha>
    -> falha "Login incorrect" e permite nova tentativa (até 3).
"""

from __future__ import annotations

import socket

from honeypot.core.session import Session
from honeypot.core.server import register_service
from honeypot.services.base_service import BaseService

MAX_LOGIN_ATTEMPTS = 3


@register_service("telnet")
class TelnetFake(BaseService):
    """Simula um Telnet de roteador/equipamento legado."""

    name = "telnet"

    def handle(self, session: Session, sock: socket.socket) -> None:
        for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
            # Login
            self.send(sock, b"Login: ")
            user = self.recv_line(sock)
            if user is None:
                return
            session.add_command(f"Login: {user}")
            session.add_credential("username", user)

            # Senha (eco desativado em Telnet real — aqui apenas lemos)
            self.send(sock, b"Password: ")
            password = self.recv_line(sock)
            if password is None:
                return
            session.add_credential("password", password)

            # Sempre falha — objetivo é manter o atacante digitando
            self.send(sock, b"Login incorrect\r\n\r\n")
            session.add_event("login_failed", {"attempt": attempt})

        # Após 3 tentativas, derruba (comportamento de daemon realista)
        self.send(sock, b"Too many attempts. Connection closed.\r\n")