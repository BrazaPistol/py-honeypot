"""Serviço falso de FTP — captura comandos USER/PASS e tentativas de upload."""

from __future__ import annotations

import socket

from honeypot.core.session import Session
from honeypot.core.server import register_service
from honeypot.services.base_service import BaseService


@register_service("ftp")
class FTPFake(BaseService):
    """Simula um servidor FTP que sempre rejeita credenciais."""

    name = "ftp"

    def handle(self, session: Session, sock: socket.socket) -> None:
        self.send(sock, b"220 FTP Server ready\r\n")

        username: str | None = None
        while True:
            line = self.recv_line(sock)
            if line is None:
                return
            session.add_command(line)

            parts = line.split(" ", 1)
            command = parts[0].upper()
            argument = parts[1] if len(parts) > 1 else ""

            if command == "USER":
                username = argument
                session.add_credential("username", username)
                self.send(sock, b"331 Password required\r\n")
            elif command == "PASS":
                session.add_credential("password", argument)
                self.send(sock, b"530 Login incorrect\r\n")
            elif command == "SYST":
                self.send(sock, b"215 UNIX Type: L8\r\n")
            elif command in ("QUIT", "BYE"):
                self.send(sock, b"221 Goodbye\r\n")
                return
            elif command in ("PASV", "EPSV"):
                self.send(sock, b"530 Please login with USER and PASS\r\n")
            else:
                # Qualquer outro comando antes do login (STOR, RETR, etc.)
                self.send(sock, b"530 Please login with USER and PASS\r\n")