"""Servidor principal: escuta portas configuradas e despacha conexões.

Cada serviço habilitado roda em sua própria thread. Cada conexão
de atacante recebe uma thread dedicada com timeout configurável.
"""

from __future__ import annotations

import socket
import socketserver
import threading
import uuid
from typing import Any

from honeypot.core.config import load_config
from honeypot.core.logger import get_logger, utc_now
from honeypot.core.session import Session

log = get_logger()

# Registro de serviços — preenchido por register_service()
_SERVICE_REGISTRY: dict[str, type] = {}


def register_service(name: str):
    """Decorator que registra uma classe de serviço falso.

    Uso:
        @register_service("telnet")
        class TelnetFake(BaseService): ...
    """
    def decorator(cls):
        _SERVICE_REGISTRY[name] = cls
        return cls
    return decorator


def _build_session(service_name: str, client_address: tuple[str, int]) -> Session:
    return Session(
        session_id=uuid.uuid4().hex[:12],
        source_ip=client_address[0],
        source_port=client_address[1],
        service=service_name,
    )


class HoneypotHandler(socketserver.BaseRequestHandler):
    """Handler por conexão: cria a Session e delega ao serviço falso."""

    service_name: str = ""
    service_config: dict[str, Any] = {}
    session_timeout: int = 60
    active_sessions: dict[str, Session] = {}

    def setup(self) -> None:
        self.request.settimeout(self.session_timeout)
        self.session = _build_session(self.service_name, self.client_address)
        HoneypotHandler.active_sessions[self.session.session_id] = self.session

    def handle(self) -> None:
        svc_cls = _SERVICE_REGISTRY.get(self.service_name)
        if svc_cls is None:
            log.error("Serviço não registrado: %s", self.service_name,
                      extra={"honeypot_data": {"service": self.service_name}})
            return

        service = svc_cls(self.service_config)
        try:
            service.handle(self.session, self.request)
        except socket.timeout:
            log.info("Sessão encerrada por timeout",
                     extra={"honeypot_data": {"session": self.session.to_dict()}})
        except ConnectionError:
            log.info("Atacante desconectou",
                     extra={"honeypot_data": {"session": self.session.to_dict()}})
        except Exception:  # noqa: BLE001 — nunca derrubar o honeypot
            log.exception("Erro inesperado no serviço %s", self.service_name,
                          extra={"honeypot_data": {"session": self.session.to_dict()}})
        finally:
            self.session.close()
            log.info("Sessão registrada: %s", self.session.session_id,
                     extra={"honeypot_data": {"session": self.session.to_dict()}})

    def finish(self) -> None:
        HoneypotHandler.active_sessions.pop(self.session.session_id, None)


class HoneypotServer(socketserver.ThreadingTCPServer):
    """TCP server multi-thread com allow_reuse_address e daemon threads."""
    allow_reuse_address = True
    daemon_threads = True


def run(config_path=None) -> None:
    """Ponto de entrada: carrega config e sobe todos os serviços habilitados."""
    config = load_config(config_path)
    timeout = int(config["server"].get("session_timeout", 60))
    bind = config["server"].get("bind_address", "0.0.0.0")

    servers: list[HoneypotServer] = []
    for name, svc_config in config["services"].items():
        if not svc_config.get("enabled", False):
            log.info("Serviço desativado: %s", name)
            continue
        if name not in _SERVICE_REGISTRY:
            log.warning("Serviço habilitado mas sem implementação: %s", name)
            continue

        handler = type(f"Handler_{name}", (HoneypotHandler,), {
            "service_name": name,
            "service_config": svc_config,
            "session_timeout": timeout,
        })

        port = int(svc_config["port"])
        server = HoneypotServer((bind, port), handler)
        servers.append(server)

        thread = threading.Thread(target=server.serve_forever, daemon=True,
                                  name=f"honeypot-{name}")
        thread.start()
        log.info("Serviço '%s' escutando em %s:%s", name, bind, port,
                 extra={"honeypot_data": {"started": utc_now(), "service": name}})

    log.info("py-honeypot iniciado com %d serviço(s). Ctrl+C para encerrar.", len(servers))
    try:
        threading.Event().wait()  # mantém a thread principal viva
    except KeyboardInterrupt:
        log.info("Encerrando honeypot...")
        for srv in servers:
            srv.shutdown()


if __name__ == "__main__":
    run()