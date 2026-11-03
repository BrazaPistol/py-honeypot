"""Representa uma sessão de atacante: estado, eventos e serialização."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from honeypot.core.logger import utc_now


@dataclass
class Session:
    """Estado de uma conexão de atacante ao honeypot."""

    session_id: str
    source_ip: str
    source_port: int
    service: str
    started_at: str = field(default_factory=utc_now)
    ended_at: str | None = None
    banner_sent: str | None = None
    commands: list[str] = field(default_factory=list)
    payloads: list[str] = field(default_factory=list)
    credentials: dict[str, str] = field(default_factory=dict)
    bytes_received: int = 0
    fingerprint: str | None = None
    geo: dict[str, Any] = field(default_factory=dict)

    _t_start: float = field(default_factory=time.monotonic, repr=False)
    _events: list[dict[str, Any]] = field(default_factory=list, repr=False)

    def add_event(self, kind: str, data: dict[str, Any] | None = None) -> None:
        """Registra um evento de sessão (comando, payload, login...)."""
        event = {"timestamp": utc_now(), "kind": kind, "data": data or {}}
        self._events.append(event)

    def add_payload(self, raw: bytes) -> None:
        """Registra bytes brutos recebidos do atacante."""
        self.bytes_received += len(raw)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1", errors="replace")
        self.payloads.append(text)
        self.add_event("payload", {"size": len(raw), "text": text})

    def add_command(self, command: str) -> None:
        """Registra um comando interpretado (ex: linha digitada no Telnet)."""
        self.commands.append(command)
        self.add_event("command", {"value": command})

    def add_credential(self, kind: str, value: str) -> None:
        """Registra credencial enviada pelo atacante (user/pass)."""
        self.credentials[kind] = value
        self.add_event("credential", {"type": kind, "value": value})

    def close(self) -> None:
        """Finaliza a sessão — timestamp de término e duração."""
        self.ended_at = utc_now()

    def to_dict(self) -> dict[str, Any]:
        """Serialização para o log JSON / dashboard."""
        return {
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "service": self.service,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_seconds": round(time.monotonic() - self._t_start, 3),
            "banner_sent": self.banner_sent,
            "commands": self.commands,
            "payloads": self.payloads,
            "credentials": self.credentials,
            "bytes_received": self.bytes_received,
            "fingerprint": self.fingerprint,
            "geo": self.geo,
            "events": self._events,
        }