"""Leitura segura de eventos JSONL do py-honeypot.

Só extraímos IP, timestamp e tipo de evento; valores de credenciais nunca
são retornados nem incluídos em mensagens de erro.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO


@dataclass(frozen=True)
class CredentialAttempt:
    """Metadados mínimos de uma tentativa, sem usuário ou senha."""

    source_ip: str
    timestamp: datetime


def _as_utc(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _extract_attempts(record: object) -> list[CredentialAttempt]:
    if not isinstance(record, dict):
        return []
    data = record.get("data")
    session = data.get("session") if isinstance(data, dict) else None
    if not isinstance(session, dict):
        return []
    source_ip = session.get("source_ip")
    events = session.get("events")
    if not isinstance(source_ip, str) or not source_ip or not isinstance(events, list):
        return []

    attempts: list[CredentialAttempt] = []
    for event in events:
        if not isinstance(event, dict) or event.get("kind") != "credential":
            continue
        timestamp = _as_utc(event.get("timestamp"))
        if timestamp is not None:
            attempts.append(CredentialAttempt(source_ip=source_ip, timestamp=timestamp))
    return attempts


def read_credential_attempts(stream: TextIO) -> tuple[list[CredentialAttempt], int]:
    """Lê JSONL e retorna tentativas e quantidade de linhas JSON inválidas."""
    attempts: list[CredentialAttempt] = []
    malformed_lines = 0
    for line in stream:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, UnicodeError):
            malformed_lines += 1
            continue
        attempts.extend(_extract_attempts(record))
    return attempts, malformed_lines


def read_log_file(path: str | Path) -> tuple[list[CredentialAttempt], int]:
    """Lê um arquivo JSONL UTF-8 sem carregar valores de credenciais."""
    with Path(path).open("r", encoding="utf-8", errors="replace") as stream:
        return read_credential_attempts(stream)
