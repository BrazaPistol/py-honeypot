"""Regras de deteção iniciais para o mini-SIEM."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import timedelta

from honeypot_siem.reader import CredentialAttempt


@dataclass(frozen=True)
class Alert:
    rule: str
    source_ip: str
    attempts: int
    window_minutes: int
    first_seen: str
    last_seen: str


def detect_credential_burst(
    attempts: list[CredentialAttempt],
    threshold: int = 5,
    window_minutes: int = 10,
) -> list[Alert]:
    """Gera no máximo um alerta por IP se atingir o limite na janela móvel."""
    if threshold < 1:
        raise ValueError("threshold deve ser maior que zero")
    if window_minutes < 1:
        raise ValueError("window_minutes deve ser maior que zero")

    by_ip: dict[str, list] = defaultdict(list)
    for attempt in attempts:
        by_ip[attempt.source_ip].append(attempt.timestamp)

    alerts: list[Alert] = []
    window = timedelta(minutes=window_minutes)
    for source_ip in sorted(by_ip):
        timestamps = sorted(by_ip[source_ip])
        left = 0
        best_start = best_end = 0
        best_count = 0
        for right, current in enumerate(timestamps):
            while current - timestamps[left] > window:
                left += 1
            count = right - left + 1
            if count > best_count:
                best_count = count
                best_start, best_end = left, right
        if best_count >= threshold:
            alerts.append(Alert(
                rule="credential_burst",
                source_ip=source_ip,
                attempts=best_count,
                window_minutes=window_minutes,
                first_seen=timestamps[best_start].isoformat(),
                last_seen=timestamps[best_end].isoformat(),
            ))
    return alerts


def alert_to_dict(alert: Alert) -> dict[str, object]:
    """Serialização explícita do alerta, sem dados de credenciais."""
    return asdict(alert)
