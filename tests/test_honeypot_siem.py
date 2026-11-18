"""Testes unitários do MVP honeypot-siem; sem acesso à rede."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from honeypot_siem.cli import main
from honeypot_siem.reader import read_credential_attempts
from honeypot_siem.rules import detect_credential_burst


def _log_line(timestamps: list[str], password: str = "do-not-leak") -> str:
    return json.dumps({
        "timestamp": timestamps[-1] if timestamps else "2026-01-01T00:00:00+00:00",
        "level": "INFO",
        "logger": "honeypot",
        "message": "Sessão registrada",
        "data": {
            "session": {
                "source_ip": "203.0.113.7",
                "events": [
                    {
                        "timestamp": timestamp,
                        "kind": "credential",
                        "data": {"type": "password", "value": password},
                    }
                    for timestamp in timestamps
                ],
            }
        },
    })


def test_reader_extracts_metadata_without_credential_values():
    raw = _log_line(["2026-01-01T00:00:00Z"])
    attempts, malformed = read_credential_attempts(iter([raw + "\n"]))

    assert malformed == 0
    assert len(attempts) == 1
    assert attempts[0].source_ip == "203.0.113.7"
    assert "do-not-leak" not in repr(attempts)


def test_reader_skips_malformed_json_and_keeps_processing():
    valid = _log_line(["2026-01-01T00:00:00Z"])
    attempts, malformed = read_credential_attempts(iter(["{invalid json}\n", valid + "\n"]))

    assert malformed == 1
    assert len(attempts) == 1


def test_rule_alerts_at_five_attempts_inside_ten_minutes():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    attempts = [
        type("Attempt", (), {"source_ip": "203.0.113.7", "timestamp": start + timedelta(minutes=i)})()
        for i in range(5)
    ]

    alerts = detect_credential_burst(attempts)

    assert len(alerts) == 1
    assert alerts[0].rule == "credential_burst"
    assert alerts[0].source_ip == "203.0.113.7"
    assert alerts[0].attempts == 5
    assert "password" not in repr(alerts)


def test_rule_does_not_alert_when_attempts_are_outside_window():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    attempts = [
        type("Attempt", (), {"source_ip": "203.0.113.7", "timestamp": start + timedelta(minutes=i * 11)})()
        for i in range(5)
    ]

    assert detect_credential_burst(attempts) == []


def test_rule_rejects_non_positive_threshold_or_window():
    try:
        detect_credential_burst([], threshold=0)
    except ValueError:
        pass
    else:
        raise AssertionError("threshold zero deve ser rejeitado")

    try:
        detect_credential_burst([], window_minutes=0)
    except ValueError:
        pass
    else:
        raise AssertionError("janela zero deve ser rejeitada")


def test_cli_outputs_alerts_without_secret_values(tmp_path, capsys):
    timestamps = [
        (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=i)).isoformat()
        for i in range(5)
    ]
    log_path = tmp_path / "sessions.jsonl"
    log_path.write_text(_log_line(timestamps) + "\n", encoding="utf-8")

    assert main([str(log_path)]) == 0
    output = capsys.readouterr().out
    decoded = json.loads(output)
    assert decoded["alerts"][0]["attempts"] == 5
    assert "do-not-leak" not in output
    assert "password" not in output
