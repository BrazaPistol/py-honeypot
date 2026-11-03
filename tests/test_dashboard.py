"""Tests for the informational pages and dashboard endpoints."""

from __future__ import annotations

import json

from dashboard import app as dashboard_module


def test_dashboard_and_informational_pages_render():
    client = dashboard_module.create_app().test_client()

    responses = {
        "/": "Atividade observada",
        "/como-funciona": "Como funciona",
        "/servicos": "Serviços simulados",
        "/dados-e-seguranca": "Dados e segurança",
    }
    for path, expected_text in responses.items():
        response = client.get(path)
        assert response.status_code == 200
        assert expected_text.encode() in response.data


def test_informational_pages_explain_local_scope():
    client = dashboard_module.create_app().test_client()

    response = client.get("/como-funciona")

    assert "não pesquisa dispositivos".encode() in response.data.lower()
    assert "nem é afiliada ao shodan".encode() in response.data.lower()


def test_stats_api_summarizes_local_sessions(monkeypatch, tmp_path):
    log_file = tmp_path / "sessions.jsonl"
    records = [
        {"data": {"session": {"service": "http", "source_ip": "192.0.2.1"}}},
        {"data": {"session": {"service": "http", "source_ip": "192.0.2.1"}}},
        {"data": {"session": {"service": "ftp", "source_ip": "192.0.2.2"}}},
    ]
    log_file.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )
    monkeypatch.setattr(dashboard_module, "LOG_FILE", log_file)

    response = dashboard_module.create_app().test_client().get("/api/stats")

    assert response.status_code == 200
    assert response.get_json() == {
        "total_sessions": 3,
        "unique_ips": 2,
        "top_service": "http",
        "by_service": {"labels": ["http", "ftp"], "values": [2, 1]},
    }
