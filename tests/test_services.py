"""Testes do py-honeypot — validam config, sessão e fingerprinting.

São testes unitários puros (sem rede). Testes de integração com
conexões locais podem ser adicionados em tests/test_integration.py.
"""

from __future__ import annotations

import pytest

from honeypot.core.config import ConfigError, load_config, validate
from honeypot.core.session import Session
from honeypot.utils.fingerprint import (
    classify_http_path,
    classify_user_agent,
    fingerprint_session,
)


# ---------------------------------------------------------------- config

class TestConfigValidation:
    def test_config_padrao_e_valida(self):
        config = load_config()
        assert config["server"]["bind_address"] == "0.0.0.0"

    def test_rejeita_sem_chave_services(self):
        with pytest.raises(ConfigError):
            validate({"server": {}, "logging": {}})

    def test_rejeita_portas_duplicadas(self):
        config = {
            "server": {},
            "logging": {},
            "services": {
                "a": {"enabled": True, "port": 8080},
                "b": {"enabled": True, "port": 8080},
            },
        }
        with pytest.raises(ConfigError, match="duplicadas"):
            validate(config)

    def test_rejeita_nenhum_servico_habilitado(self):
        config = {
            "server": {},
            "logging": {},
            "services": {"telnet": {"enabled": False, "port": 2323}},
        }
        with pytest.raises(ConfigError, match="habilitado"):
            validate(config)


# --------------------------------------------------------------- sessão

class TestSession:
    def _session(self) -> Session:
        return Session(
            session_id="abc123",
            source_ip="192.168.1.50",
            source_port=54321,
            service="telnet",
        )

    def test_add_payload_registra_bytes(self):
        session = self._session()
        session.add_payload(b"admin\r\n")
        assert session.bytes_received == 7
        assert "admin" in " ".join(session.payloads)

    def test_add_credential(self):
        session = self._session()
        session.add_credential("username", "root")
        assert session.credentials["username"] == "root"

    def test_to_dict_contem_campos_essenciais(self):
        session = self._session()
        session.close()
        data = session.to_dict()
        for key in ("session_id", "source_ip", "service", "started_at", "ended_at"):
            assert key in data


# ---------------------------------------------------------- fingerprint

class TestFingerprint:
    def test_detecta_nmap(self):
        assert classify_user_agent("nmap scripting engine") == "nmap-script"

    def test_detecta_masscan(self):
        assert classify_user_agent("masscan/1.0") == "masscan"

    def test_user_agent_desconhecido(self):
        assert classify_user_agent("Mozilla/5.0") is None

    def test_path_de_scanner_web(self):
        assert classify_http_path("/wp-login.php") == "web-vuln-scanner"
        assert classify_http_path("/.env") == "web-vuln-scanner"

    def test_path_normal(self):
        assert classify_http_path("/index.html") is None

    def test_fingerprint_session_atualiza_atributo(self):
        session = Session("x", "10.0.0.1", 1111, "http")
        session.add_payload(b"GET /wp-admin HTTP/1.1\r\n")
        fingerprint_session(session)
        assert session.fingerprint == "web-vuln-scanner"