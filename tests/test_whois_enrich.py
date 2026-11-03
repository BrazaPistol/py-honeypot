"""Testes do enriquecimento whois/RDAP.

Sem rede: usamos IPs privados (resolvidos localmente) e mockamos o
urlopen para o caso de IP público — os testes ficam rápidos e
determinísticos, sem depender do rdap.org estar online.
"""

from __future__ import annotations

import json
from unittest import mock

from honeypot.utils import whois_enrich


class TestLookupPrivateIP:
    """IPs de laboratório não consultam rede nenhuma."""

    def test_loopback_e_marcado_como_privado(self):
        result = whois_enrich.lookup_ip("127.0.0.1")
        assert result["scope"] == "private"
        assert "note" in result

    def test_ip_invalido_tratado_como_privado(self):
        # nunca deve levantar exceção
        result = whois_enrich.lookup_ip("não-é-um-ip")
        assert result["scope"] == "private"

    def test_cache_evita_reconsulta(self):
        whois_enrich._CACHE.clear()
        whois_enrich.lookup_ip("127.0.0.1")
        assert "127.0.0.1" in whois_enrich._CACHE


class TestLookupPublicIP:
    """IP público: resposta RDAP mockada — testes rodam offline."""

    RDAP_SAMPLE = {
        "name": "LEVEL3",
        "country": "US",
        "type": "DIRECT ALLOCATION",
        "startAddress": "8.0.0.0",
        "endAddress": "8.255.255.255",
        "entities": [
            {"roles": ["registrant"],
             "vcardArray": ["vcard", [["fn", {}, "text", "Level 3 Parent"]]]},
        ],
    }

    def _lookup_mockado(self, ip="8.8.4.4"):
        whois_enrich._CACHE.clear()
        resposta = json.dumps(self.RDAP_SAMPLE).encode("utf-8")
        with mock.patch.object(
            whois_enrich.urllib.request, "urlopen",
            return_value=mock.MagicMock(
                __enter__=mock.MagicMock(
                    return_value=mock.MagicMock(read=lambda: resposta)),
                __exit__=mock.MagicMock(return_value=False),
            ),
        ):
            return whois_enrich.lookup_ip(ip)

    def test_extrai_org_rede_pais(self):
        result = self._lookup_mockado()
        assert result["org"] == "Level 3 Parent"
        assert result["network"] == "LEVEL3"
        assert result["country"] == "US"
        assert result["range"] == "8.0.0.0 - 8.255.255.255"

    def test_falha_de_rede_nao_quebra(self):
        whois_enrich._CACHE.clear()
        with mock.patch.object(
            whois_enrich.urllib.request, "urlopen",
            side_effect=OSError("sem rede"),
        ):
            result = whois_enrich.lookup_ip("8.8.4.4")
        assert "error" in result
        assert "RDAP indisponivel" in result["error"]


class TestEnrichSession:
    """enrich_session adiciona o evento whois e nunca levanta exceção."""

    def test_adiciona_evento_whois(self, tmp_path):
        session = mock.MagicMock()
        session.source_ip = "127.0.0.1"
        whois_enrich.enrich_session(session)
        session.add_event.assert_called_once_with("whois", mock.ANY)