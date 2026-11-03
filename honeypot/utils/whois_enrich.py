"""Enriquecimento passivo de IPs de atacantes via RDAP (whois moderno).

Consulta o RDAP (Registration Data Access Protocol) — o "whois em JSON" —
para descobrir a organização/rede dona do IP de origem de cada sessão.

Totalmente PASSIVO: apenas consultas a bancos de dados públicos de
registro (rdap.org). O honeypot NUNCA envia pacotes ao atacante.

Robustez: se a rede falhar ou o IP for local (laboratório), o resultado
retorna com uma anotação em vez de quebrar o fluxo da sessão.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.request
from typing import Any

_TIMEOUT = 3  # segundos — sessões não devem travar por causa do lookup
_CACHE: dict[str, dict[str, Any]] = {}
_USER_AGENT = "py-honeypot/1.0 (educational project)"


def _is_private_ip(ip: str) -> bool:
    """IPs locais/de laboratório não têm registro público — nem consultamos."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _extract_org(data: dict[str, Any]) -> str | None:
    """Procura o nome da organização (entity com role 'registrant')."""
    for entity in data.get("entities", []):
        vcard = entity.get("vcardArray") or []
        if len(vcard) < 2:
            continue
        fn = None
        for item in vcard[1]:
            if isinstance(item, (list, tuple)) and len(item) >= 4 and item[0] == "fn":
                fn = str(item[3])
                break
        if fn and "registrant" in entity.get("roles", []):
            return fn
    return None


def _summarize_rdap(data: dict[str, Any]) -> dict[str, Any]:
    """Resume a resposta RDAP nos campos que interessam ao honeypot."""
    summary: dict[str, Any] = {
        "network": (data.get("name") or "").strip() or None,
        "country": data.get("country") or None,
        "range": None,
        "org": _extract_org(data),
        "type": data.get("type"),
    }
    start = data.get("startAddress")
    end = data.get("endAddress")
    if start and end:
        summary["range"] = f"{start} - {end}"
    return summary


def lookup_ip(ip: str, timeout: int = _TIMEOUT) -> dict[str, Any]:
    """Retorna dados RDAP resumidos do IP (org, rede, país) ou motivo de falha.

    Usa cache em memória: atacantes repetem IP, e não queremos consultar
    o RDAP de novo para cada sessão.
    """
    if ip in _CACHE:
        return _CACHE[ip]

    if _is_private_ip(ip):
        result = {"scope": "private",
                  "note": "IP local/de laboratorio — sem registro RDAP."}
        _CACHE[ip] = result
        return result

    url = f"https://rdap.org/ip/{ip}"
    try:
        request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
        result = _summarize_rdap(data)
    except Exception as exc:  # timeout, offline, RDAP fora — sessão segue normal
        result = {"error": f"RDAP indisponivel: {type(exc).__name__}"}

    _CACHE[ip] = result
    return result


def enrich_session(session) -> None:
    """Adiciona um evento 'whois' à sessão com os dados do IP de origem.

    Chamado ao encerrar a sessão (server.py). lookup_ip nunca levanta
    exceção, então é seguro chamar direto no fluxo de fechamento.
    """
    session.add_event("whois", lookup_ip(session.source_ip))


if __name__ == "__main__":  # teste manual: python -m honeypot.utils.whois_enrich
    for test_ip in ("8.8.8.8", "1.1.1.1", "127.0.0.1"):
        print(test_ip, "->", json.dumps(lookup_ip(test_ip), ensure_ascii=False))