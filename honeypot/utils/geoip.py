"""Geolocalização do IP do atacante — com fallback offline.

Se o banco MaxMind GeoLite2 existir em data/, retorna país/cidade.
Caso contrário, registra apenas o IP (o honeypot funciona sem GeoIP).
"""

from __future__ import annotations

from typing import Any

DEFAULT_DB_PATH = "data/GeoLite2-City.mmdb"


def lookup(ip: str, database_path: str = DEFAULT_DB_PATH) -> dict[str, Any]:
    """Retorna {'country': ..., 'city': ...} ou {} se indisponível."""
    try:
        import geoip2.database  # dependência opcional
    except ImportError:
        return {"note": "geoip2 não instalado"}

    from pathlib import Path
    if not Path(database_path).exists():
        return {"note": "banco GeoIP ausente — baixe GeoLite2 (gratuito) em maxmind.com"}

    try:
        with geoip2.database.Reader(database_path) as reader:
            response = reader.city(ip)
            return {
                "country": response.country.iso_code,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
            }
    except Exception:  # noqa: BLE001 — GeoIP nunca deve derrubar o honeypot
        return {}