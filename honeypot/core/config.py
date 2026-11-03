"""Carregamento e validação da configuração (config/config.yaml).

Sobrescreve com config/local.yaml, se existir — útil para testes
sem commitar configuração sensível.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "config.yaml"
LOCAL_CONFIG_PATH = DEFAULT_CONFIG_PATH.parent / "local.yaml"

REQUIRED_KEYS = ("server", "services", "logging")


class ConfigError(Exception):
    """Erro de configuração (arquivo ausente, YAML inválido, chave faltando)."""


def load_config(config_path: Path | None = None) -> dict[str, Any]:
    """Carrega config.yaml e aplica overrides de local.yaml.

    Raises:
        ConfigError: se o arquivo não existir ou for inválido.
    """
    path = config_path or DEFAULT_CONFIG_PATH
    if not path.exists():
        raise ConfigError(f"Arquivo de configuração não encontrado: {path}")

    with path.open("r", encoding="utf-8") as fh:
        config = yaml.safe_load(fh) or {}

    # Overrides locais (não commitados — ver .gitignore)
    if LOCAL_CONFIG_PATH.exists():
        with LOCAL_CONFIG_PATH.open("r", encoding="utf-8") as fh:
            local = yaml.safe_load(fh) or {}
        config = _deep_merge(config, local)

    validate(config)
    return config


def _deep_merge(base: dict, override: dict) -> dict:
    """Merge recursivo: valores de override ganham sobre base."""
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def validate(config: dict[str, Any]) -> None:
    """Valida estrutura mínima e regras de negócio da configuração."""
    for key in REQUIRED_KEYS:
        if key not in config:
            raise ConfigError(f"Chave obrigatória ausente: '{key}'")

    if not isinstance(config["services"], dict) or not config["services"]:
        raise ConfigError("Pelo menos um serviço deve estar definido em 'services'")

    enabled = [
        name for name, svc in config["services"].items()
        if isinstance(svc, dict) and svc.get("enabled", False)
    ]
    if not enabled:
        raise ConfigError("Nenhum serviço habilitado (services.*.enabled = true)")

    # Portas duplicadas
    ports = [
        svc.get("port") for svc in config["services"].values()
        if isinstance(svc, dict) and svc.get("enabled", False)
    ]
    if len(ports) != len(set(ports)):
        raise ConfigError(f"Portas duplicadas entre serviços: {ports}")

    for port in ports:
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ConfigError(f"Porta inválida: {port!r} (esperado int 1-65535)")