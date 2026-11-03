"""Registro global de servicos falsos do honeypot.

Modulo proprio, independente do server.py, para evitar o problema de
modulo duplicado: quando o servidor era executado com
`python -m honeypot.core.server`, o arquivo era carregado como
`__main__`, e o import feito pelos servicos (`from honeypot.core.server
import register_service`) criava uma SEGUNDA copia do modulo — cada uma
com seu proprio `_SERVICE_REGISTRY`. Os servicos registravam na copia
que o `__main__` nunca consultava, resultando em "Servico habilitado
mas sem implementacao". Centralizar o registro aqui garante que exista
uma unica copia compartilhada por todos.
"""

from __future__ import annotations

# Registro de servicos — preenchido por register_service()
_SERVICE_REGISTRY: dict[str, type] = {}


def register_service(name: str):
    """Decorator que registra uma classe de servico falso.

    Uso:
        @register_service("telnet")
        class TelnetFake(BaseService): ...
    """
    def decorator(cls):
        _SERVICE_REGISTRY[name] = cls
        return cls
    return decorator