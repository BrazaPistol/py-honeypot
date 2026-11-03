"""Logger estruturado em JSON com rotação de arquivos.

Formato JSONL: um evento JSON por linha — fácil de analisar com
jq, pandas, ELK ou SQLite.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LOGGERS: dict[str, logging.Logger] = {}


def utc_now() -> str:
    """Timestamp ISO-8601 em UTC."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _format_json(record: logging.LogRecord) -> str:
    """Serializa o LogRecord como uma linha JSON."""
    payload: dict[str, Any] = {
        "timestamp": utc_now(),
        "level": record.levelname,
        "logger": record.name,
        "message": record.getMessage(),
    }
    if record.exc_info:
        payload["exception"] = logging.Formatter.formatException(record, record.exc_info)

    # Eventos de sessão carregam atributos extras (session, ip, service, ...)
    extras = getattr(record, "honeypot_data", None)
    if extras:
        payload["data"] = extras

    return json.dumps(payload, ensure_ascii=False, default=str)


def get_logger(name: str = "honeypot", log_dir: str = "logs",
               max_bytes: int = 10_485_760, backup_count: int = 5) -> logging.Logger:
    """Retorna um logger configurado (idempotente)."""
    if name in _LOGGERS:
        return _LOGGERS[name]

    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Handler de arquivo com rotação
    file_handler = logging.handlers.RotatingFileHandler(
        log_path / "sessions.jsonl",
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    file_handler.setFormatter(logging.Formatter(fmt="%(message)s"))
    file_handler.emit = _json_emit(file_handler)  # type: ignore[method-assign]

    # Handler de console (uso humano durante desenvolvimento)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        logging.Formatter("[%(asctime)s] %(levelname)s %(message)s", datefmt="%H:%M:%S")
    )

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.propagate = False

    _LOGGERS[name] = logger
    return logger


def _json_emit(handler: logging.Handler):
    """Envolve o emit padrão para gravar JSON em vez de texto."""
    original_emit = handler.emit

    def emit(record: logging.LogRecord) -> None:
        line = _format_json(record)
        record_copy = logging.LogRecord(
            name=record.name, level=record.levelno, pathname=record.pathname,
            lineno=record.lineno, msg=line, args=None, exc_info=None,
        )
        original_emit(record_copy)

    return emit