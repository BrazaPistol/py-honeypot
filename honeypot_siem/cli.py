"""CLI para executar regras sobre os logs JSONL do py-honeypot."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from honeypot_siem.reader import read_log_file
from honeypot_siem.rules import alert_to_dict, detect_credential_burst


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analisa logs JSONL do py-honeypot.")
    parser.add_argument("input", type=Path, help="Caminho para sessions.jsonl")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Tentativas para disparar alerta (padrão: 5)")
    parser.add_argument("--window-minutes", type=int, default=10,
                        help="Janela móvel em minutos (padrão: 10)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.threshold < 1 or args.window_minutes < 1:
        parser.error("--threshold e --window-minutes devem ser maiores que zero")

    try:
        attempts, malformed_lines = read_log_file(args.input)
    except OSError:
        print(f"Erro: não foi possível ler o arquivo: {args.input}", file=sys.stderr)
        return 2

    alerts = detect_credential_burst(
        attempts, threshold=args.threshold, window_minutes=args.window_minutes
    )
    output = {
        "alerts": [alert_to_dict(alert) for alert in alerts],
        "malformed_lines": malformed_lines,
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
