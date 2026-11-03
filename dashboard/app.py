"""Dashboard web — visualização de ataques em tempo real.

Le o arquivo logs/sessions.jsonl (escrito pelo logger do honeypot)
e expoe estatisticas via Flask. Bind em 127.0.0.1 por padrao:
NUNCA exponha o dashboard na internet (ver docs/DEPLOYMENT.md).

Paginas informativas explicam o escopo local da ferramenta: ela observa
apenas o SEU honeypot — não pesquisa dispositivos na internet e nao é
afiliada ao Shodan ou qualquer buscador global.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from flask import Flask, jsonify, render_template

LOG_FILE = Path("logs/sessions.jsonl")

INFO_PAGES: dict[str, dict] = {
    "como-funciona": {
        "eyebrow": "ENTENDA A FERRAMENTA",
        "title": "Como funciona",
        "description": (
            "O py-honeypot abre portas locais que imitam Telnet, FTP e HTTP. "
            "Este painel lê apenas o arquivo de logs gerado na SUA máquina — "
            "não pesquisa dispositivos na internet e não envia nada para fora."
        ),
        "sections": [
            {
                "title": "Coleta local",
                "body": (
                    "Cada conexão recebida pelos serviços simulados é gravada "
                    "como uma sessão em logs/sessions.jsonl, com comandos, "
                    "credenciais tentadas e eventos."
                ),
            },
            {
                "title": "Leitura do painel",
                "body": (
                    "O dashboard apenas lê esse arquivo e resume: total de "
                    "sessões, IPs de origem únicos e serviço mais visado."
                ),
            },
            {
                "title": "Escopo",
                "body": (
                    "Tudo acontece no seu computador. A ferramenta não "
                    "pesquisa dispositivos de terceiros, não escaneia redes "
                    "externas e não é afiliada ao Shodan."
                ),
            },
        ],
    },
    "servicos": {
        "eyebrow": "PORTAS SIMULADAS",
        "title": "Serviços simulados",
        "description": (
            "Cada serviço falso imita um protocolo legado para registrar o "
            "comportamento de quem tenta se conectar."
        ),
        "sections": [
            {
                "title": "Telnet (porta 2323)",
                "body": (
                    "Simula login de roteador: pede usuário e senha, falha "
                    "até 3 tentativas e captura cada credencial digitada."
                ),
            },
            {
                "title": "FTP (porta 2121)",
                "body": (
                    "Banner 'FTP Server ready' com comandos USER/PASS sempre "
                    "rejeitados — captura dicionários de credenciais."
                ),
            },
            {
                "title": "HTTP (porta 8080)",
                "body": (
                    "Responde qualquer path (inclusive /wp-login.php) e "
                    "registra user-agents e padrões de scanners web."
                ),
            },
            {
                "title": "SSH (desativado)",
                "body": (
                    "Banner-only, desativado por padrão no config.yaml — "
                    "handshake real exige biblioteca adicional."
                ),
            },
        ],
    },
    "dados-e-seguranca": {
        "eyebrow": "PRIVACIDADE E LIMITES",
        "title": "Dados e segurança",
        "description": (
            "Transparência sobre o que é coletado, onde fica e o que este "
            "painel jamais faz."
        ),
        "sections": [
            {
                "title": "O que é coletado",
                "body": (
                    "IP de origem, comandos enviados, credenciais tentadas e "
                    "eventos da sessão — tudo em texto no seu disco local."
                ),
                "items": [
                    "logs/sessions.jsonl (sessões)",
                    "logs/honeypot.log (execução)",
                ],
            },
            {
                "title": "Onde ficam os dados",
                "body": (
                    "Apenas na sua máquina. Não há telemetria, conta, nem "
                    "envio para qualquer servidor — o honeypot é passivo."
                ),
            },
            {
                "title": "Limites de uso",
                "body": (
                    "Projeto educacional para uso em rede própria/laboratório. "
                    "Expor um honeypot na internet pública exige "
                    "responsabilidade legal (ver docs/DEPLOYMENT.md)."
                ),
            },
        ],
    },
}


def _load_sessions() -> list[dict]:
    """Le todas as sessões registradas no log JSONL."""
    if not LOG_FILE.exists():
        return []
    sessions = []
    for line in LOG_FILE.read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "data" in record and "session" in record["data"]:
            sessions.append(record["data"]["session"])
    return sessions


def create_app() -> Flask:
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template("index.html", active_page="dashboard")

    @app.route("/como-funciona")
    def how_it_works():
        return render_template("info.html", active_page="como-funciona",
                              page=INFO_PAGES["como-funciona"])

    @app.route("/servicos")
    def services():
        return render_template("info.html", active_page="servicos",
                              page=INFO_PAGES["servicos"])

    @app.route("/dados-e-seguranca")
    def data_and_security():
        return render_template("info.html", active_page="dados-e-seguranca",
                              page=INFO_PAGES["dados-e-seguranca"])

    @app.route("/api/stats")
    def stats():
        sessions = _load_sessions()
        services = Counter(s.get("service") for s in sessions)
        unique_ips = len({s.get("source_ip") for s in sessions if s.get("source_ip")})
        top = services.most_common(1)[0][0] if services else None
        return jsonify({
            "total_sessions": len(sessions),
            "unique_ips": unique_ips,
            "top_service": top,
            "by_service": {
                "labels": list(services),
                "values": [services[s] for s in services],
            },
        })

    return app


if __name__ == "__main__":
    from honeypot.core.config import load_config
    config = load_config()
    host = config.get("dashboard", {}).get("host", "127.0.0.1")
    port = int(config.get("dashboard", {}).get("port", 5000))
    create_app().run(host=host, port=port, debug=False)