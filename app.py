"""Dashboard web — visualização de ataques em tempo real.

Le o arquivo logs/sessions.jsonl (escrito pelo logger do honeypot)
e expoe estatisticas via Flask. Bind em 127.0.0.1 por padrao:
NUNCA exponha o dashboard na internet (ver docs/DEPLOYMENT.md).
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from flask import Flask, jsonify, render_template_string

LOG_FILE = Path("logs/sessions.jsonl")

INDEX_HTML = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <title>Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
  <style>
    body { font-family: sans-serif; margin: 2rem; background: #f5f5f5; }
    h1 { color: #b45309; }
    .cards { display: flex; gap: 1rem; margin-bottom: 2rem; }
    .card { background: white; padding: 1rem 1.5rem; border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,.15); }
    .card h2 { margin: 0; font-size: 2rem; }
    .card span { color: #666; }
    #chart { background: white; padding: 1rem; border-radius: 8px; }
  </style>
</head>
<body>
  <h1>&#127851; Dashboard</h1>
  <div class="cards">
    <div class="card"><h2 id="total">0</h2><span>sessões</span></div>
    <div class="card"><h2 id="unique-ips">0</h2><span>IPs únicos</span></div>
    <div class="card"><h2 id="top-service">—</h2><span>serviço mais visado</span></div>
  </div>
  <canvas id="chart" width="600" height="250"></canvas>
  <script>
    async function refresh() {
      const res = await fetch('/api/stats');
      const data = await res.json();
      document.getElementById('total').textContent = data.total_sessions;
      document.getElementById('unique-ips').textContent = data.unique_ips;
      document.getElementById('top-service').textContent = data.top_service || '—';
      window.chart.data.labels = data.by_service.labels;
      window.chart.data.datasets[0].data = data.by_service.values;
      window.chart.update();
    }
    window.chart = new Chart(document.getElementById('chart'), {
      type: 'bar',
      data: { labels: [], datasets: [{ label: 'Sessões por serviço', data: [],
              backgroundColor: '#b45309' }] },
      options: { animation: false }
    });
    refresh();
    setInterval(refresh, 5000);  // atualiza a cada 5s
  </script>
</body>
</html>
"""


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
        return render_template_string(INDEX_HTML)

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