"""Fingerprinting básico: detecta scanners e padrões de ataque comuns."""

from __future__ import annotations

import re

# Assinaturas simples de ferramentas conhecidas
SIGNATURES: list[tuple[str, str]] = [
    (r"^masscan/", "masscan"),
    (r"^nmap", "nmap-script"),
    (r"^zgrab", "zgrab"),
    (r"^Go-http-client", "go-scanner"),
    (r"^python-requests/", "python-script"),
    (r"^curl/", "curl-manual"),
    (r"^Wget", "wget-manual"),
    (r"^Hydra", "hydra-bruteforce"),
    (r"^medusa", "medusa-bruteforce"),
    (r"^ncat|nmap-ncat", "netcat"),
]

# Padrões de path que indicam varredura de vulnerabilidades web
WEB_SCANNER_PATHS = re.compile(
    r"(/wp-login|/wp-admin|/\.env|/\.git|/phpmyadmin|/admin\.php|"
    r"/cgi-bin/|/manager/html|/actuator|/vendor/phpunit)",
    re.IGNORECASE,
)


def classify_user_agent(user_agent: str) -> str | None:
    """Classifica o User-Agent contra assinaturas conhecidas."""
    if not user_agent:
        return None
    for pattern, label in SIGNATURES:
        if re.search(pattern, user_agent):
            return label
    return None


def classify_http_path(path: str) -> str | None:
    """Detecta paths típicos de scanners de vulnerabilidade web."""
    if path and WEB_SCANNER_PATHS.search(path):
        return "web-vuln-scanner"
    return None


def fingerprint_session(session) -> str | None:
    """Faz fingerprint completo de uma sessão e atualiza session.fingerprint."""
    labels: list[str] = []

    # User-Agent (presente nos payloads de sessões HTTP)
    joined_payloads = " ".join(session.payloads)
    for pattern, label in SIGNATURES:
        if re.search(pattern, joined_payloads, re.IGNORECASE):
            labels.append(label)

    # Paths de scanner web
    for payload in session.payloads:
        match = WEB_SCANNER_PATHS.search(payload)
        if match:
            labels.append("web-vuln-scanner")
            break

    if labels:
        session.fingerprint = ", ".join(sorted(set(labels)))
    return session.fingerprint