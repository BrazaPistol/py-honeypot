# py-honeypot

> **Honeypot modular em Python para detecção e análise de ataques** — Telnet, FTP, HTTP e SSH falsos, logs em JSON e dashboard em tempo real.

## Aviso Legal

Este projeto é **estritamente educacional**. O honeypot deve ser implantado apenas em redes/laboratórios **de sua propriedade** ou com **autorização explícita**. Uso contra sistemas de terceiros é ilegal. Veja [DISCLAIMER.md](DISCLAIMER.md).

## Sobre

Um honeypot de baixa interação que simula serviços vulneráveis (Telnet, FTP, HTTP, SSH) para atrair, registrar e analisar tentativas de ataque em tempo real.

### Funcionalidades

- **Serviços falsos modulares** — Telnet, FTP, HTTP e SSH (cada um captura banners, credenciais e payloads)
- **Logs estruturados em JSON** — fáceis de analisar com `jq`, Python ou ELK
- **Dashboard web em tempo real** — Flask + Chart.js para visualizar ataques ao vivo
- **Geolocalização de IP** — de onde vêm os ataques
- **Fingerprinting** — detecção de scanners, user-agents e padrões conhecidos
- **Configuração via YAML** — ative/desative serviços sem tocar no código

## Arquitetura

```
Atacante -> Porta aberta -> BaseService.accept() -> banner falso
        -> sessão registrada (IP, porta, timestamp, payloads)
        -> logger JSON -> dashboard exibe em tempo real
```

Ver detalhes completos em [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Instalação

```bash
# Clonar o repositório
git clone https://github.com/BrazaPistol/py-honeypot.git
cd py-honeypot

# Criar ambiente virtual
python -m venv venv
source venv/bin/activate   # Linux/Mac
# venv\Scripts\activate    # Windows

# Instalar dependências
pip install -r requirements.txt

# Executar o honeypot
python -m honeypot.core.server
```

## Dashboard

```bash
python -m dashboard.app
# Acesse http://localhost:5000
```

## Testes

```bash
python -m pytest tests/ -v
```

## Estrutura

```
py-honeypot/
├── README.md                  # Este arquivo
├── LICENSE                    # MIT
├── DISCLAIMER.md              # Aviso legal detalhado
├── requirements.txt           # Dependências
├── config/
│   └── config.yaml            # Portas, serviços ativos
├── honeypot/                  # Pacote principal
│   ├── core/                  # Server, session, config, logger
│   ├── services/              # telnet.py, ftp.py, http.py, ssh.py
│   └── utils/                 # geoip.py, fingerprint.py
├── dashboard/
│   └── app.py                 # Painel web (Flask)
├── logs/                      # Logs JSON (nao commitados)
├── tests/                     # Testes unitarios
└── docs/                      # Arquitetura e implantacao
```

## Documentacao

- [Arquitetura](docs/ARCHITECTURE.md)
- [Guia de implantacao](docs/DEPLOYMENT.md)
- [Aviso legal](DISCLAIMER.md)

## Contribuindo

Pull requests sao bem-vindos! Para mudancas maiores, abra uma issue primeiro para discutirmos.

## Licenca

Distribuido sob a licenca MIT. Veja [LICENSE](LICENSE) para mais detalhes.

## Autor

**BrazaPistol** — [GitHub](https://github.com/BrazaPistol)
