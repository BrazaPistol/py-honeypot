# Guia de implantação — py-honeypot

> ⚠️ **Leia o [DISCLAIMER](../DISCLAIMER.md) antes de implantar.**
> Implante apenas em redes de sua propriedade ou laboratórios isolados.

## Opção 1 — Máquina virtual (recomendado para estudo)

1. Crie uma VM (VirtualBox/VMware) com Ubuntu Server.
2. Configure a VM em **rede modo bridge** na sua rede de teste.
3. Instale o honeypot:

```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv
git clone https://github.com/BrazaPistol/py-honeypot.git
cd py-honeypot
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m honeypot.core.server
```

4. Simule um atacante de outra máquina da mesma rede:

```bash
telnet <IP-da-VM> 2323
nc <IP-da-VM> 2121
curl http://<IP-da-VM>:8080/
```

## Opção 2 — Docker (isolamento máximo)

Exemplo de `Dockerfile` (a adicionar futuramente):

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 2323 2121 8080 2222
CMD ["python", "-m", "honeypot.core.server"]
```

## Opção 3 — VPS exposta (apenas com responsabilidade)

Se quiser coletar ataques reais da internet:

1. **Avisar o provedor** — muitos proíbem honeypots; verifique os termos.
2. **Firewall** — libere apenas as portas do honeypot:

```bash
sudo ufw default deny incoming
sudo ufw allow 2323/tcp
sudo ufw allow 2121/tcp
sudo ufw allow 8080/tcp
sudo ufw allow 2222/tcp
sudo ufw allow 22/tcp        # seu SSH real — restrinja ao seu IP!
sudo ufw enable
```

3. **Dashboard SEMPRE em 127.0.0.1** e acesse via tunnel:

```bash
# Na sua máquina local:
ssh -L 5000:127.0.0.1:5000 usuario@<IP-da-VPS>
```

4. **Logs sensíveis** — IPs e payloads coletados são dados pessoais
   (LGPD/GDPD). Armazene com criptografia e retenha o mínimo necessário.

## Endurecimento básico

- Rodar o honeypot com usuário **sem privilégios** (nunca root — as portas
  padrão já são > 1024 por esse motivo).
- Manter `session_timeout` curto (60s) para liberar recursos.
- Monitorar disco: logs crescem rápido com ataques automatizados
  (rotação já configurada em `logging.rotation`).
- Isolar a VM/container da sua rede doméstica se possível (VLAN ou rede host-only).

## Testando localmente

```bash
# Terminal 1
python -m honeypot.core.server

# Terminal 2
curl http://127.0.0.1:8080/admin
nc 127.0.0.1 2121

# Terminal 3
python -m dashboard.app
# Abra http://127.0.0.1:5000
```
