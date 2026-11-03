# 🔬 Guia de Laboratório — Nmap, Wireshark e Whois/RDAP

Este guia mostra como usar ferramentas clássicas de segurança **no seu
próprio laboratório** (apenas contra o honeypot rodando na SUA máquina).
O objetivo é duplo: ver o honeypot como um atacante real o veria e
validar que as capturas funcionam.

> ## ⚠️ Regra de ouro
> **NUNCA escaneie ou capture pacotes de sistemas que não sejam seus.**
> Escanear o IP de um atacante real "em retorno" é ataque — ilegal na
> maioria dos países e contra a ética deste projeto. O honeypot é
> **100% passivo**: escuta e registra, nunca responde com ofensiva.

---

## 0. Pré-requisitos

| Ferramenta | Instalação (Windows) | Verificação |
|------------|----------------------|-------------|
| Nmap | [nmap.org/download](https://nmap.org/download.html) (instalador Windows) | `nmap --version` |
| Wireshark | [wireshark.org](https://www.wireshark.org/download.html) | `tshark --version` |
| Whois/RDAP | **Nada a instalar** — já integrado ao honeypot (`honeypot/utils/whois_enrich.py`) | `python -m honeypot.utils.whois_enrich` |

Com o honeypot rodando:

```powershell
python -m honeypot.core.server
# INFO Serviço 'telnet' escutando em 0.0.0.0:2323
# INFO Serviço 'ftp' escutando em 0.0.0.0:2121
# INFO Serviço 'http' escutando em 0.0.0.0:8080
```

---

## 1. 🗺️ Nmap — veja o honeypot como o atacante vê

O Nmap simula a **fase de reconhecimento** de um ataque: descobrir
portas abertas e banners de serviço. Rode **contra 127.0.0.1** (você mesmo).

### 1.1 Scan rápido das portas do honeypot

```powershell
nmap -p 2121,2323,8080 127.0.0.1
```

**Esperado:** as 3 portas `open`. Confirme que o honeypot registrou
as conexões do Nmap como sessões (veja o dashboard ou `logs/sessions.jsonl`).

### 1.2 Detecção de versão (o que o Nmap "acha" dos nossos banners)

```powershell
nmap -sV -p 2121,2323,8080 127.0.0.1
```

O `-sV` envia probes e lê as respostas dos serviços falsos. O FTP
responde `220 FTP Server ready` — o Nmap pode classificá-lo como `ftp`.
Isso mostra o quão convincente (ou não) o banner falso é.

### 1.3 Agressivo (também só contra 127.0.0.1)

```powershell
nmap -A -p 8080 127.0.0.1
```

`-A` = detecção de SO + versão + scripts padrão. Compare as sessões
registradas: cada probe do Nmap vira sessão com `source_ip 127.0.0.1`
e comandos capturados — exatamente o que um scanner real deixaria.

### 1.4 O que observar no honeypot

- Cada scan do Nmap gera **múltiplas sessões** (uma por conexão TCP)
- O dashboard mostra o pico de "ataques" — é o comportamento de um scan
- Banners falsos que parecem reais = honeypot mais convincente

---

## 2. 🔍 Wireshark — capturando os ataques ao vivo

O Wireshark mostra os pacotes brutos: o que o atacante envia e o que
o honeypot responde. No laboratório, tudo acontece em loopback.

### 2.1 Capturando o tráfego do honeypot

1. Abra o **Wireshark**
2. Selecione a interface **`Adapter for loopback traffic capture`** (Npcap)
   — no Windows o tráfego 127.0.0.1 só aparece nessa interface
3. Clique no ícone **Start**
4. Rode os ataques de teste:

```powershell
curl.exe http://127.0.0.1:8080/wp-login.php
curl.exe ftp://127.0.0.1:2121/ --user admin:senha123
```

### 2.2 Filtros úteis (cole na barra de filtro)

| Filtro | Mostra |
|--------|--------|
| `tcp.port == 8080` | Todo o tráfego HTTP do honeypot |
| `tcp.port == 2121` | FTP (veja USER/PASS em texto claro!) |
| `tcp.port == 2323` | Telnet (credenciais em texto claro) |
| `ftp.request.command` | Apenas comandos FTP capturados |
| `http.request` | Apenas requisições HTTP (paths tipo /wp-login.php) |

### 2.3 O que observar

- **"Follow TCP Stream"** (botão direito no pacote → Follow): mostra a
  conversa completa atacante ↔ honeypot, incluindo `admin`/`senha123`
  em texto puro — a razão pela qual Telnet/FTP foram descontinuados
- O padrão de request/response dos banners falsos
- Timeouts: sessões encerradas por inatividade (FIN/RST no final)

---

## 3. 🌐 Whois/RDAP — de quem é o IP do atacante?

**Já integrado automaticamente.** Ao encerrar cada sessão, o honeypot
consulta o RDAP público (o whois em JSON, via `rdap.org`) e registra um
evento `whois` na sessão com: organização, rede, país e faixa do IP.

### 3.1 Vendo no lab

Sessões de `127.0.0.1` são marcadas:

```json
{"event": "whois", "data": {"scope": "private", "note": "IP local/de laboratorio — sem registro RDAP."}}
```

### 3.2 Testando com IP real (consulta manual, sem atacar ninguém)

```powershell
python -m honeypot.utils.whois_enrich
# 8.8.8.8 -> {"network": "GOOGLE", "org": "GOOGLE", "country": "US", ...}
# 1.1.1.1 -> {"network": "CLOUDFLARENET", ...}
# 127.0.0.1 -> {"scope": "private", "note": "..."}
```

Em produção (honeypot exposto na internet), cada atacante real aparece
no `logs/sessions.jsonl` com a org/rede dona do IP — insumo para análise
de ameaças, sem enviar um único pacote ao atacante.

### 3.3 Cache

IPs repetidos (atacantes voltam!) são atendidos por cache em memória —
o lookup custa ~0ms após a primeira consulta, e falha de rede não
afeta o registro da sessão.

---

## 4. 🧪 Roteiro completo de experimento

1. `python -m honeypot.core.server` (Terminal 1)
2. `python -m dashboard.app` (Terminal 2) → abra `http://127.0.0.1:5000`
3. Wireshark capturando o loopback (Filtro: `tcp.port == 8080 || tcp.port == 2121 || tcp.port == 2323`)
4. `nmap -sV -p 2121,2323,8080 127.0.0.1` (Terminal 3)
5. Ataques curl + o `python -m honeypot.utils.whois_enrich`
6. Compare: **Wireshark** (pacotes) ↔ **Dashboard/JSONL** (interpretação
   do honeypot) ↔ **Nmap** (visão do atacante) — três ângulos do mesmo evento

---

## 5. 📜 Referências éticas e legais

- Nmap: escaneie apenas máquinas suas ou com autorização por escrito
- Wireshark: capture apenas tráfego da sua rede/dispositivos
- Whois/RDAP: consulta pública e passiva — segura contra qualquer IP
- Um honeypot bem comportado nunca "devolve" ataques. Ele coleta
  inteligência e espera.
