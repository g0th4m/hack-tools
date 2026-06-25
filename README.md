# hack-tools

Toolkit per penetration test e preparazione OSCP.

## Requisiti

- Python 3.9+
- `nmap`, `ffuf` (su Kali sono già presenti)
- Wordlist Seclists (consigliata)

Nessuna dipendenza Python esterna: solo stdlib.

## Avvio

```bash
# Menù interattivo
./oscp-scan

# Oppure con IP diretto
./oscp-scan 10.129.28.172

# Equivalente
python3 -m oscp_scan
./scan.sh
```

## Menù

| Opzione | Azione |
|---------|--------|
| 1 | Full TCP scan (`-p- --min-rate 5000`) |
| 2 | Detail scan (`-sCV` sulle porte aperte) |
| 3 | UDP top-100 (foreground) |
| 4 | UDP top-100 (background) |
| 5 | Riesegui estrazione dominio da nmap |
| 6 | FFuf subdomains / vhost |
| 7 | Pipeline completa (flusso automatico) |
| 8 | Mostra file generati |
| 9 | Cambia target / carica scan esistente |

Ogni scan salva lo stato in `oscp_scan_<IP>/state.json` così puoi rilanciare singoli task senza rifare tutto.

## Output

```
oscp_scan_10.129.28.172/
├── state.json
├── detected_domain.txt
├── full.nmap / .gnmap / .xml
├── detail.nmap / .gnmap / .xml
├── udp.nmap / .gnmap / .xml
└── ffuf_target_htb.json / .log
```

## Clone su HTB

```bash
git clone https://github.com/g0th4m/hack-tools.git
cd hack-tools
chmod +x oscp-scan scan.sh
./oscp-scan
```
