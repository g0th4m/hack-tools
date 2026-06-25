#!/bin/bash

# OSCP-style scan helper: TCP full → detail → optional UDP (bg) + ffuf subdomains
# Usage:
#   ./scan.sh
#   ./scan.sh 10.129.28.172

set -e

# Colors
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
CYAN="\e[36m"
MAGENTA="\e[35m"
BOLD="\e[1m"
RESET="\e[0m"

print_cmd() {
    echo -e "${CYAN}${BOLD}Command:${RESET} ${BLUE}$*${RESET}"
}

ask_yes_no() {
    local prompt="$1"
    local answer
    read -rp "$(echo -e "${YELLOW}$prompt [y/N]: ${RESET}")" answer
    [[ "$answer" =~ ^[Yy]$ ]]
}

ask_yes_no_default_yes() {
    local prompt="$1"
    local answer
    read -rp "$(echo -e "${YELLOW}$prompt [Y/n]: ${RESET}")" answer
    [[ -z "$answer" || "$answer" =~ ^[Yy]$ ]]
}

get_domain_sources() {
    local nmap_file="$1"
    local domain="$2"
    local sources=()

    [ -f "$nmap_file" ] || return 0

    grep -qE "Nmap scan report for ${domain}[ (]" "$nmap_file" 2>/dev/null && sources+=("scan report")
    grep -qiE "commonName[=: ].*${domain}" "$nmap_file" 2>/dev/null && sources+=("SSL certificate")
    grep -qiE "DNS:${domain}" "$nmap_file" 2>/dev/null && sources+=("SSL SAN")
    grep -qiE "https?://${domain}" "$nmap_file" 2>/dev/null && sources+=("HTTP redirect")

    if [ "${#sources[@]}" -gt 0 ]; then
        local IFS=', '
        echo "${sources[*]}"
    fi
}

print_domain_detection() {
    local nmap_file="$1"

    echo
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════${RESET}"

    if [ -n "$DETECTED_DOMAIN" ]; then
        local sources
        sources=$(get_domain_sources "$nmap_file" "$DETECTED_DOMAIN" || true)

        echo -e "${GREEN}${BOLD}  Dominio rilevato da nmap:${RESET} ${MAGENTA}${BOLD}${DETECTED_DOMAIN}${RESET}"
        if [ -n "$sources" ]; then
            echo -e "${GREEN}${BOLD}  Fonte:${RESET} ${CYAN}${sources}${RESET}"
        fi
        if [ -n "$NMAP_DOMAINS" ] && [ "$(echo "$NMAP_DOMAINS" | wc -l | tr -d ' ')" -gt 1 ]; then
            echo -e "${GREEN}${BOLD}  Altri hostname trovati:${RESET}"
            while IFS= read -r d; do
                [ -z "$d" ] && continue
                [ "$d" = "$DETECTED_DOMAIN" ] && continue
                echo -e "    ${BLUE}${d}${RESET}"
            done <<< "$NMAP_DOMAINS"
        fi
        if [ -n "$WEB_URL" ]; then
            echo -e "${GREEN}${BOLD}  Endpoint web:${RESET} ${CYAN}${WEB_URL}${RESET}"
        fi
        echo "$DETECTED_DOMAIN" >"$OUTDIR/detected_domain.txt"
    else
        echo -e "${YELLOW}${BOLD}  Nessun dominio rilevato da nmap${RESET}"
        echo -e "${YELLOW}  Dovrai inserirlo manualmente per ffuf.${RESET}"
    fi

    echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════${RESET}"
    echo
}

extract_open_ports() {
    awk -F'[/ ]' '
        /Ports:/ {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /\/open\/tcp/) {
                    split($i, p, "/")
                    print p[1]
                }
            }
        }
    ' "$1" | paste -sd,
}

extract_domains_from_nmap() {
    local nmap_file="$1"
    local target_ip="$2"

    [ -f "$nmap_file" ] || return 0

    {
        grep -oE 'Nmap scan report for [^( ]+' "$nmap_file" \
            | sed 's/Nmap scan report for //' \
            | grep -vE '^[0-9.]+$'

        grep -oiE 'commonName[=: ][^,/| ]+' "$nmap_file" \
            | sed -E 's/commonName[=: ]//I'

        grep -oiE 'DNS:[^,| ]+' "$nmap_file" \
            | sed -E 's/DNS://I'

        grep -oiE 'https?://[^/[:space:]"<>]+' "$nmap_file" \
            | sed -E 's|https?://||I' \
            | cut -d: -f1
    } | grep -iEv 'localhost|^[0-9.]+$' \
      | grep -E '^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$' \
      | grep -viF "$target_ip" \
      | awk '{ print tolower($0) }' \
      | sort -u
}

pick_base_domain() {
    local domains="$1"
    local domain line best=""

    if [ -z "$domains" ]; then
        return 1
    fi

    # Prefer lab-style TLDs, then shortest hostname (usually the box root domain)
    while IFS= read -r domain; do
        [ -z "$domain" ] && continue
        if [[ "$domain" =~ \.(htb|htb\.cloud|local|corp|internal)$ ]]; then
            if [ -z "$best" ] || [ "${#domain}" -lt "${#best}" ]; then
                best="$domain"
            fi
        fi
    done <<< "$domains"

    if [ -n "$best" ]; then
        echo "$best"
        return 0
    fi

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        if [ -z "$best" ] || [ "${#line}" -lt "${#best}" ]; then
            best="$line"
        fi
    done <<< "$domains"

    echo "$best"
}

extract_web_endpoint() {
    local gnmap_file="$1"
    local target_ip="$2"
    local ports

    [ -f "$gnmap_file" ] || return 0

    ports=$(awk -F'[/ ]' '
        /Ports:/ {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /\/open\/tcp/) {
                    split($i, p, "/")
                    print p[1]
                }
            }
        }
    ' "$gnmap_file")

    if echo "$ports" | grep -qx 443; then
        echo "https://${target_ip}:443"
        return 0
    fi
    if echo "$ports" | grep -qx 80; then
        echo "http://${target_ip}:80"
        return 0
    fi
    if echo "$ports" | grep -qx 8080; then
        echo "http://${target_ip}:8080"
        return 0
    fi
    if echo "$ports" | grep -qx 8443; then
        echo "https://${target_ip}:8443"
        return 0
    fi

    local first
    first=$(echo "$ports" | head -n1)
    [ -n "$first" ] && echo "http://${target_ip}:${first}"
}

default_wordlist() {
    local candidates=(
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        "/usr/share/wordlists/dirb/common.txt"
    )
    local path
    for path in "${candidates[@]}"; do
        if [ -f "$path" ]; then
            echo "$path"
            return 0
        fi
    done
    return 1
}

show_ffuf_results() {
    local json_file="$1"
    local domain="$2"
    local log_file="$3"
    local found=0

    echo -e "${GREEN}[+] Subdomains / vhosts found:${RESET}"

    if [ -f "$json_file" ] && [ -s "$json_file" ]; then
        if command -v jq &>/dev/null; then
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                echo -e "    ${BOLD}${MAGENTA}$line${RESET}"
                found=1
            done < <(jq -r --arg d "$domain" '
                .results[]?
                | (.input.FUZZ // .input["FUZZ"] // empty) as $fuzz
                | select($fuzz != null and $fuzz != "")
                | (if ($fuzz | test($d)) then $fuzz else "\($fuzz).\($d)" end) as $host
                | "\($host) [\(.status)] \(.length)b"
            ' "$json_file" 2>/dev/null)
        else
            while IFS= read -r fuzz; do
                [ -z "$fuzz" ] && continue
                if [[ "$fuzz" == *"$domain" ]]; then
                    echo -e "    ${BOLD}${MAGENTA}${fuzz}${RESET}"
                else
                    echo -e "    ${BOLD}${MAGENTA}${fuzz}.${domain}${RESET}"
                fi
                found=1
            done < <(grep -oE '"FUZZ"[[:space:]]*:[[:space:]]*"[^"]*"' "$json_file" | sed -E 's/.*"([^"]*)"/\1/' | sort -u)
        fi
    fi

    if [ -f "$log_file" ]; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            echo -e "    ${BOLD}${MAGENTA}$line${RESET}"
            found=1
        done < <(grep -E '^\s*\* FUZZ:' "$log_file" 2>/dev/null \
            | sed -E 's/^\s*\* FUZZ:[[:space:]]*//' \
            | while read -r fuzz; do
                if [[ "$fuzz" == *"$domain" ]]; then
                    echo "$fuzz"
                else
                    echo "${fuzz}.${domain}"
                fi
            done | sort -u)
    fi

    if [ "$found" -eq 0 ]; then
        echo -e "    ${YELLOW}(none)${RESET}"
    fi
}

run_ffuf_enum() {
    local domain="$1"
    local ffuf_url="$2"
    local wordlist="$3"
    local mode="$4"
    local out_json="$OUTDIR/ffuf_${domain//./_}.json"
    local out_log="$OUTDIR/ffuf_${domain//./_}.log"
    local ffuf_cmd=()

    if [ "$mode" = "vhost" ]; then
        ffuf_cmd=(
            ffuf
            -w "$wordlist"
            -u "$ffuf_url"
            -H "Host: FUZZ.${domain}"
            -ac
            -t 40
            -v
            -o "$out_json"
            -of json
        )
    else
        ffuf_cmd=(
            ffuf
            -w "$wordlist"
            -u "http://FUZZ.${domain}"
            -ac
            -t 40
            -v
            -o "$out_json"
            -of json
        )
    fi

    echo
    echo -e "${YELLOW}[+] Starting ffuf subdomain enumeration on ${BOLD}${domain}${RESET}${YELLOW}...${RESET}"
    print_cmd "${ffuf_cmd[*]}"
    echo

    if ! command -v ffuf &>/dev/null; then
        echo -e "${RED}[!] ffuf not found in PATH. Skipping subdomain enumeration.${RESET}"
        return 1
    fi

    "${ffuf_cmd[@]}" 2>&1 | tee "$out_log"
    echo
    show_ffuf_results "$out_json" "$domain" "$out_log"
    echo -e "${GREEN}[+] ffuf output:${RESET} ${BLUE}$out_json${RESET}"
    echo -e "${GREEN}[+] ffuf log:${RESET} ${BLUE}$out_log${RESET}"
}

TARGET="${1:-}"

if [ -z "$TARGET" ]; then
    read -rp "Enter target IP: " TARGET
fi

if [ -z "$TARGET" ]; then
    echo -e "${RED}[!] No target IP specified.${RESET}"
    exit 1
fi

OUTDIR="oscp_scan_$TARGET"
FULL_SCAN="$OUTDIR/full"
DETAIL_SCAN="$OUTDIR/detail"
UDP_SCAN="$OUTDIR/udp"
UDP_PID=""
UDP_LOG="$OUTDIR/udp.log"
DETECTED_DOMAIN=""
WEB_URL=""

mkdir -p "$OUTDIR"

echo -e "${GREEN}[+] Target:${RESET} $TARGET"
echo -e "${GREEN}[+] Output directory:${RESET} $OUTDIR"
echo

# --- Phase 1: full TCP port scan ---
FULL_CMD=(nmap -p- --min-rate 5000 -oA "$FULL_SCAN" "$TARGET")

echo -e "${YELLOW}[+] Phase 1: full TCP port scan${RESET}"
print_cmd "${FULL_CMD[*]}"
echo

"${FULL_CMD[@]}"

echo
echo -e "${YELLOW}[+] Extracting open TCP ports...${RESET}"

PORTS=$(extract_open_ports "$FULL_SCAN.gnmap" || true)

if [ -z "$PORTS" ]; then
    echo -e "${YELLOW}[!] No open TCP ports found. Skipping detailed TCP scan.${RESET}"
else
    echo -e "${GREEN}[+] Open ports found:${RESET} ${BOLD}$PORTS${RESET}"
fi

echo

# --- Phase 2: optional UDP scan in background ---
if ask_yes_no "Run UDP top-100 scan in background while continuing?"; then
    UDP_CMD=(nmap -sU --top-ports 100 -oA "$UDP_SCAN" "$TARGET")
    echo -e "${YELLOW}[+] Starting UDP scan in background...${RESET}"
    print_cmd "${UDP_CMD[*]}"
    echo -e "${CYAN}    Log: $UDP_LOG${RESET}"
    echo

    (
        "${UDP_CMD[@]}"
    ) >"$UDP_LOG" 2>&1 &
    UDP_PID=$!

    echo -e "${GREEN}[+] UDP scan running (PID ${UDP_PID}). Continuing with other tasks...${RESET}"
    echo
fi

# --- Phase 3: detailed TCP scan (needed before ffuf to grab hostname/domain) ---
if [ -n "$PORTS" ]; then
    DETAIL_CMD=(nmap -sCV -p "$PORTS" -oA "$DETAIL_SCAN" "$TARGET")

    echo -e "${YELLOW}[+] Phase 3: detailed service scan on open ports${RESET}"
    print_cmd "${DETAIL_CMD[*]}"
    echo

    "${DETAIL_CMD[@]}"
    echo

    echo -e "${YELLOW}[+] Extracting hostname/domain from nmap...${RESET}"
    NMAP_SOURCE_FILE="$DETAIL_SCAN.nmap"
    NMAP_DOMAINS=$(extract_domains_from_nmap "$NMAP_SOURCE_FILE" "$TARGET" || true)
    DETECTED_DOMAIN=$(pick_base_domain "$NMAP_DOMAINS" || true)
    WEB_URL=$(extract_web_endpoint "$DETAIL_SCAN.gnmap" "$TARGET" || true)
    print_domain_detection "$NMAP_SOURCE_FILE"
else
    NMAP_SOURCE_FILE="$FULL_SCAN.nmap"
    NMAP_DOMAINS=$(extract_domains_from_nmap "$NMAP_SOURCE_FILE" "$TARGET" || true)
    DETECTED_DOMAIN=$(pick_base_domain "$NMAP_DOMAINS" || true)
    WEB_URL="http://${TARGET}"
    print_domain_detection "$NMAP_SOURCE_FILE"
fi

# --- Phase 4: ffuf subdomain enumeration on detected domain ---
RUN_FFUF=false
DOMAIN=""

if [ -n "$DETECTED_DOMAIN" ]; then
    if ask_yes_no_default_yes "Avviare ffuf sui sottodomini di ${BOLD}${DETECTED_DOMAIN}${RESET}?"; then
        RUN_FFUF=true
        DOMAIN="$DETECTED_DOMAIN"
    fi
elif ask_yes_no "Nessun dominio rilevato. Vuoi comunque lanciare ffuf inserendo il dominio a mano?"; then
    RUN_FFUF=true
    read -rp "$(echo -e "${YELLOW}Inserisci il dominio base (es. target.htb): ${RESET}")" DOMAIN
fi

if [ "$RUN_FFUF" = true ] && [ -n "$DOMAIN" ]; then
    WORDLIST=""
    DEFAULT_WL="$(default_wordlist || true)"
    if [ -n "$DEFAULT_WL" ]; then
        read -rp "$(echo -e "${YELLOW}Wordlist [${DEFAULT_WL}]: ${RESET}")" WORDLIST
        WORDLIST="${WORDLIST:-$DEFAULT_WL}"
    else
        read -rp "$(echo -e "${YELLOW}Percorso wordlist: ${RESET}")" WORDLIST
    fi

    if [ ! -f "$WORDLIST" ]; then
        echo -e "${RED}[!] Wordlist non trovata: $WORDLIST${RESET}"
    else
        FFUF_URL="${WEB_URL:-http://${TARGET}}"
        FFUF_MODE="vhost"
        echo -e "${CYAN}Modalità ffuf:${RESET}"
        echo -e "  ${BOLD}1)${RESET} vhost su ${FFUF_URL} (Host: FUZZ.${DOMAIN})"
        echo -e "  ${BOLD}2)${RESET} DNS diretto (http://FUZZ.${DOMAIN})"
        read -rp "$(echo -e "${YELLOW}Scegli modalità [1]: ${RESET}")" MODE_CHOICE
        MODE_CHOICE="${MODE_CHOICE:-1}"
        if [ "$MODE_CHOICE" = "2" ]; then
            FFUF_MODE="direct"
        fi

        echo
        echo -e "${GREEN}[+] Avvio ffuf su dominio:${RESET} ${BOLD}${DOMAIN}${RESET}"
        run_ffuf_enum "$DOMAIN" "$FFUF_URL" "$WORDLIST" "$FFUF_MODE" || true
    fi
elif [ "$RUN_FFUF" = true ]; then
    echo -e "${YELLOW}[!] Dominio non specificato. ffuf saltato.${RESET}"
fi
echo

# --- Wait for background UDP if still running ---
if [ -n "$UDP_PID" ]; then
    if kill -0 "$UDP_PID" 2>/dev/null; then
        echo -e "${YELLOW}[+] Waiting for background UDP scan to finish...${RESET}"
        wait "$UDP_PID" || true
    fi

    echo -e "${GREEN}[+] UDP scan completed.${RESET}"
    if [ -f "$UDP_SCAN.gnmap" ]; then
        UDP_PORTS=$(awk -F'[/ ]' '
            /Ports:/ {
                for (i = 1; i <= NF; i++) {
                    if ($i ~ /\/open\/udp/) {
                        split($i, p, "/")
                        print p[1]
                    }
                }
            }
        ' "$UDP_SCAN.gnmap" | paste -sd, || true)
        if [ -n "$UDP_PORTS" ]; then
            echo -e "${GREEN}[+] Open UDP ports:${RESET} ${BOLD}$UDP_PORTS${RESET}"
        else
            echo -e "${YELLOW}[!] No open UDP ports in top-100 scan.${RESET}"
        fi
    fi
    echo
fi

# --- Summary ---
echo -e "${GREEN}[+] All tasks completed.${RESET}"
echo
echo -e "${GREEN}[+] Generated files:${RESET}"
echo -e "    ${BLUE}$FULL_SCAN.nmap${RESET}"
echo -e "    ${BLUE}$FULL_SCAN.gnmap${RESET}"
echo -e "    ${BLUE}$FULL_SCAN.xml${RESET}"
if [ -n "$PORTS" ]; then
    echo -e "    ${BLUE}$DETAIL_SCAN.nmap${RESET}"
    echo -e "    ${BLUE}$DETAIL_SCAN.gnmap${RESET}"
    echo -e "    ${BLUE}$DETAIL_SCAN.xml${RESET}"
fi
if [ -f "$OUTDIR/detected_domain.txt" ]; then
    echo -e "    ${BLUE}$OUTDIR/detected_domain.txt${RESET} ${CYAN}($(cat "$OUTDIR/detected_domain.txt"))${RESET}"
fi
if [ -n "$UDP_PID" ]; then
    echo -e "    ${BLUE}$UDP_SCAN.nmap${RESET}"
    echo -e "    ${BLUE}$UDP_SCAN.gnmap${RESET}"
    echo -e "    ${BLUE}$UDP_SCAN.xml${RESET}"
    echo -e "    ${BLUE}$UDP_LOG${RESET}"
fi
for f in "$OUTDIR"/ffuf_*; do
    [ -f "$f" ] && echo -e "    ${BLUE}$f${RESET}"
done
