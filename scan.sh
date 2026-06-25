#!/bin/bash

# OSCP-style scan helper: TCP full → optional UDP (background) + ffuf subdomains → detail scan
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
    local found=0

    if [ ! -s "$json_file" ]; then
        echo -e "${RED}[!] No ffuf output file or empty results.${RESET}"
        return 0
    fi

    echo -e "${GREEN}[+] Subdomains / vhosts found:${RESET}"
    if command -v jq &>/dev/null; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            echo -e "    ${BOLD}${MAGENTA}$line${RESET}"
            found=1
        done < <(jq -r '.results[] | "\(.input.FUZZ // .input["FUZZ"]) [\(.status)] \(.length)b"' "$json_file" 2>/dev/null)
    else
        while IFS= read -r subdomain; do
            [ -z "$subdomain" ] && continue
            echo -e "    ${BOLD}${MAGENTA}$subdomain${RESET}"
            found=1
        done < <(grep -o '"FUZZ":"[^"]*"' "$json_file" | cut -d'"' -f4 | sort -u)
    fi

    if [ "$found" -eq 0 ]; then
        echo -e "    ${YELLOW}(none)${RESET}"
    fi
}

run_ffuf_enum() {
    local domain="$1"
    local ffuf_target="$2"
    local wordlist="$3"
    local mode="$4"
    local out_json="$OUTDIR/ffuf_${domain//./_}.json"
    local ffuf_cmd=()

    if [ "$mode" = "vhost" ]; then
        ffuf_cmd=(
            ffuf
            -w "$wordlist"
            -u "http://${ffuf_target}"
            -H "Host: FUZZ.${domain}"
            -mc 200,301,302,403
            -t 40
            -o "$out_json"
            -of json
        )
    else
        ffuf_cmd=(
            ffuf
            -w "$wordlist"
            -u "http://FUZZ.${domain}"
            -mc 200,301,302,403
            -t 40
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

    "${ffuf_cmd[@]}"
    echo
    show_ffuf_results "$out_json"
    echo -e "${GREEN}[+] ffuf output:${RESET} ${BLUE}$out_json${RESET}"
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

# --- Phase 3: optional ffuf subdomain enumeration (parallel to UDP) ---
if ask_yes_no "Run ffuf third-level subdomain enumeration while scans continue?"; then
    DOMAIN=""
    read -rp "$(echo -e "${YELLOW}Enter base domain (e.g. target.htb): ${RESET}")" DOMAIN

    if [ -n "$DOMAIN" ]; then
        WORDLIST=""
        DEFAULT_WL="$(default_wordlist || true)"
        if [ -n "$DEFAULT_WL" ]; then
            read -rp "$(echo -e "${YELLOW}Wordlist path [${DEFAULT_WL}]: ${RESET}")" WORDLIST
            WORDLIST="${WORDLIST:-$DEFAULT_WL}"
        else
            read -rp "$(echo -e "${YELLOW}Wordlist path: ${RESET}")" WORDLIST
        fi

        if [ ! -f "$WORDLIST" ]; then
            echo -e "${RED}[!] Wordlist not found: $WORDLIST${RESET}"
        else
            FFUF_MODE="vhost"
            echo -e "${CYAN}ffuf mode:${RESET}"
            echo -e "  ${BOLD}1)${RESET} vhost on IP ${TARGET} (Host: FUZZ.${DOMAIN})"
            echo -e "  ${BOLD}2)${RESET} direct DNS (http://FUZZ.${DOMAIN})"
            read -rp "$(echo -e "${YELLOW}Choose mode [1]: ${RESET}")" MODE_CHOICE
            MODE_CHOICE="${MODE_CHOICE:-1}"
            if [ "$MODE_CHOICE" = "2" ]; then
                FFUF_MODE="direct"
            fi

            run_ffuf_enum "$DOMAIN" "$TARGET" "$WORDLIST" "$FFUF_MODE" || true
        fi
    else
        echo -e "${YELLOW}[!] No domain provided. Skipping ffuf.${RESET}"
    fi
    echo
fi

# --- Phase 4: detailed TCP scan on open ports ---
if [ -n "$PORTS" ]; then
    DETAIL_CMD=(nmap -sCV -p "$PORTS" -oA "$DETAIL_SCAN" "$TARGET")

    echo -e "${YELLOW}[+] Phase 4: detailed service scan on open ports${RESET}"
    print_cmd "${DETAIL_CMD[*]}"
    echo

    "${DETAIL_CMD[@]}"
    echo
fi

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
if [ -n "$UDP_PID" ]; then
    echo -e "    ${BLUE}$UDP_SCAN.nmap${RESET}"
    echo -e "    ${BLUE}$UDP_SCAN.gnmap${RESET}"
    echo -e "    ${BLUE}$UDP_SCAN.xml${RESET}"
    echo -e "    ${BLUE}$UDP_LOG${RESET}"
fi
for f in "$OUTDIR"/ffuf_*.json; do
    [ -f "$f" ] && echo -e "    ${BLUE}$f${RESET}"
done
