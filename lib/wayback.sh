#!/usr/bin/env bash
# wayback.sh — Multi-source historical URL fetcher
# Sources: Wayback Machine CDX + OTX AlienVault + VirusTotal (if VT_API_KEY set)
#
# Usage: ./lib/wayback.sh <domain> [--no-subs] [--limit N] [--timeout N]

set -euo pipefail

DOMAIN="${1:?Usage: wayback.sh <domain> [--no-subs] [--limit N] [--timeout N]}"
shift

NO_SUBS=false
LIMIT=""
TIMEOUT=120

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-subs) NO_SUBS=true; shift ;;
        --limit) LIMIT="&limit=$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        *) echo "Unknown flag: $1" >&2; exit 1 ;;
    esac
done

if [[ "$NO_SUBS" == "true" ]]; then
    URL_PREFIX=""
else
    URL_PREFIX="*."
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Source 1: Wayback Machine CDX API
CDX_URL="https://web.archive.org/cdx/search/cdx?url=${URL_PREFIX}${DOMAIN}/*&output=text&fl=original&collapse=urlkey${LIMIT}"
curl -s --max-time "$TIMEOUT" "$CDX_URL" >> "$TMPDIR/all.txt" 2>/dev/null &
PID_WB=$!

# Source 2: OTX AlienVault (paginated, max 500 per page)
(
    page=1
    has_next=true
    while [[ "$has_next" == "true" ]]; do
        resp=$(curl -s --max-time 30 "https://otx.alienvault.com/api/v1/indicators/domain/${DOMAIN}/url_list?limit=500&page=${page}" 2>/dev/null)
        echo "$resp" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for u in d.get('url_list', []):
        print(u.get('url', ''))
except: pass
" >> "$TMPDIR/all.txt"
        has_next=$(echo "$resp" | python3 -c "import sys,json; print(str(json.load(sys.stdin).get('has_next',False)).lower())" 2>/dev/null || echo "false")
        page=$((page + 1))
        if [[ $page -gt 20 ]]; then break; fi
    done
) &
PID_OTX=$!

# Source 3: VirusTotal API v3 (set VT_API_KEY env var)
if [[ -n "${VT_API_KEY:-}" ]]; then
    curl -s --max-time 30 -H "x-apikey: ${VT_API_KEY}" \
        "https://www.virustotal.com/api/v3/domains/${DOMAIN}/urls?limit=40" 2>/dev/null \
        | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for item in d.get('data', []):
        url = item.get('attributes', {}).get('url', '')
        if url: print(url)
except: pass
" >> "$TMPDIR/all.txt" &
    PID_VT=$!
fi

# Wait for all sources
wait "$PID_WB" 2>/dev/null || true
wait "$PID_OTX" 2>/dev/null || true
[[ -n "${PID_VT:-}" ]] && wait "$PID_VT" 2>/dev/null || true

# Dedupe and output
sort -u "$TMPDIR/all.txt" | grep -v '^$' || true
