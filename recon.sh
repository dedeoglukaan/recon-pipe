#!/usr/bin/env bash
# recon-pipe — Automated recon pipeline for bug bounty targets.
# 7 phases: subdomain enum → DNS → port scan → crawl → path check → cloud → secrets → takeover
#
# Usage:
#   ./recon.sh <target> --domains "d1.com d2.com" [options]
#
# Options:
#   --domains "d1.com d2.com"   Target domains (required)
#   --output DIR                Output directory (default: ./output/<target>)
#   --proxy URL                 HTTP proxy for crawling (e.g. http://127.0.0.1:8080)
#   --skip-phase N              Skip phase N (repeatable)
#   --github-org NAME           GitHub org for TruffleHog secret scan
#   --cookie "session=..."      Session cookie for authenticated crawling
#   --rate-limit N              Requests/sec for HTTP tools (default: 30)
#   --header "Name: Value"      Custom header for all HTTP requests
#   --no-port-scan              Disable port scanning
#   --no-brute-force            Disable subdomain permutation brute-force
#   --skip-wayback              Skip Wayback Machine / historical URL sources
#   --config FILE               Load settings from config file
#   --force                     Re-run phases even if output exists
#   --dry-run                   Print commands without executing

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESOLVERS_URL="https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

FAILED_SOURCES=()

# --- Argument parsing ---

TARGET=""
DOMAINS=""
OUTPUT_DIR=""
PROXY=""
SKIP_PHASES=()
GITHUB_ORG=""
COOKIE=""
RATE_LIMIT=30
HEADER=""
PORT_SCAN=true
BRUTE_FORCE=true
SKIP_WAYBACK=false
CONFIG_FILE=""
FORCE=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --domains) DOMAINS="$2"; shift 2 ;;
        --output) OUTPUT_DIR="$2"; shift 2 ;;
        --proxy) PROXY="$2"; shift 2 ;;
        --skip-phase) SKIP_PHASES+=("$2"); shift 2 ;;
        --github-org) GITHUB_ORG="$2"; shift 2 ;;
        --cookie) COOKIE="$2"; shift 2 ;;
        --rate-limit) RATE_LIMIT="$2"; shift 2 ;;
        --header) HEADER="$2"; shift 2 ;;
        --no-port-scan) PORT_SCAN=false; shift ;;
        --no-brute-force) BRUTE_FORCE=false; shift ;;
        --skip-wayback) SKIP_WAYBACK=true; shift ;;
        --config) CONFIG_FILE="$2"; shift 2 ;;
        --force) FORCE=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        -*) echo "Unknown option: $1"; exit 1 ;;
        *) TARGET="$1"; shift ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target> --domains \"example.com\" [options]"
    echo "Run '$0 --help' for details."
    exit 1
fi

# --- Load config file ---

if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
    parse_conf() {
        local key="$1" default="$2"
        local val
        val=$(grep -oP "^${key}\s*=\s*\K.*" "$CONFIG_FILE" | tr -d ' "'"'" | head -1)
        echo "${val:-$default}"
    }

    cfg_rate=$(parse_conf "rate_limit" "")
    cfg_org=$(parse_conf "github_org" "")
    cfg_proxy=$(parse_conf "proxy" "")
    cfg_port=$(parse_conf "port_scan" "true")
    cfg_brute=$(parse_conf "brute_force" "true")
    cfg_wayback=$(parse_conf "skip_wayback" "false")
    cfg_skip=$(parse_conf "skip_phases" "")

    [[ -n "$cfg_rate" && "$RATE_LIMIT" == "30" ]] && RATE_LIMIT="$cfg_rate"
    [[ -n "$cfg_org" && -z "$GITHUB_ORG" ]] && GITHUB_ORG="$cfg_org"
    [[ -n "$cfg_proxy" && -z "$PROXY" ]] && PROXY="$cfg_proxy"
    [[ "$cfg_port" == "false" ]] && PORT_SCAN=false
    [[ "$cfg_brute" == "false" ]] && BRUTE_FORCE=false
    [[ "$cfg_wayback" == "true" ]] && SKIP_WAYBACK=true

    if [[ -n "$cfg_skip" ]]; then
        for phase in $(echo "$cfg_skip" | tr ',' ' '); do
            SKIP_PHASES+=("$phase")
        done
    fi
fi

# --- Input validation ---

validate_safe() {
    local label="$1" value="$2"
    if [[ "$value" =~ [\'\"\`\$\(\)\|\&\\] ]]; then
        echo -e "${RED}ERROR: Unsafe characters in $label${NC}"
        exit 1
    fi
}

validate_domain() {
    local d="$1"
    if [[ ! "$d" =~ ^(\*\.)?[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}ERROR: Invalid domain: $d${NC}"
        exit 1
    fi
}

validate_safe "target" "$TARGET"
[[ -n "$COOKIE" ]] && validate_safe "cookie" "$COOKIE"
[[ -n "$HEADER" ]] && validate_safe "header" "$HEADER"
[[ -n "$GITHUB_ORG" ]] && validate_safe "github-org" "$GITHUB_ORG"

if [[ -z "$DOMAINS" ]]; then
    echo -e "${RED}ERROR: No domains provided. Use --domains \"example.com api.example.com\"${NC}"
    exit 1
fi

read -ra DOMAIN_LIST <<< "$DOMAINS"
for d in "${DOMAIN_LIST[@]}"; do
    validate_domain "$d"
done

# --- Output directory ---

RECON_DIR="${OUTPUT_DIR:-./output/$TARGET}"
mkdir -p "$RECON_DIR"

# --- Proxy flag ---

PROXY_FLAG=""
if [[ -n "$PROXY" ]]; then
    PROXY_FLAG="-proxy '$PROXY'"
fi

HEADER_FLAG=""
if [[ -n "$HEADER" ]]; then
    HEADER_FLAG="-H '$HEADER'"
fi

# --- Helper functions ---

log() { echo -e "${CYAN}[recon]${NC} $*"; }
ok()  { echo -e "${GREEN}[recon]${NC} $*"; }
warn(){ echo -e "${YELLOW}[recon]${NC} $*"; }
err() { echo -e "${RED}[recon]${NC} $*"; }

should_skip() {
    local phase="$1"
    for sp in "${SKIP_PHASES[@]:-}"; do
        [[ "$sp" == "$phase" ]] && return 0
    done
    return 1
}

file_exists_skip() {
    local file="$1" label="$2"
    if [[ -f "$file" && "$FORCE" != "true" ]]; then
        warn "$label: output exists ($file), skipping. Use --force to re-run."
        return 0
    fi
    return 1
}

count_lines() {
    [[ -f "$1" ]] && wc -l < "$1" || echo 0
}

run_cmd() {
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "  [dry-run] $*"
        return 0
    fi
    "$@"
}

# --- Summary tracking ---

declare -A PHASE_STATUS
TOTAL_SUBS=0
TOTAL_RESOLVED=0
TOTAL_LIVE=0
TOTAL_PORTS=0
TOTAL_PATHS=0
TOTAL_SECRETS=0
TOTAL_TAKEOVERS=0

# ============================================================
# PHASE 1: Subdomain Enumeration
# ============================================================

phase1_subdomain_enum() {
    if should_skip 1; then log "Phase 1 skipped (--skip-phase)"; PHASE_STATUS[1]="skipped"; return; fi
    log "Phase 1: Subdomain Enumeration — ${#DOMAIN_LIST[@]} domain(s)"

    ALL_SUBS="$RECON_DIR/all-subs.txt"
    touch "$ALL_SUBS"

    for domain in "${DOMAIN_LIST[@]}"; do
        log "  Enumerating: $domain"

        # subfinder
        local sf_out="$RECON_DIR/subs-subfinder-${domain}.txt"
        if ! file_exists_skip "$sf_out" "subfinder/$domain"; then
            if command -v subfinder &>/dev/null; then
                log "    subfinder..."
                run_cmd subfinder -d "$domain" -all -silent -o "$sf_out" 2>/dev/null || true
                ok "    subfinder: $(count_lines "$sf_out") subdomains"
            else
                warn "    subfinder not installed, skipping"
            fi
        fi
        [[ -f "$sf_out" ]] && cat "$sf_out" >> "$ALL_SUBS"

        # crt.sh (with health check)
        local crt_out="$RECON_DIR/subs-crtsh-${domain}.txt"
        if ! file_exists_skip "$crt_out" "crt.sh/$domain"; then
            log "    crt.sh..."
            local crt_status
            crt_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://crt.sh/?q=example.com&output=json" 2>/dev/null || echo "000")
            if [[ "$crt_status" == "200" ]]; then
                run_cmd bash -c "curl -s --max-time 30 'https://crt.sh/?q=%25.${domain}&output=json' 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u > '$crt_out'" || true
                ok "    crt.sh: $(count_lines "$crt_out") entries"
            else
                warn "    crt.sh: UNAVAILABLE (HTTP $crt_status) — skipping"
                FAILED_SOURCES+=("crt.sh")
            fi
        fi
        [[ -f "$crt_out" ]] && cat "$crt_out" >> "$ALL_SUBS"

        # amass (passive mode)
        local amass_out="$RECON_DIR/subs-amass-${domain}.txt"
        if ! file_exists_skip "$amass_out" "amass/$domain"; then
            if command -v amass &>/dev/null; then
                log "    amass..."
                run_cmd bash -c "amass enum -passive -d '$domain' -timeout 5 2>/dev/null | sort -u > '$amass_out'" || true
                ok "    amass: $(count_lines "$amass_out") subdomains"
            else
                warn "    amass not installed, skipping"
            fi
        fi
        [[ -f "$amass_out" ]] && cat "$amass_out" >> "$ALL_SUBS"

        # certspotter (crt.sh alternative)
        local cs_out="$RECON_DIR/subs-certspotter-${domain}.txt"
        if ! file_exists_skip "$cs_out" "certspotter/$domain"; then
            log "    certspotter..."
            run_cmd bash -c "curl -s --max-time 20 'https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=true&expand=dns_names' 2>/dev/null | jq -r '.[].dns_names[]' 2>/dev/null | sed 's/\*\.//g' | sort -u > '$cs_out'" || true
            ok "    certspotter: $(count_lines "$cs_out") entries"
        fi
        [[ -f "$cs_out" ]] && cat "$cs_out" >> "$ALL_SUBS"

        # wayback (subdomain extraction)
        local wb_out="$RECON_DIR/subs-wayback-${domain}.txt"
        if [[ "$SKIP_WAYBACK" == "true" ]]; then
            warn "    wayback: skipped (--skip-wayback)"
        elif ! file_exists_skip "$wb_out" "wayback/$domain"; then
            log "    wayback..."
            if [[ -f "$SCRIPT_DIR/lib/wayback.sh" ]]; then
                run_cmd bash -c "$SCRIPT_DIR/lib/wayback.sh '$domain' 2>/dev/null | grep -oP '^https?://([^/]+)' | sed 's|https\?://||' | sort -u > '$wb_out'" || true
            else
                run_cmd bash -c "curl -s --max-time 60 'https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=text&fl=original&collapse=urlkey' 2>/dev/null | grep -oP '^https?://([^/]+)' | sed 's|https\?://||' | sort -u > '$wb_out'" || true
            fi
            ok "    wayback: $(count_lines "$wb_out") hosts"
        fi
        [[ -f "$wb_out" ]] && cat "$wb_out" >> "$ALL_SUBS"

        # Add the domain itself
        echo "$domain" >> "$ALL_SUBS"
        echo "www.$domain" >> "$ALL_SUBS"
    done

    # Deduplicate
    sort -u "$ALL_SUBS" -o "$ALL_SUBS"
    TOTAL_SUBS=$(count_lines "$ALL_SUBS")

    # Source summary
    local src_count=0
    local src_total=0
    for src_file in "$RECON_DIR"/subs-*-*.txt; do
        [[ -f "$src_file" ]] && src_total=$((src_total + 1))
        [[ -f "$src_file" && $(count_lines "$src_file") -gt 0 ]] && src_count=$((src_count + 1))
    done
    local fail_msg=""
    if [[ ${#FAILED_SOURCES[@]} -gt 0 ]]; then
        fail_msg=" (failed: ${FAILED_SOURCES[*]})"
    fi
    ok "Phase 1A: $TOTAL_SUBS unique subdomains from $src_count/$src_total sources${fail_msg}"

    # Permutation brute-force (only if >5 subs found and config allows)
    if [[ $TOTAL_SUBS -gt 5 && "$BRUTE_FORCE" == "true" ]]; then
        local perm_out="$RECON_DIR/permutations.txt"
        local perm_resolved="$RECON_DIR/perm-resolved.txt"
        if ! file_exists_skip "$perm_resolved" "permutations"; then
            if command -v alterx &>/dev/null; then
                log "  alterx permutations..."
                run_cmd bash -c "cat '$ALL_SUBS' | alterx -enrich -limit 100000 -silent > '$perm_out' 2>/dev/null" || true

                if [[ -f "$perm_out" && $(count_lines "$perm_out") -gt 0 ]]; then
                    # Fresh resolvers
                    local resolvers="$RECON_DIR/resolvers.txt"
                    if [[ ! -f "$resolvers" || "$FORCE" == "true" ]]; then
                        wget -q "$RESOLVERS_URL" -O "$resolvers" 2>/dev/null || true
                    fi

                    if [[ -f "$resolvers" ]] && command -v shuffledns &>/dev/null; then
                        for domain in "${DOMAIN_LIST[@]}"; do
                            log "    shuffledns $domain..."
                            run_cmd shuffledns -d "$domain" -list "$perm_out" -r "$resolvers" -silent >> "$perm_resolved" 2>/dev/null || true
                        done
                        ok "  Permutations resolved: $(count_lines "$perm_resolved")"
                        [[ -f "$perm_resolved" ]] && cat "$perm_resolved" >> "$ALL_SUBS"
                        sort -u "$ALL_SUBS" -o "$ALL_SUBS"
                        TOTAL_SUBS=$(count_lines "$ALL_SUBS")
                    fi
                fi
            else
                warn "  alterx not installed, skipping permutations"
            fi
        fi
    fi

    # DNS resolution + wildcard filtering
    local resolved="$RECON_DIR/resolved.txt"
    local cnames="$RECON_DIR/cnames.txt"
    if ! file_exists_skip "$resolved" "DNS resolution"; then
        if command -v dnsx &>/dev/null; then
            log "  dnsx resolution (wildcard-filtered)..."
            for domain in "${DOMAIN_LIST[@]}"; do
                run_cmd bash -c "cat '$ALL_SUBS' | grep '${domain}$' | dnsx -silent -a -resp -wd '$domain' 2>/dev/null >> '$resolved'" || true
            done
            sort -u "$resolved" -o "$resolved" 2>/dev/null || true
            TOTAL_RESOLVED=$(count_lines "$resolved")
            ok "  Resolved: $TOTAL_RESOLVED hosts"

            log "  CNAME records..."
            run_cmd bash -c "cat '$ALL_SUBS' | dnsx -silent -cname -resp > '$cnames' 2>/dev/null" || true
            ok "  CNAMEs: $(count_lines "$cnames")"
        else
            warn "  dnsx not installed — using basic resolution"
            run_cmd bash -c "cat '$ALL_SUBS' | while read -r sub; do host \"\$sub\" 2>/dev/null | grep -q 'has address' && echo \"\$sub\"; done > '$resolved'" || true
            TOTAL_RESOLVED=$(count_lines "$resolved")
            ok "  Resolved (basic): $TOTAL_RESOLVED hosts"
        fi
    else
        TOTAL_RESOLVED=$(count_lines "$resolved")
    fi

    PHASE_STATUS[1]="done"
    ok "Phase 1 complete: $TOTAL_SUBS subs, $TOTAL_RESOLVED resolved"
}

# ============================================================
# PHASE 2: Port Scan + HTTP Fingerprinting
# ============================================================

phase2_portscan_probe() {
    if should_skip 2; then log "Phase 2 skipped"; PHASE_STATUS[2]="skipped"; return; fi
    log "Phase 2: Port Scan + HTTP Probe"

    local resolved="$RECON_DIR/resolved.txt"
    if [[ ! -f "$resolved" ]]; then
        warn "Phase 2: No resolved.txt — run Phase 1 first"
        PHASE_STATUS[2]="skipped"
        return
    fi

    # Filter CDN hosts for port scanning
    local direct="$RECON_DIR/non-cdn-hosts.txt"
    if ! file_exists_skip "$direct" "CDN filter"; then
        if command -v httpx &>/dev/null; then
            log "  Filtering CDN hosts..."
            run_cmd bash -c "cat '$resolved' | awk '{print \$1}' | httpx -fcdn cloudflare,cloudfront,akamai,fastly,incapsula -silent > '$direct' 2>/dev/null" || true
            ok "  Non-CDN hosts: $(count_lines "$direct")"
        else
            cp "$resolved" "$direct"
        fi
    fi

    # Port scan (non-CDN only, if config allows)
    local ports="$RECON_DIR/ports.txt"
    if [[ "$PORT_SCAN" != "true" ]]; then
        warn "  Port scan disabled (--no-port-scan)"
        touch "$ports"
    elif ! file_exists_skip "$ports" "Port scan"; then
        if [[ -f "$direct" && $(count_lines "$direct") -gt 0 ]]; then
            if command -v naabu &>/dev/null; then
                log "  naabu port scan (top 1000)..."
                run_cmd naabu -list "$direct" -top-ports 1000 -ec -rate 3000 -silent -o "$ports" 2>/dev/null || true
                TOTAL_PORTS=$(count_lines "$ports")
                ok "  Ports found: $TOTAL_PORTS"
            else
                warn "  naabu not installed, skipping port scan"
                touch "$ports"
            fi
        else
            warn "  No non-CDN hosts to port scan"
            touch "$ports"
        fi
    else
        TOTAL_PORTS=$(count_lines "$ports")
    fi

    # HTTP probing
    local probe_input="$RECON_DIR/_probe-input.txt"
    cat "$resolved" | awk '{print $1}' > "$probe_input" 2>/dev/null
    [[ -f "$ports" ]] && cat "$ports" >> "$probe_input" 2>/dev/null
    sort -u "$probe_input" -o "$probe_input"

    local httpx_json="$RECON_DIR/httpx-recon.json"
    local httpx_txt="$RECON_DIR/httpx-recon.txt"
    if ! file_exists_skip "$httpx_json" "HTTP probe"; then
        if command -v httpx &>/dev/null; then
            log "  httpx fingerprinting (rate: ${RATE_LIMIT}/s)..."
            local header_args=""
            [[ -n "$HEADER" ]] && header_args="-H '$HEADER'"

            run_cmd bash -c "cat '$probe_input' | httpx -sc -title -td -server -favicon -cdn -ip -asn -follow-redirects -rl $RATE_LIMIT $header_args -json -o '$httpx_json' 2>/dev/null" || true
            run_cmd bash -c "cat '$probe_input' | httpx -sc -title -td -server -cdn -follow-redirects -rl $RATE_LIMIT $header_args -o '$httpx_txt' 2>/dev/null" || true
            TOTAL_LIVE=$(count_lines "$httpx_txt")
            ok "  Live HTTP hosts: $TOTAL_LIVE"
        else
            warn "  httpx not installed, skipping HTTP probe"
        fi
    else
        TOTAL_LIVE=$(count_lines "$httpx_txt")
    fi

    rm -f "$probe_input"
    PHASE_STATUS[2]="done"
    ok "Phase 2 complete: $TOTAL_LIVE live hosts, $TOTAL_PORTS port entries"
}

# ============================================================
# PHASE 3: Crawling + Historical URLs
# ============================================================

phase3_crawl() {
    if should_skip 3; then log "Phase 3 skipped"; PHASE_STATUS[3]="skipped"; return; fi
    log "Phase 3: Crawling + Historical URLs"

    local header_args=""
    [[ -n "$HEADER" ]] && header_args="-H '$HEADER'"

    for domain in "${DOMAIN_LIST[@]}"; do
        # Unauthenticated crawl
        local crawl_out="$RECON_DIR/crawl-${domain}.txt"
        if ! file_exists_skip "$crawl_out" "katana/$domain"; then
            if command -v katana &>/dev/null; then
                log "  katana crawl: $domain..."
                run_cmd bash -c "katana -u 'https://$domain' -jc -kf all -d 5 -ef css,png,jpg,gif,svg,woff,woff2,ttf,ico -rl $RATE_LIMIT $PROXY_FLAG $header_args -silent -o '$crawl_out' 2>/dev/null" || true
                ok "    URLs: $(count_lines "$crawl_out")"
            else
                warn "  katana not installed, skipping crawl"
            fi
        fi

        # Authenticated crawl (if cookie provided)
        if [[ -n "$COOKIE" ]]; then
            local crawl_auth="$RECON_DIR/crawl-auth-${domain}.txt"
            if ! file_exists_skip "$crawl_auth" "katana-auth/$domain"; then
                if command -v katana &>/dev/null; then
                    log "  katana authenticated crawl: $domain..."
                    run_cmd bash -c "katana -u 'https://$domain' -H 'Cookie: $COOKIE' -jc -kf all -d 5 -ef css,png,jpg,gif,svg,woff,woff2,ttf,ico -rl $RATE_LIMIT $PROXY_FLAG $header_args -silent -o '$crawl_auth' 2>/dev/null" || true
                    ok "    Auth URLs: $(count_lines "$crawl_auth")"
                fi
            fi
        fi

        # Wayback full URLs
        local wb_urls="$RECON_DIR/wayback-${domain}.txt"
        if [[ "$SKIP_WAYBACK" == "true" ]]; then
            warn "  wayback URLs: skipped (--skip-wayback)"
        elif ! file_exists_skip "$wb_urls" "wayback-urls/$domain"; then
            log "  wayback URLs: $domain..."
            if [[ -f "$SCRIPT_DIR/lib/wayback.sh" ]]; then
                run_cmd bash -c "$SCRIPT_DIR/lib/wayback.sh '$domain' > '$wb_urls' 2>/dev/null" || true
            else
                run_cmd bash -c "curl -s --max-time 120 'https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=text&fl=original&collapse=urlkey' > '$wb_urls' 2>/dev/null" || true
            fi
            ok "    Wayback URLs: $(count_lines "$wb_urls")"
        fi
    done

    # Filter interesting wayback URLs
    local wb_all="$RECON_DIR/wayback-all.txt"
    local wb_interesting="$RECON_DIR/wayback-interesting.txt"
    cat "$RECON_DIR"/wayback-*.txt 2>/dev/null | sort -u > "$wb_all" 2>/dev/null || true
    grep -iE "(api|admin|internal|debug|staging|config|backup|test|swagger|graphql|actuator)" "$wb_all" > "$wb_interesting" 2>/dev/null || true

    if [[ -f "$wb_interesting" && $(count_lines "$wb_interesting") -gt 0 ]]; then
        ok "  Interesting wayback URLs: $(count_lines "$wb_interesting")"
    fi

    PHASE_STATUS[3]="done"
    ok "Phase 3 complete"
}

# ============================================================
# PHASE 4: Standard Path Checks
# ============================================================

phase4_paths() {
    if should_skip 4; then log "Phase 4 skipped"; PHASE_STATUS[4]="skipped"; return; fi
    log "Phase 4: Standard Path Checks"

    local httpx_txt="$RECON_DIR/httpx-recon.txt"
    local path_out="$RECON_DIR/path-check.txt"

    if file_exists_skip "$path_out" "Path checks"; then
        TOTAL_PATHS=$(count_lines "$path_out")
        PHASE_STATUS[4]="done"
        return
    fi

    if ! command -v httpx &>/dev/null; then
        warn "  httpx not installed, skipping path checks"
        PHASE_STATUS[4]="skipped"
        return
    fi

    # Build URL list from live hosts
    local live_hosts="$RECON_DIR/_live-urls.txt"
    if [[ -f "$httpx_txt" ]]; then
        awk '{print $1}' "$httpx_txt" | sort -u > "$live_hosts"
    else
        for domain in "${DOMAIN_LIST[@]}"; do
            echo "https://$domain"
        done > "$live_hosts"
    fi

    local paths=(
        robots.txt sitemap.xml .well-known/security.txt
        swagger.json openapi.json api-docs api/docs
        graphql graphiql playground
        .git/HEAD .env .env.local .env.production
        debug health status
        actuator actuator/env actuator/health actuator/configprops
        server-status server-info
        elmah.axd trace metrics prometheus
        _debug_toolbar phpinfo.php info.php
        wp-json/wp/v2/users
        crossdomain.xml clientaccesspolicy.xml
    )

    local path_urls="$RECON_DIR/_path-urls.txt"
    > "$path_urls"
    while IFS= read -r host; do
        host="${host%/}"
        for path in "${paths[@]}"; do
            echo "$host/$path" >> "$path_urls"
        done
    done < "$live_hosts"

    local header_args=""
    [[ -n "$HEADER" ]] && header_args="-H '$HEADER'"

    log "  Checking $(count_lines "$path_urls") URLs..."
    run_cmd bash -c "cat '$path_urls' | httpx -sc -cl -title -follow-redirects -silent -mc 200,301,302,403 -rl $RATE_LIMIT $header_args -o '$path_out' 2>/dev/null" || true

    TOTAL_PATHS=$(count_lines "$path_out")
    rm -f "$live_hosts" "$path_urls"

    PHASE_STATUS[4]="done"
    ok "Phase 4 complete: $TOTAL_PATHS accessible paths"
}

# ============================================================
# PHASE 5: Cloud/Infra Recon (Shodan via uncover)
# ============================================================

phase5_cloud() {
    if should_skip 5; then log "Phase 5 skipped"; PHASE_STATUS[5]="skipped"; return; fi
    log "Phase 5: Cloud & Infrastructure Recon"

    local shodan_out="$RECON_DIR/shodan-results.txt"

    if file_exists_skip "$shodan_out" "Shodan/uncover"; then
        PHASE_STATUS[5]="done"
        return
    fi

    if ! command -v uncover &>/dev/null; then
        warn "  uncover not installed, skipping"
        PHASE_STATUS[5]="skipped"
        return
    fi

    > "$shodan_out"
    for domain in "${DOMAIN_LIST[@]}"; do
        log "  uncover: ssl:\"$domain\"..."
        run_cmd bash -c "echo 'ssl:\"$domain\"' | uncover -e shodan -silent >> '$shodan_out' 2>/dev/null" || true
    done

    if [[ $(count_lines "$shodan_out") -gt 0 ]]; then
        local shodan_live="$RECON_DIR/shodan-live.txt"
        log "  Probing Shodan results..."
        run_cmd bash -c "cat '$shodan_out' | sort -u | httpx -sc -title -td -silent -rl $RATE_LIMIT -o '$shodan_live' 2>/dev/null" || true
        ok "  Shodan live: $(count_lines "$shodan_live")"
    fi

    PHASE_STATUS[5]="done"
    ok "Phase 5 complete: $(count_lines "$shodan_out") Shodan entries"
}

# ============================================================
# PHASE 6: Secret Scanning (TruffleHog)
# ============================================================

phase6_secrets() {
    if should_skip 6; then log "Phase 6 skipped"; PHASE_STATUS[6]="skipped"; return; fi
    log "Phase 6: Secret Scanning"

    local secrets_out="$RECON_DIR/secrets.json"

    if file_exists_skip "$secrets_out" "TruffleHog"; then
        PHASE_STATUS[6]="done"
        return
    fi

    if [[ -z "$GITHUB_ORG" ]]; then
        warn "  No --github-org provided, skipping TruffleHog"
        PHASE_STATUS[6]="skipped"
        return
    fi

    if ! command -v trufflehog &>/dev/null; then
        warn "  trufflehog not installed, skipping"
        PHASE_STATUS[6]="skipped"
        return
    fi

    log "  trufflehog: GitHub org '$GITHUB_ORG' (verified only)..."
    run_cmd trufflehog github --org="$GITHUB_ORG" --only-verified --json > "$secrets_out" 2>/dev/null || true

    TOTAL_SECRETS=$(python3 -c "
import json, sys
count = 0
with open(sys.argv[1]) as f:
    for line in f:
        try:
            json.loads(line)
            count += 1
        except: pass
print(count)
" "$secrets_out" 2>/dev/null || echo 0)

    PHASE_STATUS[6]="done"
    ok "Phase 6 complete: $TOTAL_SECRETS verified secrets"
}

# ============================================================
# PHASE 7: Subdomain Takeover Check
# ============================================================

phase7_takeover() {
    if should_skip 7; then log "Phase 7 skipped"; PHASE_STATUS[7]="skipped"; return; fi
    log "Phase 7: Subdomain Takeover Check"

    local takeover_out="$RECON_DIR/takeovers.txt"
    local all_subs="$RECON_DIR/all-subs.txt"

    if file_exists_skip "$takeover_out" "Takeover check"; then
        PHASE_STATUS[7]="done"
        return
    fi

    if [[ ! -f "$all_subs" ]]; then
        warn "  No all-subs.txt — run Phase 1 first"
        PHASE_STATUS[7]="skipped"
        return
    fi

    if ! command -v nuclei &>/dev/null; then
        warn "  nuclei not installed, skipping takeover check"
        PHASE_STATUS[7]="skipped"
        return
    fi

    log "  nuclei takeover templates..."
    run_cmd bash -c "cat '$all_subs' | nuclei -tags takeover -silent -rl $RATE_LIMIT -o '$takeover_out' 2>/dev/null" || true

    # Also check dangling CNAMEs
    local cnames="$RECON_DIR/cnames.txt"
    local dangling="$RECON_DIR/dangling-cnames.txt"
    if [[ -f "$cnames" ]]; then
        log "  Checking dangling CNAMEs..."
        > "$dangling"
        while IFS= read -r line; do
            local cname_target
            cname_target=$(echo "$line" | awk '{print $NF}')
            if ! host "$cname_target" >/dev/null 2>&1; then
                echo "DANGLING: $line" >> "$dangling"
            fi
        done < "$cnames"
        if [[ $(count_lines "$dangling") -gt 0 ]]; then
            ok "  Dangling CNAMEs: $(count_lines "$dangling")"
        fi
    fi

    TOTAL_TAKEOVERS=$(count_lines "$takeover_out")
    PHASE_STATUS[7]="done"
    ok "Phase 7 complete: $TOTAL_TAKEOVERS takeover candidates"
}

# ============================================================
# SUMMARY
# ============================================================

print_summary() {
    echo ""
    echo -e "${CYAN}=== Recon Pipeline Complete ===${NC}"
    echo "Target:           $TARGET"
    echo "Domains:          ${#DOMAIN_LIST[@]} (${DOMAIN_LIST[*]})"
    echo "Output:           $RECON_DIR/"
    echo "Subdomains:       $TOTAL_SUBS"
    echo "Resolved:         $TOTAL_RESOLVED"
    echo "Live HTTP:        $TOTAL_LIVE"
    echo "Port entries:     $TOTAL_PORTS"
    echo "Paths found:      $TOTAL_PATHS"
    echo "Secrets:          $TOTAL_SECRETS"
    echo "Takeovers:        $TOTAL_TAKEOVERS"
    echo ""
    echo "Phase status:"
    for phase in 1 2 3 4 5 6 7; do
        local status="${PHASE_STATUS[$phase]:-not run}"
        local color="$NC"
        [[ "$status" == "done" ]] && color="$GREEN"
        [[ "$status" == "skipped" ]] && color="$YELLOW"
        echo -e "  Phase $phase: ${color}${status}${NC}"
    done
    echo ""
    echo "Key output files:"
    echo "  $RECON_DIR/all-subs.txt         All discovered subdomains"
    echo "  $RECON_DIR/resolved.txt         DNS-resolved hosts"
    echo "  $RECON_DIR/httpx-recon.json     HTTP fingerprints (JSON)"
    echo "  $RECON_DIR/httpx-recon.txt      Live HTTP hosts"
    echo "  $RECON_DIR/path-check.txt       Accessible paths"
    echo "  $RECON_DIR/wayback-interesting.txt  Interesting historical URLs"
}

# ============================================================
# MAIN
# ============================================================

log "recon-pipe starting for: $TARGET"
log "Domains: ${DOMAIN_LIST[*]}"
[[ -n "$HEADER" ]] && log "Header: $HEADER"
[[ -n "$PROXY" ]] && log "Proxy: $PROXY"
log "Rate limit: ${RATE_LIMIT}/s"
log "Port scan: $PORT_SCAN | Brute-force: $BRUTE_FORCE"
[[ -n "$GITHUB_ORG" ]] && log "GitHub org: $GITHUB_ORG"
[[ ${#SKIP_PHASES[@]} -gt 0 ]] && log "Skipping phases: ${SKIP_PHASES[*]}"
log "Output: $RECON_DIR/"
echo ""

phase1_subdomain_enum
phase2_portscan_probe
phase3_crawl
phase4_paths
phase5_cloud
phase6_secrets
phase7_takeover
print_summary
