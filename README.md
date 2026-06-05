# recon-pipe

Automated recon pipeline for bug bounty and security assessments. Runs 7 phases in sequence, skips missing tools gracefully, and caches results so re-runs are fast.

## Phases

| # | Phase | Tools Used | Output |
|---|-------|-----------|--------|
| 1 | Subdomain Enumeration | subfinder, amass, crt.sh, certspotter, wayback, alterx, shuffledns, dnsx | `all-subs.txt`, `resolved.txt` |
| 2 | Port Scan + HTTP Probe | naabu, httpx | `ports.txt`, `httpx-recon.json` |
| 3 | Crawling + Historical URLs | katana, wayback | `crawl-*.txt`, `wayback-interesting.txt` |
| 4 | Standard Path Checks | httpx | `path-check.txt` |
| 5 | Cloud/Infra Recon | uncover (Shodan) | `shodan-results.txt` |
| 6 | Secret Scanning | trufflehog | `secrets.json` |
| 7 | Subdomain Takeover | nuclei | `takeovers.txt`, `dangling-cnames.txt` |

## Quick Start

```bash
# Check what tools you have installed
./install-check.sh

# Run against a target
./recon.sh acme --domains "acme.com api.acme.com"

# Results land in ./output/acme/
ls output/acme/
```

## Usage

```
./recon.sh <target> --domains "d1.com d2.com" [options]

Options:
  --domains "d1.com d2.com"   Target domains (required)
  --output DIR                Output directory (default: ./output/<target>)
  --proxy URL                 HTTP proxy for crawling (e.g. http://127.0.0.1:8080)
  --skip-phase N              Skip phase N (repeatable)
  --github-org NAME           GitHub org for TruffleHog secret scan
  --cookie "session=..."      Session cookie for authenticated crawling
  --rate-limit N              Requests/sec for HTTP tools (default: 30)
  --header "Name: Value"      Custom header for all HTTP requests
  --no-port-scan              Disable port scanning
  --no-brute-force            Disable subdomain permutation brute-force
  --skip-wayback              Skip Wayback Machine / historical URL sources
  --config FILE               Load settings from config file
  --force                     Re-run phases even if output exists
  --dry-run                   Print commands without executing
```

## Examples

```bash
# Basic recon
./recon.sh target --domains "target.com"

# With proxy and custom header
./recon.sh target --domains "target.com *.target.com" \
  --proxy http://127.0.0.1:8080 \
  --header "X-Bug-Bounty: researcher123"

# Authenticated crawl + secret scan
./recon.sh target --domains "target.com" \
  --cookie "session=abc123" \
  --github-org targetcorp

# Skip slow phases, custom output
./recon.sh target --domains "target.com" \
  --skip-phase 5 --skip-phase 6 \
  --output /tmp/recon-target

# Use a config file
./recon.sh target --domains "target.com" --config recon.conf

# Dry run — see what would execute
./recon.sh target --domains "target.com" --dry-run
```

## Config File

Copy `config/recon.conf.example` to `recon.conf` and customize:

```ini
rate_limit = 30
proxy = http://127.0.0.1:8080
github_org = targetcorp
port_scan = true
brute_force = true
skip_wayback = false
skip_phases = 5,6
```

Pass it with `--config recon.conf`. CLI flags override config values.

## Features

- **Graceful degradation** — missing tools are skipped with a warning, not a crash. Install what you have and the pipeline adapts.
- **Caching** — each phase checks if output already exists. Re-run without `--force` to skip completed phases.
- **Dry run** — `--dry-run` prints every command without executing. Review before committing to a full scan.
- **Input validation** — domains are validated, shell metacharacters are rejected to prevent injection.
- **CDN-aware** — port scanning automatically filters out CDN hosts (Cloudflare, Akamai, Fastly, etc.) to avoid noise.
- **Multi-source wayback** — `lib/wayback.sh` pulls from Wayback Machine, OTX AlienVault, and VirusTotal in parallel.

## Dependencies

**Required:** `curl`, `jq`, `python3`

**Optional** (install for full coverage):

```bash
# ProjectDiscovery tools (Go)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest

# OWASP Amass
go install -v github.com/owasp-amass/amass/v4/...@master

# TruffleHog
pip install trufflehog
```

Run `./install-check.sh` to see what you have and what's missing.

## License

MIT
