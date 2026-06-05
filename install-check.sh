#!/usr/bin/env bash
# Check which recon tools are installed and which are missing.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "recon-pipe dependency check"
echo "==========================="
echo ""

REQUIRED=(curl jq python3)
OPTIONAL=(subfinder amass dnsx httpx naabu katana nuclei alterx shuffledns uncover trufflehog host wget)

installed=0
missing_req=0
missing_opt=0

echo "Required:"
for tool in "${REQUIRED[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}[OK]${NC} $tool"
        installed=$((installed + 1))
    else
        echo -e "  ${RED}[MISSING]${NC} $tool"
        missing_req=$((missing_req + 1))
    fi
done

echo ""
echo "Optional (phases degrade gracefully if missing):"
for tool in "${OPTIONAL[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}[OK]${NC} $tool"
        installed=$((installed + 1))
    else
        echo -e "  ${YELLOW}[MISSING]${NC} $tool"
        missing_opt=$((missing_opt + 1))
    fi
done

echo ""
echo "---"
echo -e "Installed: ${GREEN}$installed${NC} | Required missing: ${RED}$missing_req${NC} | Optional missing: ${YELLOW}$missing_opt${NC}"

if [[ $missing_req -gt 0 ]]; then
    echo ""
    echo -e "${RED}Install required tools before running recon-pipe.${NC}"
    exit 1
fi

if [[ $missing_opt -gt 0 ]]; then
    echo ""
    echo "Missing optional tools can be installed with:"
    echo "  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    echo "  go install -v github.com/owasp-amass/amass/v4/...@master"
    echo "  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    echo "  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    echo "  go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    echo "  go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
    echo "  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    echo "  go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest"
    echo "  go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    echo "  go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest"
    echo "  pip install trufflehog"
fi
