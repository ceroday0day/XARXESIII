#!/usr/bin/env bash
#
# auto-enum.sh — Automated enumeration against Umbrella Corporation domain
#
# Usage: ./auto-enum.sh [target_dc_ip]
# Default target: 192.168.56.10 (DC01)
#
# Runs: nmap, enum4linux-ng, ldapdomaindump, bloodhound-python
# Output: /results/<timestamp>/
#
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────
DC_IP="${1:-192.168.56.10}"
SRV_IP="192.168.56.11"
DOMAIN="umbrella.corp"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUTPUT_DIR="/results/${TIMESTAMP}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}[*]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }

# ── Pre-flight checks ───────────────────────────────────────────────────
check_tool() {
    if ! command -v "$1" &>/dev/null; then
        log_error "Required tool not found: $1"
        log_warn "Install with: $2"
        return 1
    fi
    return 0
}

log_info "0xLab-AD Automated Enumeration"
log_info "Target DC: ${DC_IP} | Domain: ${DOMAIN}"
log_info "Output directory: ${OUTPUT_DIR}"
echo ""

missing=0
check_tool nmap "apt install nmap" || missing=1
check_tool enum4linux-ng "apt install enum4linux-ng || pip3 install enum4linux-ng" || missing=1
check_tool ldapdomaindump "pip3 install ldapdomaindump" || missing=1
check_tool bloodhound-python "pip3 install bloodhound" || missing=1
check_tool crackmapexec "apt install crackmapexec" || missing=1

if [ "$missing" -eq 1 ]; then
    log_error "Some tools are missing. Install them and retry."
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"/{nmap,smb,ldap,bloodhound,cme}

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 1: Network Discovery (nmap)
# ═══════════════════════════════════════════════════════════════════════════
log_info "PHASE 1: Network scan with nmap..."

log_info "Quick TCP scan — top 1000 ports on all targets..."
nmap -sV -sC -T4 -oA "${OUTPUT_DIR}/nmap/quick_scan" \
    "${DC_IP}" "${SRV_IP}" 2>/dev/null
log_ok "Quick scan complete"

log_info "Full TCP scan on DC01..."
nmap -sV -sC -p- -T4 -oA "${OUTPUT_DIR}/nmap/dc01_full" \
    "${DC_IP}" 2>/dev/null
log_ok "DC01 full scan complete"

log_info "Full TCP scan on SRV01..."
nmap -sV -sC -p- -T4 -oA "${OUTPUT_DIR}/nmap/srv01_full" \
    "${SRV_IP}" 2>/dev/null
log_ok "SRV01 full scan complete"

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 2: SMB Enumeration
# ═══════════════════════════════════════════════════════════════════════════
log_info "PHASE 2: SMB enumeration..."

log_info "enum4linux-ng against DC01..."
enum4linux-ng -A "${DC_IP}" -oJ "${OUTPUT_DIR}/smb/enum4linux_dc01" 2>/dev/null || true
log_ok "enum4linux-ng DC01 complete"

log_info "enum4linux-ng against SRV01..."
enum4linux-ng -A "${SRV_IP}" -oJ "${OUTPUT_DIR}/smb/enum4linux_srv01" 2>/dev/null || true
log_ok "enum4linux-ng SRV01 complete"

log_info "CrackMapExec SMB enumeration..."
crackmapexec smb "${DC_IP}" "${SRV_IP}" --shares \
    > "${OUTPUT_DIR}/cme/smb_shares.txt" 2>/dev/null || true
log_ok "CME share enumeration complete"

log_info "Checking anonymous SMB access on SRV01..."
smbclient -N -L "//${SRV_IP}" \
    > "${OUTPUT_DIR}/smb/anonymous_shares.txt" 2>/dev/null || true

# Try to download contents of Public share
mkdir -p "${OUTPUT_DIR}/smb/public_share"
smbclient -N "//${SRV_IP}/Public" -c "prompt OFF; recurse ON; mget *" \
    --directory="${OUTPUT_DIR}/smb/public_share" 2>/dev/null || true
log_ok "Anonymous SMB enumeration complete"

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 3: LDAP Enumeration
# ═══════════════════════════════════════════════════════════════════════════
log_info "PHASE 3: LDAP enumeration..."

log_info "ldapdomaindump against DC01..."
ldapdomaindump "${DC_IP}" -o "${OUTPUT_DIR}/ldap/" \
    --no-json --no-grep 2>/dev/null || true
log_ok "LDAP domain dump complete"

log_info "Anonymous LDAP query for users..."
ldapsearch -x -H "ldap://${DC_IP}" -b "DC=umbrella,DC=corp" \
    "(objectClass=user)" sAMAccountName userPrincipalName memberOf \
    > "${OUTPUT_DIR}/ldap/users.ldif" 2>/dev/null || true
log_ok "LDAP user query complete"

log_info "LDAP query for SPNs (Kerberoastable accounts)..."
ldapsearch -x -H "ldap://${DC_IP}" -b "DC=umbrella,DC=corp" \
    "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName \
    > "${OUTPUT_DIR}/ldap/spn_users.ldif" 2>/dev/null || true
log_ok "SPN enumeration complete"

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 4: BloodHound Collection
# ═══════════════════════════════════════════════════════════════════════════
log_info "PHASE 4: BloodHound data collection..."

# Note: If credentials have been discovered, use them here
log_info "Attempting BloodHound collection (anonymous)..."
bloodhound-python -d "${DOMAIN}" -ns "${DC_IP}" \
    -c All --zip \
    -o "${OUTPUT_DIR}/bloodhound/" 2>/dev/null || {
    log_warn "Anonymous BloodHound collection failed (expected — needs creds)"
    log_info "Re-run after obtaining credentials:"
    log_info "  bloodhound-python -d ${DOMAIN} -u 'svc_monitor' -p 'Monitor2024!' -ns ${DC_IP} -c All --zip"
}

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 5: Summary
# ═══════════════════════════════════════════════════════════════════════════
echo ""
log_info "════════════════════════════════════════════════════"
log_ok   "Enumeration complete!"
log_info "════════════════════════════════════════════════════"
log_info "Results saved to: ${OUTPUT_DIR}/"
echo ""
log_info "Directory structure:"
find "${OUTPUT_DIR}" -type f | head -30 | while IFS= read -r f; do
    echo "  ${f}"
done

echo ""
log_info "Next steps:"
log_info "  1. Check ${OUTPUT_DIR}/smb/public_share/ for planted credentials"
log_info "  2. Review ${OUTPUT_DIR}/ldap/spn_users.ldif for Kerberoastable accounts"
log_info "  3. Import ${OUTPUT_DIR}/bloodhound/*.zip into BloodHound GUI"
log_info "  4. See /opt/0xlab/attack-chain.md for full walkthrough"
