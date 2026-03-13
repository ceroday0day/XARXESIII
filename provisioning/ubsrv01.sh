#!/usr/bin/env bash
#
# UBSRV01 Provisioning — Joins Ubuntu Server to umbrella.corp Active Directory domain.
#
# Usage: Called by Vagrant with arguments:
#   $1 = DomainName (e.g. umbrella.corp)
#   $2 = NetBIOSName (e.g. UMBRELLA)
#   $3 = AdminPassword
#   $4 = DCIP
#
set -e

DOMAIN_NAME="$1"
NETBIOS_NAME="$2"
ADMIN_PASSWORD="$3"
DC_IP="$4"

DOMAIN_UPPER=$(echo "$DOMAIN_NAME" | tr '[:lower:]' '[:upper:]')

log_info()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')][INFO] $1"; }
log_ok()    { echo "[$(date '+%Y-%m-%d %H:%M:%S')][OK]   $1"; }
log_error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')][ERROR] $1"; }

log_info "Starting UBSRV01 provisioning — joining domain: $DOMAIN_NAME"

# ── Configure DNS to point to DC ────────────────────────────────────────
log_info "Configuring DNS to point to DC at $DC_IP"

cat > /etc/netplan/99-dns-override.yaml << EOF
network:
  version: 2
  ethernets:
    eth1:
      nameservers:
        addresses: [$DC_IP]
        search: [$DOMAIN_NAME]
EOF

netplan apply 2>/dev/null || true

# Also set resolv.conf directly for immediate use
cat > /etc/resolv.conf << EOF
nameserver $DC_IP
search $DOMAIN_NAME
EOF

log_ok "DNS configured"

# ── Configure /etc/hosts ────────────────────────────────────────────────
log_info "Configuring /etc/hosts..."
echo "$DC_IP  dc01.$DOMAIN_NAME dc01 $DOMAIN_NAME" >> /etc/hosts
log_ok "/etc/hosts updated"

# ── Install required packages ───────────────────────────────────────────
log_info "Installing packages for AD domain join..."
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq

# Pre-seed Kerberos configuration to avoid interactive prompts
debconf-set-selections <<< "krb5-config krb5-config/default_realm string $DOMAIN_UPPER"
debconf-set-selections <<< "krb5-config krb5-config/add_servers_realm string $DOMAIN_NAME"
debconf-set-selections <<< "krb5-config krb5-config/kerberos_servers string dc01.$DOMAIN_NAME"
debconf-set-selections <<< "krb5-config krb5-config/admin_server string dc01.$DOMAIN_NAME"

apt-get install -y -qq \
    realmd \
    sssd \
    sssd-tools \
    libnss-sss \
    libpam-sss \
    adcli \
    samba-common-bin \
    krb5-user \
    packagekit \
    oddjob \
    oddjob-mkhomedir \
    >/dev/null 2>&1

log_ok "Packages installed"

# ── Configure Kerberos ──────────────────────────────────────────────────
log_info "Configuring Kerberos (krb5.conf)..."
cat > /etc/krb5.conf << EOF
[libdefaults]
    default_realm = $DOMAIN_UPPER
    dns_lookup_realm = true
    dns_lookup_kdc = true
    rdns = false

[realms]
    $DOMAIN_UPPER = {
        kdc = dc01.$DOMAIN_NAME
        admin_server = dc01.$DOMAIN_NAME
    }

[domain_realm]
    .$DOMAIN_NAME = $DOMAIN_UPPER
    $DOMAIN_NAME = $DOMAIN_UPPER
EOF

log_ok "Kerberos configured"

# ── Join domain ─────────────────────────────────────────────────────────
log_info "Joining domain: $DOMAIN_NAME"

MAX_RETRIES=5
RETRY_DELAY=30

for i in $(seq 1 $MAX_RETRIES); do
    log_info "Domain join attempt $i/$MAX_RETRIES..."
    if echo "$ADMIN_PASSWORD" | realm join --user=Administrator "$DOMAIN_NAME" 2>&1; then
        log_ok "Successfully joined domain"
        break
    else
        log_error "Domain join attempt $i/$MAX_RETRIES failed"
        if [ "$i" -eq "$MAX_RETRIES" ]; then
            log_error "Failed to join domain after $MAX_RETRIES attempts"
            exit 1
        fi
        log_info "Retrying in $RETRY_DELAY seconds..."
        sleep $RETRY_DELAY
    fi
done

# ── Configure SSSD ──────────────────────────────────────────────────────
log_info "Configuring SSSD..."

cat > /etc/sssd/sssd.conf << EOF
[sssd]
domains = $DOMAIN_NAME
config_file_version = 2
services = nss, pam

[domain/$DOMAIN_NAME]
default_shell = /bin/bash
krb5_store_password_if_offline = True
cache_credentials = True
krb5_realm = $DOMAIN_UPPER
realmd_tags = manages-system joined-with-adcli
id_provider = ad
fallback_homedir = /home/%u@%d
ad_domain = $DOMAIN_NAME
use_fully_qualified_names = True
ldap_id_mapping = True
access_provider = ad
EOF

chmod 600 /etc/sssd/sssd.conf

# Enable automatic home directory creation
pam-auth-update --enable mkhomedir 2>/dev/null || true

systemctl restart sssd
systemctl enable sssd

log_ok "SSSD configured and running"

# ── Verify domain join ──────────────────────────────────────────────────
log_info "Verifying domain join..."
if realm list | grep -q "$DOMAIN_NAME"; then
    log_ok "Domain membership verified: $(realm list | head -1)"
else
    log_error "Domain membership verification failed"
fi

# ── Allow domain users to log in ────────────────────────────────────────
log_info "Permitting domain user logins..."
realm permit --all 2>/dev/null || true
log_ok "All domain users permitted to log in"

# ── Disable firewall for lab environment ────────────────────────────────
log_info "Disabling UFW for lab environment..."
ufw disable 2>/dev/null || true
log_ok "Firewall disabled"

log_ok "UBSRV01 provisioning complete — Ubuntu Server joined to $DOMAIN_NAME"
