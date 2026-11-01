#!/usr/bin/env bash
# 04-issue-server.sh : Issue a TLS server certificate for a domain
#
# Usage: ./04-issue-server.sh <domain> [<san2> <san3> ...]
#
# Examples:
#   ./04-issue-server.sh registry.dafidev.com
#   ./04-issue-server.sh dash.dafidev.com
#   ./04-issue-server.sh analytics.dafidev.com
#   ./04-issue-server.sh example.com www.example.com  # multi-SAN
#
# Signed directly by the Root CA (pathlen:1 allows it).
# The root CA cert must be trusted by clients that connect to these domains.
#
# Produces (in ca-vault/export/server/):
#   <domain>.crt    server certificate (copy to Traefik)
#   <domain>.key    private key       (copy to Traefik, keep secret in transit)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CA_HOME="$SCRIPT_DIR/ca-vault"
ROOT_DIR="$CA_HOME/root"

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <domain> [<san2> <san3> ...]"
  echo "Example: $0 registry.dafidev.com"
  exit 1
fi

PRIMARY_DOMAIN="$1"
shift
EXTRA_SANS=("$@")

if [[ ! -f "$ROOT_DIR/private/ca-root.key" ]]; then
  echo "ERROR: Root CA not found. Run ./01-init-root-ca.sh first."
  exit 1
fi

OUT_DIR="$CA_HOME/export/server"
KEY_FILE="$OUT_DIR/${PRIMARY_DOMAIN}.key"
CRT_FILE="$OUT_DIR/${PRIMARY_DOMAIN}.crt"
CSR_FILE="$ROOT_DIR/csr/${PRIMARY_DOMAIN}.csr"

if [[ -f "$CRT_FILE" ]]; then
  echo "ERROR: Server cert already exists at $CRT_FILE"
  echo "       Remove it manually if you want to reissue."
  exit 1
fi

mkdir -p "$ROOT_DIR/csr"

# Read C and O from root CA to satisfy policy_strict (countryName/org must match)
ROOT_SUBJECT=$(openssl x509 -noout -subject -nameopt sep_comma_plus,space_eq -in "$ROOT_DIR/certs/ca-root.crt")
ROOT_COUNTRY=$(echo "$ROOT_SUBJECT" | grep -oP '(?<=\bC\s?=\s?)[^,/]+' | tr -d ' ' | head -1)
ROOT_ORG=$(echo "$ROOT_SUBJECT" | grep -oP '(?<=\bO\s?=\s?)[^,/]+' | sed 's/[[:space:]]*$//' | head -1)

if [[ -z "$ROOT_COUNTRY" || -z "$ROOT_ORG" ]]; then
  echo "ERROR: Could not parse Country or Organization from root CA subject."
  echo "       Raw subject: $ROOT_SUBJECT"
  exit 1
fi

# Validity: 1 year default, can override with CERT_DAYS env var
CERT_DAYS="${CERT_DAYS:-365}"

# Build SAN list (always include the primary domain)
SAN_LIST="DNS:${PRIMARY_DOMAIN}"
for san in "${EXTRA_SANS[@]}"; do
  SAN_LIST+=",DNS:${san}"
done

echo "=== Issuing server certificate ==="
echo "  Domain   : $PRIMARY_DOMAIN"
if [[ ${#EXTRA_SANS[@]} -gt 0 ]]; then
  echo "  Extra SANs: ${EXTRA_SANS[*]}"
fi
echo "  SANs     : $SAN_LIST"
echo "  Validity : $CERT_DAYS days"
echo ""

# Temp files for extensions and CSR config
EXT_FILE=$(mktemp)
trap 'rm -f "$EXT_FILE"' EXIT

cat > "$EXT_FILE" <<EOF
[ v3_server ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints       = critical, CA:false
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = ${SAN_LIST}
EOF

echo "==> Generating server private key (ECDSA P-384, unencrypted)"
openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-384 \
  -out "$KEY_FILE"
chmod 400 "$KEY_FILE"

echo "==> Generating CSR..."
# Write a config file for the CSR (more reliable than -subj + -addext across OpenSSL versions)
CSR_CONF=$(mktemp)
trap 'rm -f "$EXT_FILE" "$CSR_CONF"' EXIT

cat > "$CSR_CONF" <<EOF
[ req ]
default_md          = sha384
prompt              = no
distinguished_name  = req_distinguished_name
req_extensions      = v3_req

[ req_distinguished_name ]
C  = ${ROOT_COUNTRY}
O  = ${ROOT_ORG}
CN = ${PRIMARY_DOMAIN}

[ v3_req ]
subjectAltName = ${SAN_LIST}
EOF

openssl req \
  -new \
  -sha384 \
  -key "$KEY_FILE" \
  -config "$CSR_CONF" \
  -out "$CSR_FILE"

echo "==> Signing with Root CA (enter root CA passphrase)..."
openssl ca \
  -config "$ROOT_DIR/openssl.cnf" \
  -extfile "$EXT_FILE" \
  -extensions v3_server \
  -days "$CERT_DAYS" \
  -notext \
  -md sha384 \
  -in "$CSR_FILE" \
  -out "$CRT_FILE"

chmod 444 "$CRT_FILE"

# Clean up CSR
rm "$CSR_FILE"

# Verify
echo ""
echo "==> Verifying certificate..."
openssl verify -CAfile "$ROOT_DIR/certs/ca-root.crt" "$CRT_FILE"

echo ""
echo "==> Server certificate issued successfully."
echo ""
echo "  Certificate : $CRT_FILE"
echo "  Private key : $KEY_FILE"
echo ""
openssl x509 -noout -subject -ext subjectAltName -dates -in "$CRT_FILE"
echo ""
echo "Copy both files to your Ansible role:"
echo "  roles/nobullshit_traefik/files/certs/${PRIMARY_DOMAIN}.crt"
echo "  roles/nobullshit_traefik/files/certs/${PRIMARY_DOMAIN}.key"
echo ""
echo "They map to traefik-dynamic.yml tls.certificates entries:"
echo "  - certFile: /certs/${PRIMARY_DOMAIN}.crt"
echo "    keyFile:  /certs/${PRIMARY_DOMAIN}.key"

# --- Optional Ansible Vault encryption ---
echo ""
read -s -rp "Ansible Vault passphrase to encrypt the .key (leave empty to skip): " VAULT_PASS
echo ""

if [[ -n "$VAULT_PASS" ]]; then
  if ! command -v ansible-vault &>/dev/null; then
    echo "WARNING: ansible-vault not found. Skipping encryption."
    echo "         Install ansible and run: ansible-vault encrypt $KEY_FILE"
  else
    # Write passphrase to a temp file (never pass secrets as CLI arguments)
    VAULT_PASS_FILE=$(mktemp)
    chmod 600 "$VAULT_PASS_FILE"
    printf '%s' "$VAULT_PASS" > "$VAULT_PASS_FILE"
    unset VAULT_PASS

    # Temporarily allow write access for ansible-vault to shred and replace the file
    chmod 600 "$KEY_FILE"
    ansible-vault encrypt --vault-password-file "$VAULT_PASS_FILE" "$KEY_FILE"
    chmod 400 "$KEY_FILE"

    # Securely delete the temp passphrase file
    if command -v shred &>/dev/null; then
      shred -u "$VAULT_PASS_FILE"
    else
      rm -f "$VAULT_PASS_FILE"
    fi

    echo "==> $KEY_FILE encrypted with Ansible Vault."
  fi
else
  unset VAULT_PASS
  echo "Skipping encryption. The .key file is stored in plaintext."
fi
