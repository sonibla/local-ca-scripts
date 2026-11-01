#!/usr/bin/env bash
# 01-init-root-ca.sh : Generate the offline Root CA
# Run ONCE. Keep this VM offline forever after.
#
# Produces:
#   ca-vault/root/private/ca-root.key  (NEVER copies this out)
#   ca-vault/root/certs/ca-root.crt    (copy to Traefik servers)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CA_HOME="$SCRIPT_DIR/ca-vault"
ROOT_DIR="$CA_HOME/root"

if [[ ! -d "$ROOT_DIR" ]]; then
  echo "ERROR: CA vault not initialized. Run ./00-setup.sh first."
  exit 1
fi

if [[ -f "$ROOT_DIR/private/ca-root.key" ]]; then
  echo "ERROR: Root CA already exists at $ROOT_DIR/private/ca-root.key"
  echo "       Refusing to overwrite. Delete manually if you really mean it."
  exit 1
fi

# --- Prompt for subject fields ---
echo "=== Root CA Setup ==="
read -rp "Organization name (e.g. MyOrg): " ORG
read -rp "Country code (2 letters, e.g. FR): " COUNTRY
read -rp "Root CA Common Name (e.g. MyOrg Root CA): " CN

# Write openssl.cnf for root CA
cat > "$ROOT_DIR/openssl.cnf" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $ROOT_DIR
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand
private_key       = \$dir/private/ca-root.key
certificate       = \$dir/certs/ca-root.crt
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/ca-root.crl
crl_extensions    = crl_ext
default_crl_days  = 365
default_md        = sha384
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 3650
preserve          = no
policy            = policy_strict
copy_extensions   = copy
unique_subject    = no

[ policy_strict ]
countryName             = match
organizationName        = match
commonName              = supplied

[ req ]
default_bits        = 4096
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha384
x509_extensions     = v3_ca
prompt              = no

[ req_distinguished_name ]
C  = $COUNTRY
O  = $ORG
CN = $CN

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:1
keyUsage               = critical, keyCertSign, cRLSign

[ v3_intermediate_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign

[ crl_ext ]
authorityKeyIdentifier = keyid:always
EOF

echo ""
echo "==> Generating Root CA private key (ECDSA P-384, encrypted with AES-256)..."
echo "    You will be asked to set a passphrase. You need it to sign intermediates."
echo ""

openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-384 \
  -aes-256-cbc \
  -out "$ROOT_DIR/private/ca-root.key"

chmod 400 "$ROOT_DIR/private/ca-root.key"

echo ""
echo "==> Generating self-signed Root CA certificate (valid 20 years)..."

openssl req \
  -config "$ROOT_DIR/openssl.cnf" \
  -key "$ROOT_DIR/private/ca-root.key" \
  -new \
  -x509 \
  -days 7300 \
  -sha384 \
  -extensions v3_ca \
  -out "$ROOT_DIR/certs/ca-root.crt"

chmod 444 "$ROOT_DIR/certs/ca-root.crt"

# Copy public cert to export area
cp "$ROOT_DIR/certs/ca-root.crt" "$CA_HOME/export/server/ca-root.crt"

echo ""
echo "==> Root CA created successfully."
echo ""
echo "  Private key : $ROOT_DIR/private/ca-root.key  ← NEVER copy this out"
echo "  Certificate : $ROOT_DIR/certs/ca-root.crt"
echo "  Export copy : $CA_HOME/export/server/ca-root.crt"
echo ""
openssl x509 -noout -subject -issuer -dates -in "$ROOT_DIR/certs/ca-root.crt"
echo ""
echo "Next step: run ./02-new-intermediate.sh <name>"
echo "  e.g.:  ./02-new-intermediate.sh registry"
echo "         ./02-new-intermediate.sh admin"
echo "         ./02-new-intermediate.sh umami"
