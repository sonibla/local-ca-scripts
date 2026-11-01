#!/usr/bin/env bash
# 02-new-intermediate.sh : Create and sign a new Intermediate CA
#
# Usage: ./02-new-intermediate.sh <name>
#
# Example:
#   ./02-new-intermediate.sh registry
#   ./02-new-intermediate.sh admin
#   ./02-new-intermediate.sh umami
#
# Produces:
#   ca-vault/intermediates/<name>/private/ca-<name>.key  (stays here)
#   ca-vault/intermediates/<name>/certs/ca-<name>.crt    (copy to Traefik)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CA_HOME="$SCRIPT_DIR/ca-vault"
ROOT_DIR="$CA_HOME/root"

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <name>"
  echo "Example: $0 registry"
  exit 1
fi

NAME="$1"
INT_DIR="$CA_HOME/intermediates/$NAME"

if [[ ! -f "$ROOT_DIR/private/ca-root.key" ]]; then
  echo "ERROR: Root CA not found. Run ./01-init-root-ca.sh first."
  exit 1
fi

if [[ -d "$INT_DIR" ]]; then
  echo "ERROR: Intermediate CA '$NAME' already exists at $INT_DIR"
  echo "       Refusing to overwrite."
  exit 1
fi

# Read Root CA subject to enforce policy_strict (country + org must match)
# Use -subject -nameopt sep_comma_plus to get a consistent parseable format
ROOT_SUBJECT=$(openssl x509 -noout -subject -nameopt sep_comma_plus,space_eq -in "$ROOT_DIR/certs/ca-root.crt")
# Extract C and O, handle both "C = FR" and "C=FR" output styles
ROOT_COUNTRY=$(echo "$ROOT_SUBJECT" | grep -oP '(?<=\bC\s?=\s?)[^,/]+' | tr -d ' ' | head -1)
ROOT_ORG=$(echo "$ROOT_SUBJECT" | grep -oP '(?<=\bO\s?=\s?)[^,/]+' | sed 's/[[:space:]]*$//' | head -1)

if [[ -z "$ROOT_COUNTRY" || -z "$ROOT_ORG" ]]; then
  echo "ERROR: Could not parse Country or Organization from root CA subject."
  echo "       Raw subject: $ROOT_SUBJECT"
  exit 1
fi

echo "=== New Intermediate CA: $NAME ==="
echo "(Country and Organization must match Root CA: C=$ROOT_COUNTRY, O=$ROOT_ORG)"
echo ""
CN_DEFAULT="$ROOT_ORG Intermediate CA - $NAME"
read -rp "Common Name [$CN_DEFAULT]: " CN
CN="${CN:-$CN_DEFAULT}"

# Create directory structure
mkdir -p "$INT_DIR/private"
mkdir -p "$INT_DIR/certs"
mkdir -p "$INT_DIR/csr"
mkdir -p "$INT_DIR/crl"
mkdir -p "$INT_DIR/newcerts"
mkdir -p "$INT_DIR/issued"
chmod 700 "$INT_DIR/private"

touch "$INT_DIR/index.txt"
echo "unique_subject = yes" > "$INT_DIR/index.txt.attr"
echo 1000 > "$INT_DIR/serial"
echo 1000 > "$INT_DIR/crlnumber"

# Write openssl.cnf for this intermediate
cat > "$INT_DIR/openssl.cnf" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $INT_DIR
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand
private_key       = \$dir/private/ca-${NAME}.key
certificate       = \$dir/certs/ca-${NAME}.crt
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/ca-${NAME}.crl
crl_extensions    = crl_ext
default_crl_days  = 365
default_md        = sha384
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 365
preserve          = no
policy            = policy_loose
copy_extensions   = copy
unique_subject    = no

[ policy_loose ]
countryName             = optional
organizationName        = optional
commonName              = supplied

[ req ]
default_bits        = 4096
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha384
prompt              = no

[ req_distinguished_name ]
C  = $ROOT_COUNTRY
O  = $ROOT_ORG
CN = $CN

[ v3_intermediate_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign

[ v3_client ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints       = critical, CA:false
keyUsage               = critical, digitalSignature
extendedKeyUsage       = clientAuth

[ crl_ext ]
authorityKeyIdentifier = keyid:always
EOF

echo ""
echo "==> Generating Intermediate CA private key (ECDSA P-384, encrypted with AES-256)..."
echo "    Set a passphrase (can differ from root CA passphrase)."
echo ""

openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-384 \
  -aes-256-cbc \
  -out "$INT_DIR/private/ca-${NAME}.key"

chmod 400 "$INT_DIR/private/ca-${NAME}.key"

echo ""
echo "==> Generating Certificate Signing Request..."

openssl req \
  -config "$INT_DIR/openssl.cnf" \
  -key "$INT_DIR/private/ca-${NAME}.key" \
  -new \
  -sha384 \
  -out "$INT_DIR/csr/ca-${NAME}.csr"

echo ""
echo "==> Signing with Root CA (you will be asked for the ROOT CA passphrase)..."

openssl ca \
  -config "$ROOT_DIR/openssl.cnf" \
  -extensions v3_intermediate_ca \
  -days 3650 \
  -notext \
  -md sha384 \
  -in "$INT_DIR/csr/ca-${NAME}.csr" \
  -out "$INT_DIR/certs/ca-${NAME}.crt"

chmod 444 "$INT_DIR/certs/ca-${NAME}.crt"

# Verify
echo ""
echo "==> Verifying certificate chain..."
openssl verify -CAfile "$ROOT_DIR/certs/ca-root.crt" "$INT_DIR/certs/ca-${NAME}.crt"

# Copy to export
cp "$INT_DIR/certs/ca-${NAME}.crt" "$CA_HOME/export/server/ca-${NAME}.crt"

echo ""
echo "==> Intermediate CA '$NAME' created successfully."
echo ""
echo "  Private key : $INT_DIR/private/ca-${NAME}.key  ← keep here"
echo "  Certificate : $INT_DIR/certs/ca-${NAME}.crt"
echo "  Export copy : $CA_HOME/export/server/ca-${NAME}.crt"
echo ""
openssl x509 -noout -subject -issuer -dates -in "$INT_DIR/certs/ca-${NAME}.crt"
echo ""
echo "Next step: issue client certs with ./03-issue-client.sh $NAME <common-name>"
