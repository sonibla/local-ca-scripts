#!/usr/bin/env bash
# 03-issue-client.sh : Issue a client certificate from an Intermediate CA
#
# Usage: ./03-issue-client.sh <intermediate-name> <common-name>
#
# Example:
#   ./03-issue-client.sh registry dafi-laptop
#   ./03-issue-client.sh admin    dafi-laptop
#   ./03-issue-client.sh umami    dafi-laptop
#
# Produces (all in ca-vault/export/clients/<intermediate>/<cn>/):
#   <cn>.key        private key (unencrypted, ready to install in browser/curl)
#   <cn>.crt        certificate
#   <cn>.p12        PKCS#12 bundle (for web browsers)
#   <cn>-chain.crt  cert + intermediate CA chain (for curl/apps)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CA_HOME="$SCRIPT_DIR/ca-vault"

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <intermediate-name> <common-name>"
  echo "Example: $0 registry dafi-laptop"
  exit 1
fi

INTERMEDIATE="$1"
CN="$2"
INT_DIR="$CA_HOME/intermediates/$INTERMEDIATE"
OUT_DIR="$CA_HOME/export/clients/$INTERMEDIATE/$CN"

if [[ ! -f "$INT_DIR/private/ca-${INTERMEDIATE}.key" ]]; then
  echo "ERROR: Intermediate CA '$INTERMEDIATE' not found."
  echo "       Run ./02-new-intermediate.sh $INTERMEDIATE first."
  exit 1
fi

if [[ -d "$OUT_DIR" ]]; then
  echo "ERROR: Client cert '$CN' already exists for intermediate '$INTERMEDIATE'."
  echo "       Path: $OUT_DIR"
  echo "       Revoke it first with ./04-revoke-client.sh $INTERMEDIATE $CN"
  exit 1
fi

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

# Validity: 1 year default, can override with CERT_DAYS env var
CERT_DAYS="${CERT_DAYS:-365}"

echo "=== Issuing client certificate ==="
echo "  Intermediate : $INTERMEDIATE"
echo "  Common Name  : $CN"
echo "  Validity     : $CERT_DAYS days"
echo ""

CSR_FILE="$INT_DIR/csr/${CN}-${INTERMEDIATE}.csr"
KEY_FILE="$OUT_DIR/${CN}-${INTERMEDIATE}.key"
CRT_FILE="$OUT_DIR/${CN}-${INTERMEDIATE}.crt"
P12_FILE="$OUT_DIR/${CN}-${INTERMEDIATE}.p12"
CHAIN_FILE="$OUT_DIR/${CN}-${INTERMEDIATE}-chain.crt"

echo "==> Generating client private key (ECDSA P-384, unencrypted for usability)..."
openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-384 \
  -out "$KEY_FILE"
chmod 400 "$KEY_FILE"

echo "==> Generating CSR..."
openssl req \
  -new \
  -sha384 \
  -key "$KEY_FILE" \
  -subj "/CN=${CN}" \
  -out "$CSR_FILE"

echo "==> Signing with intermediate CA '$INTERMEDIATE' (enter its passphrase)..."
openssl ca \
  -config "$INT_DIR/openssl.cnf" \
  -extensions v3_client \
  -days "$CERT_DAYS" \
  -notext \
  -md sha384 \
  -in "$CSR_FILE" \
  -out "$CRT_FILE"

chmod 444 "$CRT_FILE"

# Verify chain up to root
ROOT_CRT="$CA_HOME/root/certs/ca-root.crt"
INT_CRT="$INT_DIR/certs/ca-${INTERMEDIATE}.crt"

echo ""
echo "==> Verifying certificate chain..."
cat "$INT_CRT" "$ROOT_CRT" > /tmp/chain-verify.crt
openssl verify -CAfile /tmp/chain-verify.crt "$CRT_FILE"
rm /tmp/chain-verify.crt

# Build chain file (cert + intermediate)
cat "$CRT_FILE" "$INT_CRT" > "$CHAIN_FILE"

# Build PKCS#12 bundle for browsers
echo ""
echo "==> Building PKCS#12 bundle for browser import..."
echo "    Set a passphrase to protect the .p12 file."
echo ""
openssl pkcs12 \
  -export \
  -inkey "$KEY_FILE" \
  -in "$CRT_FILE" \
  -certfile "$INT_CRT" \
  -name "${CN} - ${INTERMEDIATE} access" \
  -out "$P12_FILE"

chmod 400 "$P12_FILE"

# Clean up CSR (no longer needed)
rm "$CSR_FILE"

echo ""
echo "==> Client certificate issued successfully."
echo ""
echo "  Output directory: $OUT_DIR"
echo "  Files:"
  echo "    ${CN}-${INTERMEDIATE}.key            private key (keep secret)"
  echo "    ${CN}-${INTERMEDIATE}.crt            certificate"
  echo "    ${CN}-${INTERMEDIATE}-chain.crt      cert + intermediate chain (use with curl)"
  echo "    ${CN}-${INTERMEDIATE}.p12            PKCS#12 bundle (import into browser)"
echo ""
openssl x509 -noout -subject -issuer -dates -in "$CRT_FILE"
echo ""
echo "To use with curl:"
echo "  curl --cert $OUT_DIR/${CN}-${INTERMEDIATE}-chain.crt --key $OUT_DIR/${CN}-${INTERMEDIATE}.key https://your-service"

# --- Optional Ansible Vault encryption ---
echo ""
read -s -rp "Ansible Vault passphrase to encrypt the .key (leave empty to skip): " VAULT_PASS
echo ""

if [[ -n "$VAULT_PASS" ]]; then
  if ! command -v ansible-vault &>/dev/null; then
    echo "WARNING: ansible-vault not found. Skipping encryption."
    echo "         Install ansible and run: ansible-vault encrypt $KEY_FILE"
  else
    # Write passphrase to a temp file
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
