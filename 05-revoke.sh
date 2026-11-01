#!/usr/bin/env bash
# 05-revoke.sh : Revoke a certificate and regenerate the CRL
#
# Usage:
#   Revoke a SERVER cert (signed by root CA):
#     ./05-revoke.sh server <domain>
#
#   Revoke a CLIENT cert (signed by an intermediate CA):
#     ./05-revoke.sh client <intermediate-name> <cn>
#
# Examples:
#   ./05-revoke.sh server  umami.dafidev.com
#   ./05-revoke.sh client  registry  prod-server-1
#   ./05-revoke.sh client  admin     qubes
#
# After revoking, copy the updated CRL to your Traefik server:
#   Server CRL : ca-vault/export/crl/ca-root.crl
#   Client CRL : ca-vault/export/crl/ca-<intermediate>.crl
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CA_HOME="$SCRIPT_DIR/ca-vault"
ROOT_DIR="$CA_HOME/root"

usage() {
  echo "Usage:"
  echo "  $0 server <domain>"
  echo "  $0 client <intermediate-name> <cn>"
  exit 1
}

if [[ $# -lt 2 ]]; then
  usage
fi

TYPE="$1"

# ---------------------------------------------------------------------------
# Shared: regenerate CRL for a given CA directory
# ---------------------------------------------------------------------------
generate_crl() {
  local CA_DIR="$1"
  local CA_NAME="$2"
  local CRL_FILE="$CA_DIR/crl/ca-${CA_NAME}.crl"

  echo ""
  echo "==> Regenerating CRL for ca-${CA_NAME} (enter its passphrase)..."
  openssl ca \
    -config "$CA_DIR/openssl.cnf" \
    -gencrl \
    -out "$CRL_FILE"

  mkdir -p "$CA_HOME/export/crl"
  cp "$CRL_FILE" "$CA_HOME/export/crl/ca-${CA_NAME}.crl"

  echo ""
  echo "  CRL written : $CA_HOME/export/crl/ca-${CA_NAME}.crl"
  echo ""
  echo "  CRL details:"
  openssl crl -noout -lastupdate -nextupdate -in "$CRL_FILE"
}

# ---------------------------------------------------------------------------
# SERVER revocation (root CA)
# ---------------------------------------------------------------------------
if [[ "$TYPE" == "server" ]]; then
  if [[ $# -ne 2 ]]; then
    echo "Usage: $0 server <domain>"
    exit 1
  fi

  DOMAIN="$2"
  CRT_FILE="$CA_HOME/export/server/${DOMAIN}.crt"

  if [[ ! -f "$CRT_FILE" ]]; then
    # Fall back to searching newcerts by CN
    echo "Certificate not found at $CRT_FILE"
    echo "Searching ca-vault/root/newcerts/ by CN=$DOMAIN ..."
    CRT_FILE=$(grep -rl "CN=$DOMAIN" "$ROOT_DIR/newcerts/" 2>/dev/null | head -1 || true)
    if [[ -z "$CRT_FILE" ]]; then
      echo "ERROR: Could not find a certificate for $DOMAIN."
      echo "       You can also revoke by serial: look up the serial in ca-vault/root/index.txt"
      echo "       then run: openssl ca -config ca-vault/root/openssl.cnf -revoke ca-vault/root/newcerts/<serial>.pem"
      exit 1
    fi
    echo "Found: $CRT_FILE"
  fi

  echo "=== Revoking SERVER certificate ==="
  echo "  Domain : $DOMAIN"
  echo "  File   : $CRT_FILE"
  echo ""
  read -rp "Are you sure? [y/N] " CONFIRM
  [[ "${CONFIRM,,}" == "y" ]] || { echo "Aborted."; exit 0; }

  echo ""
  echo "==> Revoking (enter ROOT CA passphrase)..."
  openssl ca \
    -config "$ROOT_DIR/openssl.cnf" \
    -revoke "$CRT_FILE"

  generate_crl "root" "root"

  # Remove exported files
  rm -f "$CA_HOME/export/server/${DOMAIN}.crt" \
        "$CA_HOME/export/server/${DOMAIN}.key"

  echo "==> Server certificate for $DOMAIN revoked."
  echo "    Exported files removed from ca-vault/export/server/"

# ---------------------------------------------------------------------------
# CLIENT revocation (intermediate CA)
# ---------------------------------------------------------------------------
elif [[ "$TYPE" == "client" ]]; then
  if [[ $# -ne 3 ]]; then
    echo "Usage: $0 client <intermediate-name> <cn>"
    exit 1
  fi

  INTERMEDIATE="$2"
  CN="$3"
  INT_DIR="$CA_HOME/intermediates/$INTERMEDIATE"
  CRT_FILE="$CA_HOME/export/clients/$INTERMEDIATE/${CN}-${INTERMEDIATE}.crt"

  if [[ ! -d "$INT_DIR" ]]; then
    echo "ERROR: Intermediate CA '$INTERMEDIATE' not found."
    exit 1
  fi

  if [[ ! -f "$CRT_FILE" ]]; then
    echo "Certificate not found at $CRT_FILE"
    echo "Searching ca-vault/intermediates/$INTERMEDIATE/newcerts/ by CN=$CN ..."
    CRT_FILE=$(grep -rl "/CN=$CN$" "$INT_DIR/newcerts/" 2>/dev/null | head -1 || true)
    if [[ -z "$CRT_FILE" ]]; then
      echo "ERROR: Could not find a certificate for CN=$CN under intermediate '$INTERMEDIATE'."
      echo "       Look up the serial in ca-vault/intermediates/$INTERMEDIATE/index.txt"
      echo "       then run: openssl ca -config ca-vault/intermediates/$INTERMEDIATE/openssl.cnf \\"
      echo "                   -revoke ca-vault/intermediates/$INTERMEDIATE/newcerts/<serial>.pem"
      exit 1
    fi
    echo "Found: $CRT_FILE"
  fi

  echo "=== Revoking CLIENT certificate ==="
  echo "  Intermediate : $INTERMEDIATE"
  echo "  Common Name  : $CN"
  echo "  File         : $CRT_FILE"
  echo ""
  read -rp "Are you sure? [y/N] " CONFIRM
  [[ "${CONFIRM,,}" == "y" ]] || { echo "Aborted."; exit 0; }

  echo ""
  echo "==> Revoking (enter '$INTERMEDIATE' intermediate CA passphrase)..."
  openssl ca \
    -config "$INT_DIR/openssl.cnf" \
    -revoke "$CRT_FILE"

  generate_crl "$INT_DIR" "$INTERMEDIATE"

  # Remove all exported files for this client
  rm -rf "$CA_HOME/export/clients/$INTERMEDIATE/${CN}-${INTERMEDIATE}.crt" \
         "$CA_HOME/export/clients/$INTERMEDIATE/${CN}-${INTERMEDIATE}.key" \
         "$CA_HOME/export/clients/$INTERMEDIATE/${CN}-${INTERMEDIATE}-chain.crt" \
         "$CA_HOME/export/clients/$INTERMEDIATE/${CN}-${INTERMEDIATE}.p12"

  echo "==> Client certificate for $CN ($INTERMEDIATE) revoked."
  echo "    Exported files removed from ca-vault/export/clients/$INTERMEDIATE/"

else
  echo "ERROR: Unknown type '$TYPE'. Must be 'server' or 'client'."
  usage
fi

echo ""
echo "=== What to do next ==="
echo ""
echo "Copy the updated CRL to your Traefik server and configure Traefik"
echo ""
echo "If Traefik CRL support is not yet configured, the most effective"
echo "immediate revocation is to rotate the intermediate CA:"
echo "  1. Delete ca-vault/intermediates/<name>/"
echo "  2. Run ./02-new-intermediate.sh <name>"
echo "  3. Reissue all legitimate client certs from the new intermediate"
echo "  4. Deploy the new CA cert to Traefik"
