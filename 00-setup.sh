#!/usr/bin/env bash
# 00-setup.sh : Initialize the CA vault directory structure
# Run this ONCE before anything else.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CA_HOME="$SCRIPT_DIR/ca-vault"

echo "==> Creating CA vault at: $CA_HOME"

# Root CA directories
mkdir -p "$CA_HOME/root/private"
mkdir -p "$CA_HOME/root/certs"
mkdir -p "$CA_HOME/root/crl"
mkdir -p "$CA_HOME/root/newcerts"

# Intermediates container
mkdir -p "$CA_HOME/intermediates"

# Export staging area
mkdir -p "$CA_HOME/export/server"

# Root CA database files
touch "$CA_HOME/root/index.txt"
echo "unique_subject = no" > "$CA_HOME/root/index.txt.attr"
echo 1000 > "$CA_HOME/root/serial"
echo 1000 > "$CA_HOME/root/crlnumber"

# Restrict access to private directories
chmod 700 "$CA_HOME/root/private"

echo ""
echo "Done. Directory structure created:"
echo "  $CA_HOME/"
echo "  ├── root/          (root CA files)"
echo "  ├── intermediates/ (one subdirectory per intermediate CA)"
echo "  └── export/        (files safe to copy out)"
echo ""
echo "Next step: run ./01-init-root-ca.sh"
