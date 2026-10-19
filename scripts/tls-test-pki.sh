#!/usr/bin/env bash
# Makes a THROWAWAY test PKI for the iec104-tls examples and interop runs:
# a CA and two leaf certificates, master and outstation, each valid for
# 127.0.0.1 and localhost and for both TLS roles. ECDSA P-256, 30 days.
#
#   scripts/tls-test-pki.sh [directory]      (default: target/tls-test-pki)
#
# Writes ca.crt ca.key master.crt master.key outstation.crt outstation.key.
# The keys are unencrypted: for tests only, never for a real station.
# Needs openssl (1.1.1 or later).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
dir=${1:-$root/target/tls-test-pki}
mkdir -p "$dir"
cd "$dir"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
    -subj "/CN=iec104 throwaway test CA" -keyout ca.key -out ca.crt \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

extensions=$(mktemp)
trap 'rm -f "$extensions"' EXIT
cat >"$extensions" <<'EOF'
subjectAltName=IP:127.0.0.1,DNS:localhost
extendedKeyUsage=serverAuth,clientAuth
keyUsage=critical,digitalSignature
EOF

serial=1
for name in master outstation; do
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -subj "/CN=iec104 test $name" -keyout "$name.key" -out "$name.csr" 2>/dev/null
    openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -set_serial "$serial" \
        -days 30 -extfile "$extensions" -out "$name.crt" 2>/dev/null
    rm -f "$name.csr"
    serial=$((serial + 1))
done
echo "test PKI in $dir: ca.crt, master.{crt,key}, outstation.{crt,key}"
