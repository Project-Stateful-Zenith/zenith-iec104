#!/usr/bin/env bash
# Runs every ignored interop suite (the core crate's, iec104-tokio's and
# iec104-tls's) against lib60870-C and c104. Builds the peers first if they
# are missing (scripts/interop-setup.sh).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
"$root/scripts/interop-setup.sh"
cd "$root"

status=0
run() {
    echo
    echo "== cargo test $*"
    cargo test "$@" -- --ignored --test-threads=1 || status=1
}
run --test lib60870            # all three crates have one (iec104-tls: over TLS)
run -p iec104 --test interop   # core: the scripted c104 scenario
run --test c104_outstation     # core: the blocking outstation, a c104 master
run -p iec104-tokio --test c104
run -p iec104-tls --test c104      # 104 over TLS: c104's outstation
exit $status
