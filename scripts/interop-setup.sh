#!/usr/bin/env bash
# Builds the interop peers the ignored test suites run against:
#
#   target/interop/bin/full_server, full_client   lib60870-C peers (tests/lib60870/)
#   target/interop/bin/tls_peer                   lib60870-C over mbedTLS (iec104-tls/tests/lib60870/)
#   .venv/                                        Python with c104 (tests/interop/)
#
# Idempotent: what is already there is kept. `cargo clean` removes the
# lib60870 peers; run this again after it. Needs git, make, gcc, curl, tar
# (with bzip2), sha256sum and python3.
set -euo pipefail

# The lib60870 commit the peers are checked against, and the c104 version.
LIB60870_COMMIT=7a388e3e133999e1ca77ba7521d55d074b7cd2bc
C104_VERSION=2.2.1
# The mbedTLS lib60870's TLS peer is built with (its README names 3.6.x);
# the checksum is of the release tarball as downloaded when this was set up.
MBEDTLS_VERSION=3.6.6
MBEDTLS_SHA256=8fb65fae8dcae5840f793c0a334860a411f884cc537ea290ce1c52bb64ca007a

root=$(cd "$(dirname "$0")/.." && pwd)
dir="$root/target/interop"
lib="$dir/lib60870/lib60870-C"
bin="$dir/bin"

includes=(
    "-I$lib/src/inc/api" "-I$lib/src/inc/internal" "-I$lib/src/hal/inc"
    "-I$lib/src/tls" "-I$lib/config" "-I$lib/src/file-service" "-I$lib/src/common/inc"
)

# lib60870 at the checked commit, built once for every plain peer.
build_lib60870() {
    [[ -f "$lib/build/liblib60870.a" ]] && return
    if [[ ! -d "$dir/lib60870/.git" ]]; then
        echo "cloning lib60870 into $dir/lib60870"
        git clone -q https://github.com/mz-automation/lib60870.git "$dir/lib60870"
    fi
    git -C "$dir/lib60870" checkout -q "$LIB60870_COMMIT"
    echo "building lib60870 at ${LIB60870_COMMIT:0:7}"
    make -s -C "$lib" lib >"$dir/lib60870-build.log" 2>&1 \
        || { echo "make failed; see $dir/lib60870-build.log" >&2; exit 1; }
}

if [[ ! -x "$bin/full_server" || ! -x "$bin/full_client" ]]; then
    build_lib60870
    mkdir -p "$bin"
    gcc -o "$bin/full_server" "$root/tests/lib60870/full_server.c" \
        "$lib/src/file-service/file_server.c" "${includes[@]}" "$lib/build/liblib60870.a" -lpthread
    gcc -o "$bin/full_client" "$root/tests/lib60870/full_client.c" \
        "${includes[@]}" "$lib/build/liblib60870.a" -lpthread
    echo "lib60870 peers: $bin"
else
    echo "lib60870 peers: $bin (already built)"
fi

# The TLS peer (iec104-tls/tests/lib60870/tls_peer.c) needs lib60870 built
# with mbedTLS, in a checkout of its own so the plain peers stay plain.
if [[ ! -x "$bin/tls_peer" ]]; then
    tls_dir="$dir/lib60870-tls"
    tls_lib="$tls_dir/lib60870-C"
    if [[ ! -d "$tls_dir/.git" ]]; then
        git clone -q "$dir/lib60870" "$tls_dir"
    fi
    git -C "$tls_dir" checkout -q "$LIB60870_COMMIT"
    mbedtls="$tls_lib/dependencies/mbedtls-$MBEDTLS_VERSION"
    if [[ ! -d "$mbedtls" ]]; then
        tarball="$dir/mbedtls-$MBEDTLS_VERSION.tar.bz2"
        if [[ ! -f "$tarball" ]]; then
            echo "downloading mbedTLS $MBEDTLS_VERSION"
            curl -sSfL -o "$tarball" \
                "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-$MBEDTLS_VERSION/mbedtls-$MBEDTLS_VERSION.tar.bz2"
        fi
        echo "$MBEDTLS_SHA256  $tarball" | sha256sum -c --quiet \
            || { echo "mbedTLS tarball checksum mismatch" >&2; exit 1; }
        tar xjf "$tarball" -C "$tls_lib/dependencies"
    fi
    echo "building lib60870 ${LIB60870_COMMIT:0:7} with mbedTLS $MBEDTLS_VERSION"
    make -s -C "$tls_lib" WITH_MBEDTLS3=1 MBEDTLS_DIR="dependencies/mbedtls-$MBEDTLS_VERSION" lib >"$dir/lib60870-tls-build.log" 2>&1 \
        || { echo "make failed; see $dir/lib60870-tls-build.log" >&2; exit 1; }
    mkdir -p "$bin"
    gcc -o "$bin/tls_peer" "$root/iec104-tls/tests/lib60870/tls_peer.c" \
        "-I$tls_lib/src/inc/api" "-I$tls_lib/src/inc/internal" "-I$tls_lib/src/hal/inc" \
        "-I$tls_lib/config" "-I$tls_lib/src/common/inc" \
        "$tls_lib/build/liblib60870.a" -lpthread
    echo "lib60870 TLS peer: $bin/tls_peer"
else
    echo "lib60870 TLS peer: $bin/tls_peer (already built)"
fi

python="$root/.venv/bin/python"
if [[ ! -x "$python" ]]; then
    python3 -m venv "$root/.venv"
fi
if ! "$python" -c "import importlib.metadata as m, sys; sys.exit(m.version('c104') != '$C104_VERSION')" 2>/dev/null; then
    echo "installing c104 $C104_VERSION into .venv"
    "$root/.venv/bin/pip" install -q "c104==$C104_VERSION"
fi
echo "c104: $("$python" -c "import importlib.metadata as m; print(m.version('c104'))") in .venv"
