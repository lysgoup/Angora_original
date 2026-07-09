#!/bin/bash
# Sanity-checks that the Rust fuzzer workspace (common/fuzzer/runtime/runtime_fast)
# still compiles after a code change, without needing rustc/cargo/LLVM on the host.
# It builds inside the cached Angora toolchain Docker image instead.
#
# Usage:
#   ./tools/verify_build.sh              # debug + release build
#   ./tools/verify_build.sh --debug-only # skip the release build, faster
#
# Env vars:
#   ANGORA_BUILD_IMAGE - docker image with rust/cargo/clang already installed
#                        (default: yunseo/angora-reusing:latest)

set -euo pipefail

DEBUG_ONLY=0
if [ "${1:-}" = "--debug-only" ]; then
    DEBUG_ONLY=1
fi

IMAGE="${ANGORA_BUILD_IMAGE:-yunseo/angora-reusing:latest}"
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if ! command -v docker >/dev/null 2>&1; then
    echo "[-] docker not found in PATH." >&2
    exit 1
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "[-] Docker image '$IMAGE' not found locally." >&2
    echo "    Build/pull it first, or point ANGORA_BUILD_IMAGE at another image with rust+clang installed." >&2
    exit 1
fi

echo "[*] Verifying build of $ROOT_DIR using image $IMAGE"

BUILD_SCRIPT='
set -e
src=/angora_src
build=/tmp/angora_build_check
rm -rf "$build"
mkdir -p "$build"
for f in Cargo.toml Cargo.lock rust-toolchain common fuzzer runtime runtime_fast; do
    if [ -e "$src/$f" ]; then
        cp -r "$src/$f" "$build/$f"
    fi
done
cd "$build"
echo "[*] cargo build (debug)"
cargo build
'
if [ "$DEBUG_ONLY" -eq 0 ]; then
    BUILD_SCRIPT="$BUILD_SCRIPT"'
echo "[*] cargo build --release"
cargo build --release
'
fi

docker run --rm -v "$ROOT_DIR":/angora_src:ro "$IMAGE" bash -euc "$BUILD_SCRIPT"

echo "[+] Build check passed."
