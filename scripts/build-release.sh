#!/bin/bash
# Reproducible release build for HERCULES (hercules-agent).
# Same source + same toolchain + same platform => same binary hash, from any directory.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd -P)"

# rustup installs to ~/.cargo/bin, which is often not on PATH in non-login shells.
if ! command -v cargo >/dev/null && [ -x "$HOME/.cargo/bin/cargo" ]; then
  PATH="$HOME/.cargo/bin:$PATH"
fi
command -v cargo >/dev/null || { echo "REFUSE: cargo not found (not on PATH, not in ~/.cargo/bin)" >&2; exit 1; }

# The release compiler is pinned in RELEASE_RUSTC. HERCULES_RELEASE_RUSTC overrides it
# for development builds only; such builds are labelled and are not release candidates.
WANT="${HERCULES_RELEASE_RUSTC:-$(tr -d '[:space:]' < RELEASE_RUSTC)}"
V="$(rustc --version)"
case "$V" in
  "rustc $WANT "*) ;;
  *) echo "REFUSE: release builds need rustc $WANT (RELEASE_RUSTC); found: $V" >&2; exit 1 ;;
esac
[ -n "${HERCULES_RELEASE_RUSTC:-}" ] && echo "NOTE: development build with rustc override $WANT (not a release candidate)"

# Cargo creates its home on first download; a fresh CI runner (rustup from Homebrew) may not have it yet.
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
mkdir -p "$CARGO_HOME_DIR"
CARGO_HOME_DIR="$(cd "$CARGO_HOME_DIR" && pwd -P)"
SYSROOT="$(rustc --print sysroot)"
# Strip every machine-specific path from the binary. The remaps cover what the compiler writes;
# -C strip=debuginfo drops the linker's debug map, which on macOS names each standard-library object by
# its absolute path under the rustup folder (and so the user's home directory). Symbol names stay.
export RUSTFLAGS="--remap-path-prefix=$ROOT=/hercules --remap-path-prefix=$CARGO_HOME_DIR=/cargo --remap-path-prefix=$SYSROOT=/rustc -C strip=debuginfo"
# Apple's linker computes the binary's UUID before the strip, from a debug map that names the standard
# library by absolute path; -oso_prefix makes those paths relative to the toolchain, so the UUID (and the
# binary) no longer depends on the user name or the rustup toolchain's folder name.
TRIPLE="${HERCULES_TARGET:-$(rustc -vV | sed -n 's/^host: //p')}"
case "$TRIPLE" in
  *-apple-darwin) RUSTFLAGS="$RUSTFLAGS -C link-arg=-Wl,-oso_prefix,$SYSROOT" ;;
esac
export CARGO_INCREMENTAL=0
export SOURCE_DATE_EPOCH=0

# Gate 11: HERCULES_TARGET builds for another target triple (release binaries for macOS x86_64 and Linux musl).
if [ -n "${HERCULES_TARGET:-}" ]; then
  cargo build --release --locked --target "$HERCULES_TARGET"
  BIN="$ROOT/target/$HERCULES_TARGET/release/hercules-agent"
else
  cargo build --release --locked
  BIN="$ROOT/target/release/hercules-agent"
fi
if command -v shasum >/dev/null; then SUM="$(shasum -a 256 "$BIN" | awk '{print $1}')"; else SUM="$(sha256sum "$BIN" | awk '{print $1}')"; fi
echo "RUSTC=$V"
echo "BINARY_SHA256=$SUM"
echo "BINARY=$BIN"
if [ -z "${HERCULES_TARGET:-}" ] || [ "${HERCULES_RUN_VERSION:-}" = 1 ]; then "$BIN" --version; fi
