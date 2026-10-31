#!/bin/sh
# HERCULES installer. Installs the hercules-agent binary from one signed GitHub release.
#
#   curl -fsSL -o install.sh https://github.com/tcsilva214-bit/hercules-agent/releases/download/v0.1.0/install.sh
#   sh install.sh                (or: sh install.sh --force, to replace a different installed version)
#
# The README shows how to check this script itself against the signed SHA256SUMS before running it. Piping it
# straight into sh (curl ... | sh) trusts the script as GitHub serves it, over HTTPS.
#
# What it does, in order (read it before you run it; it is short):
#   1. picks the archive for this OS and CPU (macOS arm64/x86_64, Linux x86_64/arm64)
#   2. downloads the archive, SHA256SUMS and SHA256SUMS.sig from this release only
#   3. checks SHA256SUMS.sig against the release public key below (ssh-keygen -Y verify)
#   4. checks the archive's SHA-256 against SHA256SUMS
#   5. if gh is installed, also checks GitHub's build attestation for the archive: built by this repository's
#      release workflow from the tag of this release (reported; it does not decide the install)
#   6. installs hercules-agent into ~/.local/bin (or $HERCULES_INSTALL_DIR); never uses sudo
# It installs nothing unless steps 3 and 4 pass, and there is no option to skip them.
# Everything runs from main, called on the last line, so a partly downloaded script does nothing.
set -eu

VERSION="v0.1.0"
REPO="tcsilva214-bit/hercules-agent"
RELEASE_BASE="https://github.com/$REPO/releases/download/$VERSION"
# The release signing key (SSH Ed25519), fingerprint SHA256:xRDUi2ZT2xlMizPQIEi12VhRJsv8tJ1L9aGK06dwYRA (also in the README).
RELEASE_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGGEtzV1iGZzz9V8O8IrhVDvK47ynA6Vi/ZAUOvb4QVT hercules-release"
NAMESPACE="hercules-release"

say() { printf '%s\n' "$*"; }
die() { printf 'hercules install: %s\n' "$*" >&2; exit 1; }

main() {
  FORCE=0
  for arg in "$@"; do
    case "$arg" in
      --force) FORCE=1 ;;
      *) die "unknown option: $arg (the only option is --force)" ;;
    esac
  done

  case "$RELEASE_PUBKEY" in
    *RELEASE_PUBKEY_NOT_SET*) die "this copy of install.sh has no release key; use the one attached to a release" ;;
  esac

  # 1. Platform.
  os=$(uname -s)
  arch=$(uname -m)
  case "$os" in
    Darwin)
      # An x86_64 shell under Rosetta on Apple silicon: install the native arm64 binary.
      if [ "$arch" = x86_64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then arch=arm64; fi
      case "$arch" in
        arm64) target=aarch64-apple-darwin ;;
        x86_64) target=x86_64-apple-darwin ;;
        *) die "unsupported macOS CPU: $arch" ;;
      esac ;;
    Linux)
      case "$arch" in
        x86_64 | amd64) target=x86_64-unknown-linux-musl ;;
        aarch64 | arm64) target=aarch64-unknown-linux-musl ;;
        *) die "unsupported Linux CPU: $arch" ;;
      esac ;;
    *) die "unsupported OS: $os (macOS and Linux only)" ;;
  esac
  archive="hercules-agent-$VERSION-$target.tar.gz"

  # Tools.
  if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL --proto '=https' -o "$2" "$1"; }
  elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q -O "$2" "$1"; }
  else
    die "needs curl or wget"
  fi
  case "$RELEASE_BASE" in
    http://127.0.0.1:*) fetch() { curl -fsSL -o "$2" "$1"; } ;;  # the test suite's local mock release only
  esac
  command -v ssh-keygen >/dev/null 2>&1 || die "needs ssh-keygen (OpenSSH 8.1 or newer) to check the release signature"
  if command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$1" | awk '{print $1}'; }
  else
    die "needs shasum or sha256sum"
  fi

  tmp=$(mktemp -d 2>/dev/null || mktemp -d -t hercules)
  trap 'rm -rf "$tmp"' EXIT INT TERM

  # 2. Download.
  say "hercules-agent $VERSION for $target"
  fetch "$RELEASE_BASE/$archive" "$tmp/$archive" || die "download failed: $RELEASE_BASE/$archive"
  fetch "$RELEASE_BASE/SHA256SUMS" "$tmp/SHA256SUMS" || die "download failed: SHA256SUMS"
  fetch "$RELEASE_BASE/SHA256SUMS.sig" "$tmp/SHA256SUMS.sig" || die "download failed: SHA256SUMS.sig (the release is not signed yet)"

  # 3. Signature over SHA256SUMS.
  printf '%s namespaces="%s" %s\n' "$NAMESPACE" "$NAMESPACE" "${RELEASE_PUBKEY% *}" > "$tmp/allowed_signers"
  if ! ssh-keygen -Y verify -f "$tmp/allowed_signers" -I "$NAMESPACE" -n "$NAMESPACE" -s "$tmp/SHA256SUMS.sig" < "$tmp/SHA256SUMS" > "$tmp/verify.out" 2>&1; then
    cat "$tmp/verify.out" >&2
    die "SHA256SUMS signature does NOT verify against the release key; nothing installed"
  fi
  say "signature: OK (SHA256SUMS signed by the release key)"

  # 4. Checksum of the archive.
  want=$(awk -v f="$archive" '$2 == f || $2 == "*" f {print $1}' "$tmp/SHA256SUMS")
  [ -n "$want" ] || die "$archive is not listed in SHA256SUMS; nothing installed"
  got=$(sha256 "$tmp/$archive")
  [ "$got" = "$want" ] || die "checksum mismatch for $archive (got $got, signed $want); nothing installed"
  say "checksum:  OK ($got)"

  # 5. GitHub build attestation, when gh is available: this repository's release workflow, this tag.
  if command -v gh >/dev/null 2>&1; then
    if gh attestation verify "$tmp/$archive" -R "$REPO" --signer-workflow "github.com/$REPO/.github/workflows/release.yml" \
        --source-ref "refs/tags/$VERSION" --deny-self-hosted-runners > "$tmp/att.out" 2>&1; then
      say "attestation: OK (built by $REPO's release workflow from tag $VERSION)"
    else
      say "attestation: not confirmed (gh attestation verify failed; the signature and checksum above passed)"
    fi
  fi

  # 6. Install.
  tar -xzf "$tmp/$archive" -C "$tmp"
  bin="$tmp/hercules-agent-$VERSION-$target/hercules-agent"
  [ -f "$bin" ] || die "archive does not contain hercules-agent"
  chmod 755 "$bin"
  newver=$("$bin" --version 2>/dev/null) || die "the downloaded binary does not run on this machine"
  dir="${HERCULES_INSTALL_DIR:-$HOME/.local/bin}"
  mkdir -p "$dir"
  # Another user who can write to the install directory could swap files in it; refuse such a directory.
  [ -d "$dir" ] && [ ! -L "$dir" ] || die "$dir is not a plain directory"
  [ -n "$(find "$dir" -prune -user "$(id -u)" ! -perm -020 ! -perm -002 2>/dev/null)" ] \
    || die "$dir must be owned by you and not writable by group or others; nothing installed"
  dest="$dir/hercules-agent"
  if [ -e "$dest" ] || [ -L "$dest" ]; then
    [ -f "$dest" ] && [ ! -L "$dest" ] || die "$dest exists and is not a regular file; nothing installed"
    oldver=$("$dest" --version 2>/dev/null || echo "unknown")
    if [ "$oldver" = "$newver" ]; then
      say "already installed: $dest ($oldver)"
      exit 0
    fi
    [ "$FORCE" = 1 ] || die "$dest is already installed ($oldver); rerun with --force to replace it with $VERSION"
  fi
  # mktemp creates the file exclusively, with an unpredictable name, so nothing planted can be written through.
  stage=$(mktemp "$dir/.hercules-agent.XXXXXXXX") || die "could not create a temporary file in $dir"
  if ! { cat "$bin" > "$stage" && chmod 755 "$stage" && mv -f "$stage" "$dest"; }; then
    rm -f "$stage"
    die "could not install into $dir"
  fi

  say "installed: $dest"
  say "  $newver"
  say "  sha256 $(sha256 "$dest")"
  case ":$PATH:" in
    *":$dir:"*) ;;
    *) say "note: $dir is not on your PATH; add it, for example: export PATH=\"$dir:\$PATH\"" ;;
  esac
  say "next:"
  say "  hercules-agent keygen --out \$HOME/.hercules-keys     (every run is signed)"
  say "  then make a config: https://github.com/$REPO#use-it-with-a-real-model"
}

main "$@"
