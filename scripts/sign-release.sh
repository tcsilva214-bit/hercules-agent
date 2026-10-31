#!/bin/bash
# Sign and (optionally) publish a draft HERCULES release. Run by the maintainer on their own Mac.
#
#   scripts/sign-release.sh <tag> <path to the release private key> [--publish]
#
# What it checks before signing, and what it does not:
# 1. The release must be a draft on GitHub, made by the release workflow, for a tag whose commit it records.
# 2. Every archive, and install.sh, must match SHA256SUMS.
# 3. Every archive must carry GitHub's build attestation from this repository's release workflow, for this tag
#    and this tag's commit, on a GitHub-hosted runner. Attestations exist only for public repositories, so a
#    final release requires a public repository; a dry run (v0.1.0-dryrun.N) in a private one says it skipped this.
# 4. The macOS arm64 binary is rebuilt here from the tag (scripts/build-release.sh, the same target triple and the
#    Xcode version the workflow pins) and must be byte-identical to the released one. There is no override: a
#    mismatch stops the release. The other targets are not rebuilt here; for them, step 3 is the evidence.
# 5. install.sh must trust this key and install this tag's version.
# Then it signs SHA256SUMS (ssh-keygen -Y sign), verifies the signature the way install.sh will, and uploads it.
# With --publish it publishes the release; without, it prints the publish command.
set -euo pipefail
trap 'echo "STOP: sign-release.sh line $LINENO failed: $BASH_COMMAND" >&2' ERR

REPO="${HERCULES_REPO:-tcsilva214-bit/hercules-agent}"
NAMESPACE="hercules-release"
TARGET="aarch64-apple-darwin"
WORKFLOW="github.com/$REPO/.github/workflows/release.yml"
GH="$(command -v gh || echo /opt/homebrew/bin/gh)"
[ -x "$GH" ] || { echo "REFUSE: gh not found" >&2; exit 1; }

TAG="${1:-}"; KEY="${2:-}"; shift 2 || true
PUBLISH=0
for a in "$@"; do
  case "$a" in
    --publish) PUBLISH=1 ;;
    *) echo "REFUSE: unknown option $a" >&2; exit 2 ;;
  esac
done
[ -n "$TAG" ] && [ -n "$KEY" ] || { echo "usage: $0 <tag> <release private key> [--publish]" >&2; exit 2; }
[ -f "$KEY" ] && [ -f "$KEY.pub" ] || { echo "REFUSE: $KEY and $KEY.pub must both exist" >&2; exit 1; }
[ "$(uname -s)-$(uname -m)" = "Darwin-arm64" ] || { echo "REFUSE: the rebuild check needs an Apple silicon Mac" >&2; exit 1; }
if ! command -v cargo >/dev/null && [ -x "$HOME/.cargo/bin/cargo" ]; then PATH="$HOME/.cargo/bin:$PATH"; fi
case "$TAG" in
  *-dryrun.*) DRYRUN=1 ;;
  *) DRYRUN=0 ;;
esac

draft="$("$GH" release view "$TAG" -R "$REPO" --json isDraft --jq .isDraft)"
[ "$draft" = true ] || { echo "REFUSE: release $TAG is not a draft (isDraft=$draft)" >&2; exit 1; }
visibility="$("$GH" repo view "$REPO" --json visibility --jq .visibility)"
commit="$("$GH" api "repos/$REPO/commits/$TAG" --jq .sha)"
echo "release $TAG: commit $commit, repository $visibility"

T="$(mktemp -d /tmp/hercules-sign.XXXXXX)"
echo "work folder: $T"
"$GH" release download "$TAG" -R "$REPO" -D "$T/rel" -p SHA256SUMS -p install.sh -p "hercules-agent-$TAG-*.tar.gz"
n_listed="$(grep -c '\.tar\.gz$' "$T/rel/SHA256SUMS")"
n_got="$(find "$T/rel" -name "hercules-agent-$TAG-*.tar.gz" | wc -l | tr -d ' ')"
[ "$n_listed" = "$n_got" ] && [ "$n_got" -ge 3 ] || { echo "REFUSE: SHA256SUMS lists $n_listed archives, the draft has $n_got" >&2; exit 1; }
( cd "$T/rel" && shasum -a 256 -c SHA256SUMS ) || { echo "REFUSE: downloaded files do not match SHA256SUMS" >&2; exit 1; }

# Build provenance for every archive.
if [ "$visibility" = PUBLIC ]; then
  for a in "$T"/rel/hercules-agent-"$TAG"-*.tar.gz; do
    "$GH" attestation verify "$a" -R "$REPO" --signer-workflow "$WORKFLOW" --source-ref "refs/tags/$TAG" \
      --source-digest "$commit" --deny-self-hosted-runners > "$T/att.out" 2>&1 \
      || { cat "$T/att.out" >&2; echo "REFUSE: no valid build attestation for $(basename "$a")" >&2; exit 1; }
    echo "attestation OK: $(basename "$a") (release workflow, $TAG, $commit)"
  done
elif [ "$DRYRUN" = 1 ]; then
  echo "attestations: skipped (repository is $visibility; GitHub attests public repositories only; dry run)"
else
  echo "REFUSE: a final release needs a public repository, so every archive has a build attestation" >&2
  exit 1
fi

# The rebuild check: the same target triple and the same Xcode as the release workflow.
tar -xzf "$T/rel/hercules-agent-$TAG-$TARGET.tar.gz" -C "$T/rel"
released="$(shasum -a 256 "$T/rel/hercules-agent-$TAG-$TARGET/hercules-agent" | awk '{print $1}')"
"$GH" repo clone "$REPO" "$T/src" -- -q --depth 1 --branch "$TAG"
[ "$(git -C "$T/src" rev-parse HEAD)" = "$commit" ] || { echo "REFUSE: the cloned tag is not commit $commit" >&2; exit 1; }
want_xcode="$(sed -n 's/^  XCODE_VERSION: "\(.*\)"$/\1/p' "$T/src/.github/workflows/release.yml")"
xcode_out="$(xcodebuild -version 2>&1)" || true
ld_out="$(ld -v 2>&1)" || true
have_xcode="$(printf '%s\n' "$xcode_out" | sed -n 1p)"
echo "Xcode: release workflow $want_xcode, this Mac: $have_xcode ($(printf '%s\n' "$xcode_out" | sed -n 2p); $(printf '%s\n' "$ld_out" | sed -n '1s/.*PROJECT://p'))"
[ -n "$want_xcode" ] && [ "$have_xcode" = "Xcode $want_xcode" ] || { echo "REFUSE: the rebuild check needs Xcode $want_xcode here (the release workflow links with it); select it with xcode-select or install it" >&2; exit 1; }
local_build="$(HERCULES_TARGET="$TARGET" bash "$T/src/scripts/build-release.sh" | sed -n 's/^BINARY_SHA256=//p')"
echo "macOS arm64 binary: released $released"
echo "                    rebuilt  $local_build ($(rustc --version))"
[ "$released" = "$local_build" ] || { echo "REFUSE: the rebuilt binary differs from the released one; nothing signed" >&2; exit 1; }

# install.sh must trust this key and install this tag.
pub="$(awk '{print $1" "$2}' "$KEY.pub")"
grep -q "^RELEASE_PUBKEY=\"$pub " "$T/rel/install.sh" || { echo "REFUSE: install.sh in $TAG does not trust $KEY.pub" >&2; exit 1; }
BASE_TAG="${TAG%%-*}"   # a dry-run tag (v0.1.0-dryrun.1) ships the installer for v0.1.0
grep -q "^VERSION=\"$BASE_TAG\"$" "$T/rel/install.sh" || { echo "REFUSE: install.sh does not install $BASE_TAG" >&2; exit 1; }

# Sign, then verify as install.sh will.
ssh-keygen -Y sign -f "$KEY" -n "$NAMESPACE" "$T/rel/SHA256SUMS"
printf '%s namespaces="%s" %s\n' "$NAMESPACE" "$NAMESPACE" "$pub" > "$T/allowed_signers"
ssh-keygen -Y verify -f "$T/allowed_signers" -I "$NAMESPACE" -n "$NAMESPACE" -s "$T/rel/SHA256SUMS.sig" < "$T/rel/SHA256SUMS"
"$GH" release upload "$TAG" -R "$REPO" "$T/rel/SHA256SUMS.sig"
echo "SIGNED $TAG: SHA256SUMS.sig uploaded"
if [ "$PUBLISH" = 1 ]; then
  "$GH" release edit "$TAG" -R "$REPO" --draft=false
  echo "PUBLISHED $TAG: https://github.com/$REPO/releases/tag/$TAG"
else
  echo "to publish: $GH release edit $TAG -R $REPO --draft=false"
fi
