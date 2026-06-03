#!/usr/bin/env bash
# Update Formula/vaultpow.rb with a new version + sha256 sums.
#
# Called from the release workflow after each tag is published. Can also be
# run locally if you ever need to fix up the formula by hand.
#
# Usage:
#   scripts/update-formula.sh <version> <macos-arm64-sha> <linux-amd64-sha> <linux-arm64-sha>
#
# The sha256 lines in Formula/vaultpow.rb are anchored by `# bump:<asset>`
# trailing comments — keep those markers in lockstep with this script.

set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <version> <macos-arm64-sha> <linux-amd64-sha> <linux-arm64-sha>" >&2
  exit 2
fi

VERSION="$1"
MACOS_ARM64_SHA="$2"
LINUX_AMD64_SHA="$3"
LINUX_ARM64_SHA="$4"

# Validate sha256s look right (64 hex chars). Catches typos / accidentally
# passing the filename instead of just the hash.
for sha in "$MACOS_ARM64_SHA" "$LINUX_AMD64_SHA" "$LINUX_ARM64_SHA"; do
  if ! [[ "$sha" =~ ^[0-9a-f]{64}$ ]]; then
    echo "error: '$sha' doesn't look like a sha256 (expected 64 hex chars)" >&2
    exit 2
  fi
done

# Strip a leading 'v' so the version field stays a plain MAJOR.MINOR.PATCH.
VERSION="${VERSION#v}"

FORMULA="$(dirname "$0")/../Formula/vaultpow.rb"
[[ -f "$FORMULA" ]] || { echo "error: $FORMULA not found" >&2; exit 1; }

# Use a dedicated tmpfile + atomic mv so a crash mid-write can't corrupt
# the formula. -E is GNU/BSD-portable extended regex (works on macOS sed
# too once we use the `-i ''` form below; here we go via tmpfile so we
# don't have to worry about the in-place dialect mismatch at all).
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

awk -v ver="$VERSION" \
    -v sha_macos_arm64="$MACOS_ARM64_SHA" \
    -v sha_linux_amd64="$LINUX_AMD64_SHA" \
    -v sha_linux_arm64="$LINUX_ARM64_SHA" '
{
  # version line: `  version "X.Y.Z"`
  if ($0 ~ /^  version "/) {
    sub(/"[^"]*"/, "\"" ver "\"")
    print
    next
  }
  # sha256 lines: `      sha256 "..." # bump:<asset>`
  if ($0 ~ /# bump:macos-arm64$/) {
    sub(/"[^"]*"/, "\"" sha_macos_arm64 "\"")
    print
    next
  }
  if ($0 ~ /# bump:linux-amd64$/) {
    sub(/"[^"]*"/, "\"" sha_linux_amd64 "\"")
    print
    next
  }
  if ($0 ~ /# bump:linux-arm64$/) {
    sub(/"[^"]*"/, "\"" sha_linux_arm64 "\"")
    print
    next
  }
  print
}
' "$FORMULA" > "$TMP"

# Sanity check: every marker we intended to replace is actually in the
# output. If awk fell through silently we want loud failure, not a stale
# formula committed to main.
for marker in "bump:macos-arm64" "bump:linux-amd64" "bump:linux-arm64"; do
  if ! grep -q "# $marker$" "$TMP"; then
    echo "error: marker '# $marker' missing from updated formula — refusing to write" >&2
    exit 1
  fi
done
if ! grep -q "version \"$VERSION\"" "$TMP"; then
  echo "error: version '$VERSION' did not land in updated formula — refusing to write" >&2
  exit 1
fi

mv "$TMP" "$FORMULA"
trap - EXIT

echo "Updated $FORMULA → version $VERSION"
echo "  macos-arm64 sha256: $MACOS_ARM64_SHA"
echo "  linux-amd64 sha256: $LINUX_AMD64_SHA"
echo "  linux-arm64 sha256: $LINUX_ARM64_SHA"
