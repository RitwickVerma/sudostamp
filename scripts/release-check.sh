#!/usr/bin/env bash
# Is this tree a well-formed release X.Y.Z? Run by CI on release/* branches and v* tags, and by
# scripts/release.sh (prepare and package).
#
#   scripts/release-check.sh X.Y.Z
#
# Git and POSIX tools only, so it runs in a bare CI image.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${1:-}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: scripts/release-check.sh X.Y.Z" >&2; exit 2; }
GRADLE=app/build.gradle.kts
fail=0
bad() { echo "release-check: $*" >&2; fail=1; }

NAME=$(sed -nE 's/^\s*versionName = "([^"]+)".*/\1/p' "$GRADLE")
CODE=$(sed -nE 's/^\s*versionCode = ([0-9]+).*/\1/p' "$GRADLE")
[ "$NAME" = "$VERSION" ] || bad "versionName is '$NAME', not '$VERSION'"
[[ "$CODE" =~ ^[0-9]+$ ]] || { bad "no numeric versionCode in $GRADLE"; CODE=0; }

# A tag pipeline must be on the tag it claims.
if [ -n "${CI_COMMIT_TAG:-}" ] && [ "$CI_COMMIT_TAG" != "v$VERSION" ]; then bad "tag $CI_COMMIT_TAG is not v$VERSION"; fi

# versionCode only ever goes up: Android refuses to install a lower one over a higher one, and
# a code once published must never name a different build.
for t in $(git tag -l 'v[0-9]*'); do
  [ "$t" = "v$VERSION" ] && continue
  old=$(git show "$t:$GRADLE" 2>/dev/null | sed -nE 's/^\s*versionCode = ([0-9]+).*/\1/p' | head -1)
  [[ "$old" =~ ^[0-9]+$ ]] && [ "$CODE" -le "$old" ] && bad "versionCode $CODE does not exceed $t's ($old)"
done

# Release notes for the stores, and a dated changelog section.
[ -s "fastlane/metadata/android/en-US/changelogs/$CODE.txt" ] || bad "missing fastlane/metadata/android/en-US/changelogs/$CODE.txt"
grep -qE "^## $VERSION — [0-9]{4}-[0-9]{2}-[0-9]{2}$" CHANGELOG.md || bad "CHANGELOG.md has no dated '## $VERSION — YYYY-MM-DD' section"

# The installer's signer, everywhere a user copies it from: the app (signed APK) and the README
# must carry exactly keys/allowed_signers, or a correct installer would fail its own check.
SIGNER_KEY=$(awk '{print $NF}' keys/allowed_signers)
grep -qF "$SIGNER_KEY" app/src/main/java/com/ritwick/sudostamp/MainActivity.kt || bad "the app's setup command does not carry keys/allowed_signers"
grep -qF "$(cat keys/allowed_signers)" README.md || bad "README.md does not carry keys/allowed_signers"

scripts/check-listing.sh || fail=1
[ "$fail" = 0 ] && echo "release-check: $VERSION (versionCode $CODE) is consistent"
exit "$fail"
