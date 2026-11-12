#!/usr/bin/env bash
# Is this tree a well-formed release X.Y.Z? Run by CI on release/* branches and v* tags, and by
# scripts/release.sh (prepare and package).
#
#   scripts/release-check.sh X.Y.Z
#   scripts/release-check.sh X.Y.Z --dist
#
# Git and POSIX tools only, so it runs in a bare CI image. `--dist` checks what `release.sh package`
# left in dist/ instead of the tree (it needs python3 as well; SUDOSTAMP_DIST names another directory).
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${1:-}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: scripts/release-check.sh X.Y.Z" >&2; exit 2; }
GRADLE=app/build.gradle.kts
fail=0
bad() { echo "release-check: $*" >&2; fail=1; }

# dist/ is a complete release: the APK, the installer and both SBOMs exist, are all in SHA256SUMS (the
# file that gets signed, so the SBOMs are signed with it), every listed hash is right, and the SBOMs are
# well formed and describe the APK and the installer they ship beside.
if [ "${2:-}" = --dist ]; then
  D="${SUDOSTAMP_DIST:-dist}"
  [ -s "$D/SHA256SUMS" ] || { bad "$D/SHA256SUMS is missing"; exit 1; }
  for f in "sudostamp-v$VERSION.apk" sudostamp-setup.sh "sudostamp-v$VERSION.apk.cdx.json" sudostamp-setup.cdx.json; do
    [ -s "$D/$f" ] || bad "$D/$f is missing"
    grep -qE "^[0-9a-f]{64}  $f\$" "$D/SHA256SUMS" || bad "$D/SHA256SUMS does not list $f"
  done
  [ "$fail" = 0 ] || exit 1
  (cd "$D" && sha256sum -c --quiet SHA256SUMS) || bad "SHA256SUMS does not match the files it lists"
  python3 -I scripts/sbom.py check "$D/sudostamp-v$VERSION.apk.cdx.json" "$D/sudostamp-setup.cdx.json" >/dev/null || bad "an SBOM is malformed"
  python3 -I scripts/sbom.py names "$D/sudostamp-v$VERSION.apk.cdx.json" "$(sha256sum < "$D/sudostamp-v$VERSION.apk" | cut -d' ' -f1)" || bad "the APK SBOM does not name the APK beside it"
  python3 -I scripts/sbom.py names "$D/sudostamp-setup.cdx.json" "$(sha256sum < "$D/sudostamp-setup.sh" | cut -d' ' -f1)" || bad "the host SBOM does not name the installer beside it"
  [ "$fail" = 0 ] && echo "release-check: dist/ for $VERSION lists the APK, the installer and both SBOMs, and all verify"
  exit "$fail"
fi

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
