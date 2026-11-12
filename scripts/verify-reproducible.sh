#!/usr/bin/env bash
# Check that a published release APK is exactly what this source builds: rebuild vX.Y.Z unsigned in
# a temporary worktree, copy the published APK's signature onto it (apksigcopier), and compare the
# bytes. No keys involved -- anyone can run it. This is the check IzzyOnDroid and F-Droid do.
#
#   scripts/verify-reproducible.sh X.Y.Z
#
# Needs: JDK 17 (JAVA_HOME), the Android SDK with build-tools 36.0.0 (ANDROID_HOME or sdk.dir in
# local.properties), curl, and apksigcopier (pip install apksigcopier).
#
# Environment (the CI job `reproducible` sets both; docs/RELEASING.md):
#   VERIFY_WAIT_MINUTES=N   poll up to N minutes for the release to appear before building. A tag
#                           pipeline starts before `release.sh publish` uploads anything.
#   VERIFY_RELEASE_FILES=1  also check what the APK comparison does not cover: SHA256SUMS verifies
#                           against the tag's keys/allowed_signers and lists this APK's hash; the
#                           installer rebuilt from the tag (scripts/bundle-host.sh) is the one it
#                           lists; and the SBOMs, where the release has them, are in that listing,
#                           well formed, and describe this APK. Needs ssh-keygen and python3.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${1:-}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: scripts/verify-reproducible.sh X.Y.Z" >&2; exit 2; }
TAG="v$VERSION"
if [ -z "${ANDROID_HOME:-}" ] && [ -f local.properties ]; then ANDROID_HOME=$(sed -n 's/^sdk\.dir=//p' local.properties); fi
: "${ANDROID_HOME:?set ANDROID_HOME}"; : "${JAVA_HOME:?set JAVA_HOME to a JDK 17}"
export ANDROID_HOME JAVA_HOME PATH="$ANDROID_HOME/build-tools/36.0.0:$JAVA_HOME/bin:$PATH"
command -v apksigcopier >/dev/null || { echo "apksigcopier is not installed (pip install apksigcopier)" >&2; exit 1; }

URL="https://gitlab.com/ritwick7/sudostamp/-/releases/$TAG/downloads"
WAIT="${VERIFY_WAIT_MINUTES:-0}"
if [[ "$WAIT" =~ ^[0-9]+$ ]] && [ "$WAIT" -gt 0 ]; then
  for ((m = 0; ; m++)); do
    # One byte: only whether the release exists yet (a server that ignores Range sends the small APK).
    curl -fsSL -r 0-0 -o /dev/null "$URL/sudostamp.apk" 2>/dev/null && break
    [ "$m" -lt "$WAIT" ] || { echo "$TAG is not published after $WAIT minutes" >&2; exit 1; }
    echo "$TAG is not published yet; waiting ($m of $WAIT minutes)"
    sleep 60
  done
fi

W=$(mktemp -d); trap 'git worktree remove --force "$W/src" 2>/dev/null || true; rm -rf "$W"' EXIT
git fetch -q origin "refs/tags/$TAG:refs/tags/$TAG" 2>/dev/null || true
git worktree add -q --detach "$W/src" "$TAG"
curl -fsSL -o "$W/published.apk" "$URL/sudostamp.apk"
# No signing variables: the build is unsigned, whatever the caller's environment holds.
(cd "$W/src" && env -u SUDOSTAMP_KEYSTORE ./gradlew -q --no-daemon -Dorg.gradle.java.home="$JAVA_HOME" \
  --project-cache-dir "$W/gradle-project" assembleRelease)
apksigcopier copy "$W/published.apk" "$W/src/app/build/outputs/apk/release/app-release-unsigned.apk" "$W/rebuilt.apk"
a=$(sha256sum < "$W/published.apk" | cut -d' ' -f1); b=$(sha256sum < "$W/rebuilt.apk" | cut -d' ' -f1)
echo "published: $a"
echo "rebuilt:   $b"
[ "$a" = "$b" ] || { echo "NOT reproducible" >&2; exit 1; }
echo "reproducible: $TAG is exactly this source"

if [ "${VERIFY_RELEASE_FILES:-0}" = 1 ]; then
  command -v ssh-keygen >/dev/null || { echo "ssh-keygen is not installed" >&2; exit 1; }
  for f in SHA256SUMS SHA256SUMS.sig; do curl -fsSL -o "$W/$f" "$URL/$f"; done
  # The signer list of the tag itself: the same file the app and the README carry (release-check).
  ssh-keygen -Y verify -f "$W/src/keys/allowed_signers" -I sudostamp-release -n sudostamp-release \
    -s "$W/SHA256SUMS.sig" < "$W/SHA256SUMS" >/dev/null || { echo "SHA256SUMS does not verify against keys/allowed_signers" >&2; exit 1; }
  listed() { awk -v f="$1" '$2 == f {print $1}' "$W/SHA256SUMS"; }
  [ "$(listed "sudostamp-$TAG.apk")" = "$a" ] || { echo "the signed SHA256SUMS lists another APK than the published one" >&2; exit 1; }
  echo "SHA256SUMS: signed by the release signer, lists this APK"
  (cd "$W/src" && scripts/bundle-host.sh "$VERSION" >/dev/null)
  [ "$(sha256sum < "$W/src/dist/sudostamp-setup.sh" | cut -d' ' -f1)" = "$(listed sudostamp-setup.sh)" ] || \
    { echo "the installer rebuilt from $TAG is not the one in the signed SHA256SUMS" >&2; exit 1; }
  echo "installer: rebuilt from $TAG, identical to the signed SHA256SUMS entry"
  # SBOMs exist from 1.5.0 on. When listed they must be the signed ones, well formed, and name this APK.
  if [ -n "$(listed "sudostamp-$TAG.apk.cdx.json")" ]; then
    for f in sudostamp.apk.cdx.json sudostamp-setup.cdx.json; do curl -fsSL -o "$W/$f" "$URL/$f"; done
    [ "$(sha256sum < "$W/sudostamp.apk.cdx.json" | cut -d' ' -f1)" = "$(listed "sudostamp-$TAG.apk.cdx.json")" ] && \
      [ "$(sha256sum < "$W/sudostamp-setup.cdx.json" | cut -d' ' -f1)" = "$(listed sudostamp-setup.cdx.json)" ] || \
      { echo "a published SBOM is not the one in the signed SHA256SUMS" >&2; exit 1; }
    python3 -I scripts/sbom.py check "$W/sudostamp.apk.cdx.json" "$W/sudostamp-setup.cdx.json"
    python3 -I scripts/sbom.py names "$W/sudostamp.apk.cdx.json" "$a" || { echo "the APK SBOM does not describe the published APK" >&2; exit 1; }
    echo "SBOMs: in the signed listing, well formed, the APK one names this APK's SHA-256"
  fi
fi
