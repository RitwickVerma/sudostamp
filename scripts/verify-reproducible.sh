#!/usr/bin/env bash
# Check that a published release APK is exactly what this source builds: rebuild vX.Y.Z unsigned in
# a temporary worktree, copy the published APK's signature onto it (apksigcopier), and compare the
# bytes. No keys involved -- anyone can run it. This is the check IzzyOnDroid and F-Droid do.
#
#   scripts/verify-reproducible.sh X.Y.Z
#
# Needs: JDK 17 (JAVA_HOME), the Android SDK with build-tools 36.0.0 (ANDROID_HOME or sdk.dir in
# local.properties), curl, and apksigcopier (pip install apksigcopier).
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${1:-}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: scripts/verify-reproducible.sh X.Y.Z" >&2; exit 2; }
TAG="v$VERSION"
if [ -z "${ANDROID_HOME:-}" ] && [ -f local.properties ]; then ANDROID_HOME=$(sed -n 's/^sdk\.dir=//p' local.properties); fi
: "${ANDROID_HOME:?set ANDROID_HOME}"; : "${JAVA_HOME:?set JAVA_HOME to a JDK 17}"
export ANDROID_HOME JAVA_HOME PATH="$ANDROID_HOME/build-tools/36.0.0:$JAVA_HOME/bin:$PATH"
command -v apksigcopier >/dev/null || { echo "apksigcopier is not installed (pip install apksigcopier)" >&2; exit 1; }

W=$(mktemp -d); trap 'git worktree remove --force "$W/src" 2>/dev/null || true; rm -rf "$W"' EXIT
git fetch -q origin "refs/tags/$TAG:refs/tags/$TAG" 2>/dev/null || true
git worktree add -q --detach "$W/src" "$TAG"
curl -fsSL -o "$W/published.apk" "https://gitlab.com/ritwick7/sudostamp/-/releases/$TAG/downloads/sudostamp.apk"
# No signing variables: the build is unsigned, whatever the caller's environment holds.
(cd "$W/src" && env -u SUDOSTAMP_KEYSTORE ./gradlew -q --no-daemon -Dorg.gradle.java.home="$JAVA_HOME" \
  --project-cache-dir "$W/gradle-project" assembleRelease)
apksigcopier copy "$W/published.apk" "$W/src/app/build/outputs/apk/release/app-release-unsigned.apk" "$W/rebuilt.apk"
a=$(sha256sum < "$W/published.apk" | cut -d' ' -f1); b=$(sha256sum < "$W/rebuilt.apk" | cut -d' ' -f1)
echo "published: $a"
echo "rebuilt:   $b"
[ "$a" = "$b" ] && echo "reproducible: $TAG is exactly this source" || { echo "NOT reproducible" >&2; exit 1; }
