#!/usr/bin/env bash
# Release flow for SudoStamp: release branch -> merge request -> tag -> signed package.
#
#   scripts/release.sh prepare X.Y.Z
#       No secrets. Cuts release/X.Y.Z from origin/master in a temporary worktree (your checkout is
#       not touched): bumps versionCode/versionName, dates the "## X.Y.Z — unreleased" CHANGELOG
#       section, runs release-check.sh, pushes the branch and opens a merge request. The owner
#       merges it and tags the merge commit: git tag -a vX.Y.Z -m "SudoStamp X.Y.Z" && git push origin vX.Y.Z
#
#   scripts/release.sh package X.Y.Z
#       The signed build. Run by the tag pipeline's manual `package` job, and locally as a dry run
#       (publishes nothing): release-check.sh, signing key from the SOPS vault into a private tmpfs
#       directory wiped on exit, R8 release APK, certificate pinned to RELEASE_CERT below, not
#       debuggable, the single-file host installer, mapping.txt and SHA256SUMS -> dist/.
#
# Signing material, in this order:
#   SUDOSTAMP_SIGNING_SOPS   path to the encrypted vault file (CI: a protected File variable);
#                            default: sops/sudostamp/release-signing.sops.env in the maintainer's
#                            infrastructure checkout (SUDOSTAMP_HOMELAB_INFRA, default ../homelab-infra),
#                            read from origin/master so the checkout's own branch does not matter.
#   SOPS_AGE_KEY_FILE        age key that opens ONLY this vault file;
#                            default ~/.config/sops/age/sudostamp-release.txt.
# Needs: JDK 17 (JAVA_HOME), Android SDK with build-tools 36.0.0 (ANDROID_HOME), sops.
set -euo pipefail
cd "$(dirname "$0")/.."

# SHA-256 of the release signing certificate (CN=SudoStamp, O=Ritwick Verma). Every release APK must
# carry exactly this one: an update signed by any other key cannot be installed over the app, and a
# different key would mean the build did not come from this project's vault. Published in README.md
# and SECURITY.md so users can check a download.
RELEASE_CERT="7B:CB:0B:51:24:61:97:B9:BB:99:77:9E:09:A3:AD:CB:BA:EB:2D:59:A0:ED:EC:F8:D2:E8:BE:67:84:4D:06:57"

die() { echo "release: $*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }
USAGE="usage: scripts/release.sh prepare X.Y.Z | package X.Y.Z"
MODE="${1:-}"; VERSION="${2:-}"
case "$MODE" in prepare|package) ;; *) die "$USAGE" ;; esac
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "$USAGE"
GRADLE=app/build.gradle.kts
TAG="v$VERSION"

# ---------------------------------------------------------------- prepare: release branch + MR
if [ "$MODE" = prepare ]; then
  git fetch -q origin master --tags
  BRANCH="release/$VERSION"
  git rev-parse -q --verify "refs/tags/$TAG" >/dev/null && die "tag $TAG already exists"
  git ls-remote --exit-code --heads origin "$BRANCH" >/dev/null 2>&1 && die "$BRANCH already exists on origin"
  WT=$(mktemp -d "${TMPDIR:-/tmp}/sudostamp-release.XXXXXX"); rmdir "$WT"
  cleanup_prepare() { git worktree remove --force "$WT" 2>/dev/null || true; git branch -D "$BRANCH" >/dev/null 2>&1 || true; }
  trap cleanup_prepare EXIT
  git worktree add -q -b "$BRANCH" "$WT" origin/master
  (
    cd "$WT"
    OLD_CODE=$(sed -nE 's/^\s*versionCode = ([0-9]+).*/\1/p' "$GRADLE")
    OLD_NAME=$(sed -nE 's/^\s*versionName = "([^"]+)".*/\1/p' "$GRADLE")
    grep -q "^## $VERSION — unreleased$" CHANGELOG.md || \
      die "CHANGELOG.md on master has no '## $VERSION — unreleased' section (write it and the store notes, merge, then prepare)"
    # The first public release keeps the code master already has (it was never published);
    # every later one gets the next code.
    NEW_CODE=$OLD_CODE
    [ "$OLD_NAME" = "$VERSION" ] || NEW_CODE=$((OLD_CODE + 1))
    sed -i -E "s/^(\s*versionCode = )[0-9]+/\1$NEW_CODE/; s/^(\s*versionName = )\"[^\"]+\"/\1\"$VERSION\"/" "$GRADLE"
    sed -i -E "s/^## $VERSION — unreleased$/## $VERSION — $(date -u +%Y-%m-%d)/" CHANGELOG.md
    scripts/release-check.sh "$VERSION"
    git add "$GRADLE" CHANGELOG.md
    git commit -q -m "Release $VERSION" -m "versionCode $OLD_CODE -> $NEW_CODE. After merging, tag the merge commit: git tag -a $TAG -m \"SudoStamp $VERSION\" && git push origin $TAG"
    git push -q -u origin "$BRANCH" \
      -o merge_request.create -o merge_request.target=master -o merge_request.remove_source_branch \
      -o "merge_request.title=Release $VERSION"
  )
  echo "release/$VERSION pushed with a merge request. When its pipeline is green: merge, then tag the merge commit:"
  echo "  git switch master && git pull && git tag -a $TAG -m \"SudoStamp $VERSION\" && git push origin $TAG"
  exit 0
fi

# ---------------------------------------------------------------- package: signed build into dist/
[ -n "${JAVA_HOME:-}" ] || { command -v java >/dev/null && JAVA_HOME=$(dirname "$(dirname "$(readlink -f "$(command -v java)")")"); }
: "${JAVA_HOME:?set JAVA_HOME to a JDK 17}"
export JAVA_HOME PATH="$JAVA_HOME/bin:$PATH"
if [ -z "${ANDROID_HOME:-}" ] && [ -f local.properties ]; then ANDROID_HOME=$(sed -n 's/^sdk\.dir=//p' local.properties); fi
: "${ANDROID_HOME:?set ANDROID_HOME (or sdk.dir in local.properties)}"
BT="$ANDROID_HOME/build-tools/36.0.0"
command -v sops >/dev/null || die "sops is not installed"

SECRETS=""
wipe() { [ -z "$SECRETS" ] || rm -rf "$SECRETS"; }
trap wipe EXIT        # from the start: an early die must not leave decrypted material behind

step "preconditions"
[ -z "$(git status --porcelain)" ] || die "working tree not clean"
# Before anything can fail: a dist/ left by an earlier run must never pass for this run's output.
rm -rf dist
if [ -n "${CI_COMMIT_TAG:-}" ]; then
  [ "$CI_COMMIT_TAG" = "$TAG" ] || die "pipeline tag $CI_COMMIT_TAG is not $TAG"
fi
scripts/release-check.sh "$VERSION" || die "this tree is not release $VERSION"
CODE=$(sed -nE 's/^\s*versionCode = ([0-9]+).*/\1/p' "$GRADLE")

step "signing material"
HOMELAB="${SUDOSTAMP_HOMELAB_INFRA:-$PWD/../homelab-infra}"
VAULT="${SUDOSTAMP_SIGNING_SOPS:-}"
export SOPS_AGE_KEY_FILE="${SOPS_AGE_KEY_FILE:-$HOME/.config/sops/age/sudostamp-release.txt}"
[ -f "$SOPS_AGE_KEY_FILE" ] || die "no age key at $SOPS_AGE_KEY_FILE"
SECRETS=$(mktemp -d "${XDG_RUNTIME_DIR:-/dev/shm}/sudostamp-signing.XXXXXX")
chmod 700 "$SECRETS"
if [ -n "$VAULT" ]; then
  cp "$VAULT" "$SECRETS/vault.sops.env"
else
  [ -d "$HOMELAB/.git" ] || die "no SUDOSTAMP_SIGNING_SOPS and no infrastructure checkout at $HOMELAB"
  git -C "$HOMELAB" fetch -q origin master
  git -C "$HOMELAB" show origin/master:sops/sudostamp/release-signing.sops.env > "$SECRETS/vault.sops.env" 2>/dev/null || \
    die "sops/sudostamp/release-signing.sops.env is not on $HOMELAB origin/master"
fi
(umask 077; sops decrypt --input-type dotenv --output-type dotenv "$SECRETS/vault.sops.env" > "$SECRETS/signing.env") || \
  die "could not decrypt the signing vault with $SOPS_AGE_KEY_FILE"
# Parsed, never sourced: the file's contents are data.
while IFS='=' read -r k v; do
  case "$k" in
    KEYSTORE_JKS_B64) printf '%s' "$v" | base64 -d > "$SECRETS/release.jks" ;;
    STORE_PASSWORD) export SUDOSTAMP_KEYSTORE_PASSWORD="$v" ;;
    KEY_ALIAS) export SUDOSTAMP_KEY_ALIAS="$v" ;;
    KEY_PASSWORD) export SUDOSTAMP_KEY_PASSWORD="$v" ;;
  esac
done < "$SECRETS/signing.env"
rm -f "$SECRETS/signing.env" "$SECRETS/vault.sops.env"
[ -s "$SECRETS/release.jks" ] && [ -n "${SUDOSTAMP_KEY_ALIAS:-}" ] || die "the vault does not hold a complete keystore"
export SUDOSTAMP_KEYSTORE="$SECRETS/release.jks"
echo "decrypted into $SECRETS (wiped on exit)"

step "signed release build"
./gradlew -q --no-daemon -Dorg.gradle.java.home="$JAVA_HOME" ${SUDOSTAMP_GRADLE_ARGS:-} assembleRelease
APK=app/build/outputs/apk/release/app-release.apk
[ -f "$APK" ] || die "no signed APK (was the keystore read?)"
wipe; SECRETS=""

step "verify"
"$BT/apksigner" verify "$APK" || die "apksigner rejects $APK"
CERT=$("$BT/apksigner" verify --print-certs "$APK" | sed -n 's/^Signer #1 certificate SHA-256 digest: //p' | head -1 \
  | tr 'a-f' 'A-F' | sed 's/../&:/g; s/:$//')
[ "$CERT" = "$RELEASE_CERT" ] || die "signed with $CERT, not the release key $RELEASE_CERT"
echo "certificate: $CERT (release key)"
BADGING=$("$BT/aapt2" dump badging "$APK")
printf '%s\n' "$BADGING" | grep -q "versionCode='$CODE' versionName='$VERSION'" || die "APK is not versionCode $CODE / $VERSION"
! printf '%s\n' "$BADGING" | grep -q "application-debuggable" || die "release APK is debuggable"

step "artifacts"
mkdir -p dist
cp "$APK" "dist/sudostamp-$TAG.apk"
cp app/build/outputs/mapping/release/mapping.txt "dist/mapping-$TAG.txt"
scripts/bundle-host.sh "$VERSION" >/dev/null
(cd dist && sha256sum "sudostamp-$TAG.apk" sudostamp-setup.sh > SHA256SUMS && cat SHA256SUMS)
echo "dist/ ready for $TAG (nothing published)"
