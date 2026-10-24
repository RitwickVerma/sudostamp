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
#       The signed build, on the maintainer's machine only (CI never sees a signing key):
#       release-check.sh, both keys from the SOPS vault into a private tmpfs directory wiped on
#       exit, R8 release APK, certificate pinned to RELEASE_CERT below, not debuggable, the
#       single-file host installer, mapping.txt and SHA256SUMS, and SSH signatures (.sig) over
#       the installer and SHA256SUMS -> dist/. Publishes nothing.
#
#   scripts/release.sh publish X.Y.Z
#       package, then upload dist/ to the GitLab package registry and create the Release (asks
#       first). Run from a worktree at the tag: the tag pipeline must be green.
#
#   scripts/release.sh ship X.Y.Z
#       Everything after the release MR is merged, in one go, from any checkout: tags the merge
#       commit, waits for the tag pipeline, runs publish in a temporary worktree (asks once
#       before uploading), removes the worktree, and prepares the AUR update on a branch.
#
# Signing material, read from the maintainer's infrastructure checkout (SUDOSTAMP_HOMELAB_INFRA,
# default ../homelab-infra) at origin/master, so the checkout's own branch does not matter:
#   sops/sudostamp/release-signing.sops.env    the APK keystore and its passwords
#   sops/sudostamp/installer-signing.sops.env  the ed25519 key that signs the installer
#                                              (public half: keys/allowed_signers)
#   SOPS_AGE_KEY_FILE   the age key that opens ONLY these two files;
#                       default ~/.config/sops/age/sudostamp-release.txt.
# Needs: JDK 17 (JAVA_HOME), Android SDK with build-tools 36.0.0 (ANDROID_HOME), sops,
# ssh-keygen; for publish, glab logged in to gitlab.com.
set -euo pipefail
cd "$(dirname "$0")/.."

# SHA-256 of the release signing certificate (CN=SudoStamp, O=Ritwick Verma). Every release APK must
# carry exactly this one: an update signed by any other key cannot be installed over the app, and a
# different key would mean the build did not come from this project's vault. Published in README.md
# and SECURITY.md so users can check a download.
RELEASE_CERT="7B:CB:0B:51:24:61:97:B9:BB:99:77:9E:09:A3:AD:CB:BA:EB:2D:59:A0:ED:EC:F8:D2:E8:BE:67:84:4D:06:57"

die() { echo "release: $*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }
USAGE="usage: scripts/release.sh prepare X.Y.Z | package X.Y.Z | publish X.Y.Z | ship X.Y.Z"
MODE="${1:-}"; VERSION="${2:-}"
case "$MODE" in prepare|package|publish|ship) ;; *) die "$USAGE" ;; esac
# The installer's signatures: verified against this file, which is also what users paste.
SIGNERS=keys/allowed_signers
NAMESPACE=sudostamp-release
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

# ---------------------------------------------------------------- ship: tag -> CI -> publish -> AUR
if [ "$MODE" = ship ]; then
  command -v glab >/dev/null || die "glab is not installed"
  git fetch -q origin master --tags
  # The merge commit of release/X.Y.Z, and nothing else: the tag names exactly what was reviewed.
  MERGE=$(git log origin/master --merges --format='%H %s' | awk -v b="'release/$VERSION'" '$0 ~ b {print $1; exit}')
  [ -n "$MERGE" ] || die "no merge of release/$VERSION on origin/master yet: merge the release MR first"
  if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
    [ "$(git rev-parse "$TAG^{commit}")" = "$MERGE" ] || die "$TAG exists but is not the release merge commit"
    echo "$TAG already tags $MERGE"
  else
    git tag -a "$TAG" -m "SudoStamp $VERSION" "$MERGE" && git push -q origin "$TAG" || die "could not push $TAG"
    echo "tagged $MERGE as $TAG"
  fi
  step "waiting for the $TAG pipeline"
  status=""
  for _ in $(seq 1 120); do                      # up to an hour; the shared runner queues
    status=$(glab api "projects/:id/pipelines?ref=$TAG&per_page=1" 2>/dev/null \
      | python3 -c 'import json,sys
try: p=json.load(sys.stdin); print(p[0]["status"] if p else "none")
except Exception: print("unknown")')
    case "$status" in success) break ;; failed|canceled|skipped) die "the $TAG pipeline $status" ;; esac
    sleep 30
  done
  [ "$status" = success ] || die "the $TAG pipeline did not finish within an hour (last: $status)"
  echo "pipeline: success"
  WT=$(mktemp -d "${TMPDIR:-/tmp}/sudostamp-ship.XXXXXX"); rmdir "$WT"
  cleanup_ship() { git worktree remove --force "$WT" 2>/dev/null || true; }
  trap cleanup_ship EXIT
  git worktree add -q --detach "$WT" "$TAG"
  [ -f local.properties ] && cp local.properties "$WT/"
  HOMELAB="${SUDOSTAMP_HOMELAB_INFRA:-$PWD/../homelab-infra}"
  (cd "$WT" && SUDOSTAMP_HOMELAB_INFRA="$(cd "$HOMELAB" && pwd)" scripts/release.sh publish "$VERSION") || die "publish failed"
  step "AUR"
  if [ -x scripts/update-aur.sh ]; then
    AUR_BRANCH="packaging/aur-$VERSION"
    git worktree remove --force "$WT"
    git worktree add -q -b "$AUR_BRANCH" "$WT" origin/master
    (cd "$WT" && scripts/update-aur.sh "$VERSION" >/dev/null && git add packaging/aur && \
      git commit -q -m "AUR: sudostamp $VERSION" && \
      git push -q -u origin "$AUR_BRANCH" -o merge_request.create -o merge_request.target=master \
        -o merge_request.remove_source_branch -o "merge_request.title=AUR: sudostamp $VERSION") || \
      die "the AUR update failed (the release itself is published)"
    git branch -D "$AUR_BRANCH" >/dev/null 2>&1 || true
    echo "AUR update: merge request opened. After merging, push packaging/aur/ to aur@aur.archlinux.org:sudostamp.git"
  fi
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
scripts/release-check.sh "$VERSION" || die "this tree is not release $VERSION"
if [ "$MODE" = publish ]; then
  git fetch -q origin "refs/tags/$TAG:refs/tags/$TAG" 2>/dev/null || true
  [ "$(git rev-parse HEAD)" = "$(git rev-parse -q --verify "$TAG^{commit}")" ] || \
    die "HEAD is not $TAG: publish from a worktree at the tag (git worktree add --detach /tmp/rel $TAG)"
  command -v glab >/dev/null || die "glab is not installed"
  glab api "projects/:id/releases/$TAG" >/dev/null 2>&1 && die "a GitLab Release for $TAG already exists"
fi
CODE=$(sed -nE 's/^\s*versionCode = ([0-9]+).*/\1/p' "$GRADLE")

step "signing material"
HOMELAB="${SUDOSTAMP_HOMELAB_INFRA:-$PWD/../homelab-infra}"
export SOPS_AGE_KEY_FILE="${SOPS_AGE_KEY_FILE:-$HOME/.config/sops/age/sudostamp-release.txt}"
[ -f "$SOPS_AGE_KEY_FILE" ] || die "no age key at $SOPS_AGE_KEY_FILE"
command -v ssh-keygen >/dev/null || die "ssh-keygen is not installed"
# tmpfs only: never a disk-backed /tmp.
RUNDIR="${XDG_RUNTIME_DIR:-/dev/shm}"
case "$(df -P "$RUNDIR" 2>/dev/null | awk 'NR==2{print $1}')" in tmpfs|shm|none) ;; *)
  [ "$(stat -f -c %T "$RUNDIR" 2>/dev/null)" = tmpfs ] || die "$RUNDIR is not tmpfs" ;; esac
SECRETS=$(mktemp -d "$RUNDIR/sudostamp-signing.XXXXXX")
chmod 700 "$SECRETS"
[ -d "$HOMELAB/.git" ] || die "no infrastructure checkout at $HOMELAB (SUDOSTAMP_HOMELAB_INFRA)"
git -C "$HOMELAB" fetch -q origin master
for v in release-signing installer-signing; do
  git -C "$HOMELAB" show "origin/master:sops/sudostamp/$v.sops.env" > "$SECRETS/$v.sops.env" 2>/dev/null || \
    die "sops/sudostamp/$v.sops.env is not on $HOMELAB origin/master"
done
(umask 077; sops decrypt --input-type dotenv --output-type dotenv "$SECRETS/release-signing.sops.env" > "$SECRETS/signing.env") || \
  die "could not decrypt the signing vault with $SOPS_AGE_KEY_FILE"
(umask 077; sops decrypt --input-type dotenv --output-type dotenv "$SECRETS/installer-signing.sops.env" \
  | sed -n 's/^INSTALLER_KEY_B64=//p' | base64 -d > "$SECRETS/installer") || \
  die "could not decrypt the installer key with $SOPS_AGE_KEY_FILE"
[ -s "$SECRETS/installer" ] || die "the installer vault holds no key"
# The installer key must be the one users verify against.
[ "$(ssh-keygen -y -f "$SECRETS/installer" | awk '{print $2}')" = "$(awk '{print $NF}' "$SIGNERS")" ] || \
  die "the installer key in the vault is not the one in $SIGNERS"
# Parsed, never sourced: the file's contents are data.
while IFS='=' read -r k v; do
  case "$k" in
    KEYSTORE_JKS_B64) printf '%s' "$v" | base64 -d > "$SECRETS/release.jks" ;;
    STORE_PASSWORD) export SUDOSTAMP_KEYSTORE_PASSWORD="$v" ;;
    KEY_ALIAS) export SUDOSTAMP_KEY_ALIAS="$v" ;;
    KEY_PASSWORD) export SUDOSTAMP_KEY_PASSWORD="$v" ;;
  esac
done < "$SECRETS/signing.env"
rm -f "$SECRETS/signing.env" "$SECRETS"/*.sops.env
[ -s "$SECRETS/release.jks" ] && [ -n "${SUDOSTAMP_KEY_ALIAS:-}" ] || die "the vault does not hold a complete keystore"
export SUDOSTAMP_KEYSTORE="$SECRETS/release.jks"
echo "decrypted into $SECRETS (wiped on exit)"

step "signed release build"
# --project-cache-dir inside the tmpfs directory: Gradle records the signing config (the alias,
# and unsalted hashes of both passwords) as task inputs in its execution history, which would
# otherwise stay behind in .gradle/ on disk.
./gradlew -q --no-daemon -Dorg.gradle.java.home="$JAVA_HOME" --project-cache-dir "$SECRETS/gradle-project" \
  ${SUDOSTAMP_GRADLE_ARGS:-} assembleRelease
APK=app/build/outputs/apk/release/app-release.apk
[ -f "$APK" ] || die "no signed APK (was the keystore read?)"
rm -rf "$SECRETS/release.jks" "$SECRETS/gradle-project"
unset SUDOSTAMP_KEYSTORE_PASSWORD SUDOSTAMP_KEY_PASSWORD SUDOSTAMP_KEY_ALIAS SUDOSTAMP_KEYSTORE

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

step "installer signatures"
# What protects the people who run the installer as root: the package registry accepts a
# second upload under the same name, so a file there can be replaced. A replaced file fails
# this signature; users verify it before running anything (README, the app's command).
for f in sudostamp-setup.sh SHA256SUMS; do
  ssh-keygen -Y sign -q -f "$SECRETS/installer" -n "$NAMESPACE" "dist/$f" || die "could not sign $f"
done
wipe; SECRETS=""
for f in sudostamp-setup.sh SHA256SUMS; do
  ssh-keygen -Y verify -f "$SIGNERS" -I sudostamp-release -n "$NAMESPACE" -s "dist/$f.sig" < "dist/$f" >/dev/null || \
    die "the signature over $f does not verify against $SIGNERS"
done
echo "signed and verified: sudostamp-setup.sh.sig, SHA256SUMS.sig"

if [ "$MODE" = package ]; then
  echo "dist/ ready for $TAG (nothing published)"
  exit 0
fi

# ---------------------------------------------------------------- publish: registry + Release
step "publish $TAG"
FILES="sudostamp-$TAG.apk sudostamp-setup.sh sudostamp-setup.sh.sig SHA256SUMS SHA256SUMS.sig mapping-$TAG.txt"
printf '  %s\n' $FILES
if [ "${SUDOSTAMP_YES:-}" != 1 ]; then
  read -r -p "Upload these and create the public GitLab Release $TAG? [yes/no] " answer
  [ "$answer" = yes ] || die "stopped; nothing published"
fi
PKG="projects/:id/packages/generic/sudostamp/$VERSION"
for f in $FILES; do
  glab api -X PUT "$PKG/$f" --input "dist/$f" -H "Content-Type: application/octet-stream" >/dev/null || die "upload of $f failed"
done
# Parsed as JSON, not with sed: the project object nests a namespace with its own "id" and
# "web_url", and the first match (1.4.0's links) was the namespace's -- every link 401'd.
PROJECT=$(glab api projects/:id) || die "cannot read the project from GitLab"
URL=$(printf '%s' "$PROJECT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["web_url"])')
PID=$(printf '%s' "$PROJECT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
API="https://gitlab.com/api/v4/projects/$PID/packages/generic/sudostamp/$VERSION"
APK_SHA=$(awk -v f="sudostamp-$TAG.apk" '$2==f{print $1}' dist/SHA256SUMS)
HOST_SHA=$(awk '$2=="sudostamp-setup.sh"{print $1}' dist/SHA256SUMS)
python3 - "$TAG" "$URL" "$API" "$APK_SHA" "$HOST_SHA" "$RELEASE_CERT" "$(cat "$SIGNERS")" > dist/release.json <<'PY'
import json, sys
tag, url, api, apk_sha, host_sha, cert, signers = sys.argv[1:]
perm = url + "/-/releases/permalink/latest/downloads"
notes = f"""**Phone:** `sudostamp-{tag}.apk` (SHA-256 `{apk_sha}`), signed by the release key `{cert}`.

**Computer** -- download, verify, run:
```
curl -fsSLO {perm}/sudostamp-setup.sh
curl -fsSLO {perm}/sudostamp-setup.sh.sig
echo '{signers}' > sudostamp.signers
ssh-keygen -Y verify -f sudostamp.signers -I sudostamp-release -n sudostamp-release -s sudostamp-setup.sh.sig < sudostamp-setup.sh && sudo bash sudostamp-setup.sh
```
(SHA-256 `{host_sha}`; `SHA256SUMS` is signed the same way.)

Changes: [CHANGELOG.md]({url}/-/blob/{tag}/CHANGELOG.md)."""
def link(name, path=None, kind="package"):
    d = {"name": name, "url": f"{api}/{name}", "link_type": kind}
    if path:
        d["direct_asset_path"] = path
    return d
print(json.dumps({"tag_name": tag, "name": f"SudoStamp {tag}", "description": notes, "assets": {"links": [
    link(f"sudostamp-{tag}.apk", "/sudostamp.apk"),
    link("sudostamp-setup.sh", "/sudostamp-setup.sh"),
    link("sudostamp-setup.sh.sig", "/sudostamp-setup.sh.sig", "other"),
    link("SHA256SUMS", "/SHA256SUMS", "other"),
    link("SHA256SUMS.sig", "/SHA256SUMS.sig", "other"),
    link(f"mapping-{tag}.txt", None, "other"),
]}}))
PY
glab api -X POST projects/:id/releases --input dist/release.json >/dev/null || die "creating the Release failed"
rm -f dist/release.json
step "verify what anyone downloads"
CHK=$(mktemp -d)
for f in sudostamp-setup.sh sudostamp-setup.sh.sig sudostamp.apk; do
  curl -fsSL -o "$CHK/$f" "$URL/-/releases/permalink/latest/downloads/$f" || die "anonymous download of $f failed"
done
ssh-keygen -Y verify -f "$SIGNERS" -I sudostamp-release -n "$NAMESPACE" -s "$CHK/sudostamp-setup.sh.sig" < "$CHK/sudostamp-setup.sh" >/dev/null || \
  die "the published installer does not verify"
[ "$(sha256sum < "$CHK/sudostamp.apk" | cut -d' ' -f1)" = "$APK_SHA" ] || die "the published APK is not the one built"
rm -rf "$CHK"
echo "published $TAG: $URL/-/releases/$TAG"
