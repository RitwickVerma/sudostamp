#!/usr/bin/env bash
# Does every channel serve release X.Y.Z? Read-only; anyone can run it.
#
#   scripts/check-channels.sh X.Y.Z
#
# The phone app and the host installer must speak the same pairing protocol, so a channel left
# behind is not cosmetic: 1.4.0's AUR package lagging at 1.3.0 broke pairing for every Arch user
# who had the new app. `release.sh ship` ends with this; exit 1 names what is behind.
# Needs curl, ssh-keygen, python3 and, for the APK certificate, apksigner (Debian: apt install apksigner).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
VERSION="${1:-}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: scripts/check-channels.sh X.Y.Z" >&2; exit 2; }
GL=https://gitlab.com/ritwick7/sudostamp
fail=0
row() { printf '  %-28s %s\n' "$1" "$2"; }
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT

# GitLab: the permanent "latest" links are what the README, the app and Obtainium use.
if curl -fsSL -o "$W/setup.sh" "$GL/-/releases/permalink/latest/downloads/sudostamp-setup.sh" &&
   curl -fsSL -o "$W/setup.sh.sig" "$GL/-/releases/permalink/latest/downloads/sudostamp-setup.sh.sig" &&
   ssh-keygen -Y verify -f keys/allowed_signers -I sudostamp-release -n sudostamp-release \
     -s "$W/setup.sh.sig" < "$W/setup.sh" >/dev/null 2>&1 &&
   grep -q "^# SudoStamp $VERSION " "$W/setup.sh"; then
  row "GitLab installer (latest)" "$VERSION, signature ok"
else
  row "GitLab installer (latest)" "NOT $VERSION or signature fails"; fail=1
fi
# The APK: not just "the Release is named vX.Y.Z" -- the bytes that the permalink serves. The package
# registry accepts a second upload under the same name, so a replaced APK would still sit under the
# right tag. Three checks, all with the tools release.sh and verify-reproducible.sh already use:
#   1. SHA256SUMS verifies against keys/allowed_signers (ssh-keygen -Y verify, namespace
#      sudostamp-release) and lists sudostamp-vX.Y.Z.apk;
#   2. the downloaded APK has exactly that SHA-256;
#   3. apksigner verifies it and its signer certificate is RELEASE_CERT, read from release.sh (one
#      copy of the pin). apksigner comes from PATH or $ANDROID_HOME/build-tools/36.0.0; without it
#      step 3 is reported as NOT checked and counts as a failure (a skipped check must not look green).
apk_state=""
if ! curl -fsSL -o "$W/app.apk" "$GL/-/releases/permalink/latest/downloads/sudostamp.apk" ||
   ! curl -fsSL -o "$W/SHA256SUMS" "$GL/-/releases/permalink/latest/downloads/SHA256SUMS" ||
   ! curl -fsSL -o "$W/SHA256SUMS.sig" "$GL/-/releases/permalink/latest/downloads/SHA256SUMS.sig"; then
  apk_state="download failed"
elif ! ssh-keygen -Y verify -f keys/allowed_signers -I sudostamp-release -n sudostamp-release \
       -s "$W/SHA256SUMS.sig" < "$W/SHA256SUMS" >/dev/null 2>&1; then
  apk_state="SHA256SUMS signature fails"
else
  listed=$(awk -v f="sudostamp-v$VERSION.apk" '$2 == f {print $1}' "$W/SHA256SUMS")
  have=$(sha256sum < "$W/app.apk" | cut -d' ' -f1)
  if [ -z "$listed" ]; then apk_state="signed SHA256SUMS does not list sudostamp-v$VERSION.apk (not $VERSION?)"
  elif [ "$listed" != "$have" ]; then apk_state="APK sha256 $have is not the signed $listed"
  else
    want=$(sed -n 's/^RELEASE_CERT="\(.*\)"$/\1/p' scripts/release.sh | head -1)
    APKSIGNER=$(command -v apksigner || true)
    [ -n "$APKSIGNER" ] || { [ -x "${ANDROID_HOME:-/nonexistent}/build-tools/36.0.0/apksigner" ] && APKSIGNER="$ANDROID_HOME/build-tools/36.0.0/apksigner"; }
    if [ -z "$want" ]; then apk_state="cannot read RELEASE_CERT from scripts/release.sh"
    elif [ -z "$APKSIGNER" ]; then apk_state="hash ok, certificate NOT checked (no apksigner)"
    elif ! "$APKSIGNER" verify "$W/app.apk" >/dev/null 2>&1; then apk_state="apksigner rejects the APK"
    else
      cert=$("$APKSIGNER" verify --print-certs "$W/app.apk" 2>/dev/null \
        | sed -n 's/^Signer #1 certificate SHA-256 digest: //p' | head -1 | tr 'a-f' 'A-F' | sed 's/../&:/g; s/:$//')
      if [ "$cert" = "$want" ]; then apk_state=ok; else apk_state="signed by ${cert:-unknown}, not the release key"; fi
    fi
  fi
fi
if [ "$apk_state" = ok ]; then
  row "GitLab APK (latest)" "v$VERSION, signed listing + release certificate ok"
else
  row "GitLab APK (latest)" "NOT ok: $apk_state"; fail=1
fi

# AUR: its own copy of the PKGBUILD, not the search index (which lags).
# The AUR's RPC: what yay and paru read, updated by the push itself. Not cgit's plain PKGBUILD, which a
# cache in front of it kept at the old version for over an hour after the 1.5.0 push landed.
aur=$(curl -fsSL "https://aur.archlinux.org/rpc/v5/info?arg%5B%5D=sudostamp" 2>/dev/null \
  | python3 -c 'import json,sys
try: r=json.load(sys.stdin)["results"]; print(r[0]["Version"].rsplit("-",1)[0] if r else "")
except Exception: print("")')
if [ "$aur" = "$VERSION" ]; then row "AUR" "$VERSION"; else row "AUR" "${aur:-unreachable} (expected $VERSION)"; fail=1; fi

# Google Play: the public listing shows the version only on the page; best effort, not a gate
# (Play rolls out over days, and a rollout in progress is not a failure).
play=$(curl -fsSL "https://play.google.com/store/apps/details?id=com.ritwick.sudostamp&hl=en" 2>/dev/null \
  | grep -oE '"[0-9]+\.[0-9]+\.[0-9]+"' | tr -d '"' | sort -V | tail -1)
row "Google Play (info)" "${play:-not visible}$([ "${play:-}" = "$VERSION" ] || echo " (rollout or review pending?)")"

exit "$fail"
