#!/usr/bin/env bash
# Does every channel serve release X.Y.Z? Read-only; anyone can run it.
#
#   scripts/check-channels.sh X.Y.Z
#
# The phone app and the host installer must speak the same pairing protocol, so a channel left
# behind is not cosmetic: 1.4.0's AUR package lagging at 1.3.0 broke pairing for every Arch user
# who had the new app. `release.sh ship` ends with this; exit 1 names what is behind.
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
if curl -fsSL -o "$W/app.apk" "$GL/-/releases/permalink/latest/downloads/sudostamp.apk" &&
   grep -q "v$VERSION" <(curl -fsSL "https://gitlab.com/api/v4/projects/ritwick7%2Fsudostamp/releases/permalink/latest" 2>/dev/null); then
  row "GitLab APK (latest)" "v$VERSION"
else
  row "GitLab APK (latest)" "NOT v$VERSION"; fail=1
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
