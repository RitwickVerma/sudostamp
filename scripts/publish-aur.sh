#!/usr/bin/env bash
# Publish the host side of release X.Y.Z to the AUR, and check that the AUR now serves it.
#
#   scripts/publish-aur.sh X.Y.Z
#
# Builds PKGBUILD + .SRCINFO for the tag (checksum of GitLab's tag archive, as makepkg will
# download it), test-builds the package, commits "sudostamp X.Y.Z" in a fresh clone of the AUR
# repository and pushes it over SSH, then reads the AUR back. Run by `release.sh ship`.
#
# WHY it is part of the release: the phone app and the installer speak one pairing protocol. When
# 1.4.0 changed it, the AUR stayed on 1.3.0 for weeks, and every Arch user with the new app got
# "the phone refused to pair". A release is not done until the AUR has it.
#
# Needs: makepkg (Arch), git, curl, and the AUR key in ssh-agent (ssh-add ~/.ssh/aur): the push
# runs with BatchMode, so it fails at once, with the command to fix it, instead of hanging on a
# passphrase prompt.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${1:-}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: scripts/publish-aur.sh X.Y.Z" >&2; exit 2; }
die() { echo "publish-aur: $*" >&2; exit 1; }
AUR_GIT=ssh://aur@aur.archlinux.org/sudostamp.git
AUR_PLAIN="https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=sudostamp"
command -v makepkg >/dev/null || die "makepkg not found: run this on Arch"

served() { curl -fsSL "$AUR_PLAIN" 2>/dev/null | sed -n 's/^pkgver=//p'; }
if [ "$(served)" = "$VERSION" ]; then echo "AUR already serves $VERSION"; exit 0; fi

W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
cp packaging/aur/PKGBUILD "$W/PKGBUILD"
url="https://gitlab.com/ritwick7/sudostamp/-/archive/v$VERSION/sudostamp-v$VERSION.tar.gz"
sum="$(curl -fsSL "$url" | sha256sum | cut -d' ' -f1)" || die "cannot download $url (is v$VERSION tagged?)"
sed -i "s/^pkgver=.*/pkgver=$VERSION/; s/^pkgrel=.*/pkgrel=1/; s/^sha256sums=.*/sha256sums=('$sum')/" "$W/PKGBUILD"

# A package that does not build must never reach the AUR.
mkdir "$W/build"; cp "$W/PKGBUILD" "$W/build/"
(cd "$W/build" && makepkg -f --nodeps --noconfirm >/dev/null 2>&1) || die "makepkg failed for $VERSION"
pkg=$(ls "$W"/build/sudostamp-"$VERSION"-1-*.pkg.tar.zst)
bsdtar -xOf "$pkg" usr/lib/sudostamp/install.sh >/dev/null || die "the package has no installer"
echo "built and checked: $(basename "$pkg") (source $sum)"

git clone -q https://aur.archlinux.org/sudostamp.git "$W/aur"
cp "$W/PKGBUILD" "$W/aur/PKGBUILD"
(cd "$W/aur" && makepkg --printsrcinfo > .SRCINFO && git add PKGBUILD .SRCINFO && \
  git -c user.name="$(git -C "$OLDPWD" config user.name)" -c user.email="$(git -C "$OLDPWD" config user.email)" \
    commit -q -m "sudostamp $VERSION")
GIT_SSH_COMMAND="ssh -o BatchMode=yes" git -C "$W/aur" push -q "$AUR_GIT" HEAD:master 2>"$W/push.err" || {
  cat "$W/push.err" >&2
  die "push refused. Load the AUR key into the agent (ssh-add ~/.ssh/aur), then: scripts/publish-aur.sh $VERSION"
}

# Read it back: the AUR's own copy, not our clone.
for _ in $(seq 1 12); do [ "$(served)" = "$VERSION" ] && break; sleep 5; done
[ "$(served)" = "$VERSION" ] || die "pushed, but the AUR still serves $(served)"
echo "AUR serves sudostamp $VERSION"

# Keep the repository's copy in step (packaging/aur/), through a merge request.
if [ "$(sed -n 's/^pkgver=//p' packaging/aur/PKGBUILD)" != "$VERSION" ]; then
  B="packaging/aur-$VERSION"
  git fetch -q origin master
  git worktree add -q -b "$B" "$W/repo" origin/master
  cp "$W/aur/PKGBUILD" "$W/aur/.SRCINFO" "$W/repo/packaging/aur/"
  (cd "$W/repo" && git add packaging/aur && git commit -q -m "AUR: sudostamp $VERSION" && \
    git push -q -u origin "$B" -o merge_request.create -o merge_request.target=master \
      -o merge_request.remove_source_branch -o "merge_request.title=AUR: sudostamp $VERSION") || \
    echo "publish-aur: could not open the packaging/aur merge request (the AUR itself is updated)" >&2
  git worktree remove --force "$W/repo"; git branch -D "$B" >/dev/null 2>&1 || true
fi
