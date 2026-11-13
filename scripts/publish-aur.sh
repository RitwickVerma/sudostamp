#!/usr/bin/env bash
# Publish release X.Y.Z to the AUR (sudostamp, the host side, and sudostamp-desktop), and check
# that the AUR now serves both.
#
#   scripts/publish-aur.sh X.Y.Z
#
# For each: builds PKGBUILD + .SRCINFO for the tag (checksum of GitLab's tag archive, as makepkg will
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
command -v makepkg >/dev/null || die "makepkg not found: run this on Arch"
# sudostamp-desktop builds with cargo: rustup's (~/.cargo/bin) is fine, it need not be on PATH.
[ -x "$HOME/.cargo/bin/cargo" ] && PATH="$HOME/.cargo/bin:$PATH"
command -v cargo >/dev/null || die "cargo not found: the desktop package builds with it (pacman -S rust, or rustup)"
url="https://gitlab.com/ritwick7/sudostamp/-/archive/v$VERSION/sudostamp-v$VERSION.tar.gz"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
sum="$(curl -fsSL "$url" | sha256sum | cut -d' ' -f1)" || die "cannot download $url (is v$VERSION tagged?)"

# served PKG: the version the AUR's own copy of PKG's PKGBUILD names.
served() { curl -fsSL "https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=$1" 2>/dev/null | sed -n 's/^pkgver=//p'; }

# publish PKG DIR CHECK: DIR's PKGBUILD for this tag, test-built (a package that does not build must
# never reach the AUR), CHECK = a file the package must contain, then pushed and read back.
publish() {
  local pkg="$1" dir="$2" check="$3" w="$W/$1"
  if [ "$(served "$pkg")" = "$VERSION" ]; then echo "AUR already serves $pkg $VERSION"; return 0; fi
  mkdir -p "$w/build"
  cp "$dir/PKGBUILD" "$w/PKGBUILD"
  sed -i "s/^pkgver=.*/pkgver=$VERSION/; s/^pkgrel=.*/pkgrel=1/; s/^sha256sums=.*/sha256sums=('$sum')/" "$w/PKGBUILD"
  cp "$w/PKGBUILD" "$w/build/"
  (cd "$w/build" && makepkg -f --nodeps --noconfirm >"$w/makepkg.log" 2>&1) || {
    tail -20 "$w/makepkg.log" >&2; die "makepkg failed for $pkg $VERSION"; }
  local p; p=$(ls "$w"/build/"$pkg"-"$VERSION"-1-*.pkg.tar.zst)
  bsdtar -xOf "$p" "$check" >/dev/null || die "$pkg has no $check"
  echo "built and checked: $(basename "$p") (source $sum)"

  # A package's first push creates it on the AUR: an empty clone is expected then.
  git clone -q "https://aur.archlinux.org/$pkg.git" "$w/aur" 2>/dev/null || git init -q "$w/aur"
  cp "$w/PKGBUILD" "$w/aur/PKGBUILD"
  (cd "$w/aur" && makepkg --printsrcinfo > .SRCINFO && git add PKGBUILD .SRCINFO && \
    git -c user.name="$(git -C "$OLDPWD" config user.name)" -c user.email="$(git -C "$OLDPWD" config user.email)" \
      commit -q -m "$pkg $VERSION")
  GIT_SSH_COMMAND="ssh -o BatchMode=yes" git -C "$w/aur" push -q "ssh://aur@aur.archlinux.org/$pkg.git" HEAD:master 2>"$w/push.err" || {
    cat "$w/push.err" >&2
    die "push refused. Load the AUR key into the agent (ssh-add ~/.ssh/aur), then: scripts/publish-aur.sh $VERSION"
  }
  # Read it back: the AUR's own copy, not our clone.
  for _ in $(seq 1 12); do [ "$(served "$pkg")" = "$VERSION" ] && break; sleep 5; done
  [ "$(served "$pkg")" = "$VERSION" ] || die "pushed $pkg, but the AUR still serves $(served "$pkg")"
  echo "AUR serves $pkg $VERSION"
}

publish sudostamp packaging/aur usr/lib/sudostamp/install.sh
publish sudostamp-desktop packaging/aur-desktop usr/bin/sudostamp-desktop

# Keep the repository's copies in step (packaging/aur*/), through a merge request.
if [ "$(sed -n 's/^pkgver=//p' packaging/aur/PKGBUILD)" != "$VERSION" ] || \
   [ "$(sed -n 's/^pkgver=//p' packaging/aur-desktop/PKGBUILD)" != "$VERSION" ]; then
  B="packaging/aur-$VERSION"
  git fetch -q origin master
  git worktree add -q -b "$B" "$W/repo" origin/master
  for d in sudostamp:aur sudostamp-desktop:aur-desktop; do
    # Only what this run pushed (a package the AUR already served was not cloned).
    [ -f "$W/${d%%:*}/aur/PKGBUILD" ] || continue
    cp "$W/${d%%:*}/aur/PKGBUILD" "$W/${d%%:*}/aur/.SRCINFO" "$W/repo/packaging/${d#*:}/"
  done
  (cd "$W/repo" && git add packaging/aur packaging/aur-desktop && git commit -q -m "AUR: sudostamp $VERSION" && \
    git push -q -u origin "$B" -o merge_request.create -o merge_request.target=master \
      -o merge_request.remove_source_branch -o "merge_request.title=AUR: sudostamp $VERSION") || \
    echo "publish-aur: could not open the packaging/aur merge request (the AUR itself is updated)" >&2
  git worktree remove --force "$W/repo"; git branch -D "$B" >/dev/null 2>&1 || true
fi
