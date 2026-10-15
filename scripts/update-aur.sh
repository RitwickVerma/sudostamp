#!/usr/bin/env bash
# After a release tag exists on GitLab: set packaging/aur/PKGBUILD to it and regenerate
# .SRCINFO, ready to copy into the AUR repository (ssh://aur@aur.archlinux.org/sudostamp.git).
#
#   scripts/update-aur.sh 1.3.0
#
# The checksum is computed from GitLab's tag archive, which is what makepkg will download.
set -euo pipefail
cd "$(dirname "$0")/../packaging/aur"
ver="${1:?usage: $0 VERSION}"
url="https://gitlab.com/ritwick7/sudostamp/-/archive/v$ver/sudostamp-v$ver.tar.gz"
sum="$(curl -fsSL "$url" | sha256sum | cut -d' ' -f1)"
sed -i "s/^pkgver=.*/pkgver=$ver/; s/^pkgrel=.*/pkgrel=1/; s/^sha256sums=.*/sha256sums=('$sum')/" PKGBUILD
if command -v makepkg >/dev/null; then makepkg --printsrcinfo > .SRCINFO; else echo "run 'makepkg --printsrcinfo > .SRCINFO' on Arch" >&2; fi
echo "PKGBUILD -> $ver ($sum)"
