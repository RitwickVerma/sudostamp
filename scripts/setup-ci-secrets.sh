#!/usr/bin/env bash
# One-time, OWNER ONLY: lets the tag pipeline's manual `package` job sign releases.
#
#   scripts/setup-ci-secrets.sh
#
# Sets two PROTECTED File variables on gitlab.com/ritwick7/sudostamp and protects the v* tags,
# so only a maintainer's v* tag pipeline ever receives them (merge requests and branches do not):
#   SOPS_AGE_KEY_FILE       the SudoStamp age key (~/.config/sops/age/sudostamp-release.txt). It opens
#                           ONLY sops/sudostamp/release-signing.sops.env -- not ShutUp's vault, nothing else.
#   SUDOSTAMP_SIGNING_SOPS  that vault file (ciphertext), from the infrastructure repo's origin/master.
#
# This stores a private key on GitLab.com, which the maintainer's rules otherwise forbid, so it asks
# first and is never run by an agent. Without it, releases can still be signed locally:
# `scripts/release.sh package X.Y.Z`, then attach dist/ to the GitLab release by hand.
# Undo: glab api -X DELETE projects/ritwick7%2Fsudostamp/variables/<NAME>
#
# Needs: glab logged in as a project Maintainer, the infrastructure checkout, the age key.
set -euo pipefail
cd "$(dirname "$0")/.."
PROJECT="ritwick7%2Fsudostamp"
HOMELAB="${SUDOSTAMP_HOMELAB_INFRA:-$PWD/../homelab-infra}"
AGE_KEY="${SOPS_AGE_KEY_FILE:-$HOME/.config/sops/age/sudostamp-release.txt}"
die() { echo "setup-ci-secrets: $*" >&2; exit 1; }
command -v glab >/dev/null || die "glab is not installed"
glab auth status >/dev/null 2>&1 || die "glab is not logged in (glab auth login)"
[ -f "$AGE_KEY" ] || die "no age key at $AGE_KEY"
[ "$(grep -c 'AGE-SECRET-KEY' "$AGE_KEY")" = 1 ] || die "$AGE_KEY must hold exactly one age key"
[ -d "$HOMELAB/.git" ] || die "no infrastructure checkout at $HOMELAB (set SUDOSTAMP_HOMELAB_INFRA)"

tmp=$(mktemp -d "${XDG_RUNTIME_DIR:-/dev/shm}/ci-secrets.XXXXXX"); chmod 700 "$tmp"
trap 'rm -rf "$tmp"' EXIT
git -C "$HOMELAB" fetch -q origin master
git -C "$HOMELAB" show origin/master:sops/sudostamp/release-signing.sops.env > "$tmp/vault" 2>/dev/null || \
  die "sops/sudostamp/release-signing.sops.env is not on origin/master yet (merge that merge request first)"
SOPS_AGE_KEY_FILE="$AGE_KEY" sops decrypt --input-type dotenv --output-type dotenv "$tmp/vault" >/dev/null || \
  die "$AGE_KEY cannot open the vault"
cp "$AGE_KEY" "$tmp/age"

cat <<MSG
About to configure gitlab.com/ritwick7/sudostamp:
  SOPS_AGE_KEY_FILE       $(age-keygen -y "$AGE_KEY" 2>/dev/null | cut -c1-16)…  PRIVATE key, opens only the SudoStamp vault
  SUDOSTAMP_SIGNING_SOPS  the encrypted vault file
  protected tags          v*  (Maintainers create; no force push)
Both variables are Protected: only pipelines on protected refs (the v* tags) receive them.
MSG
read -r -p "Store the age key on GitLab.com? [y/N] " ans
[ "$ans" = y ] || [ "$ans" = Y ] || die "aborted, nothing was set"

set_var() { # name, file
  if glab api "projects/$PROJECT/variables/$1" >/dev/null 2>&1; then
    glab api -X PUT "projects/$PROJECT/variables/$1" -f variable_type=file -f protected=true -f raw=true -F "value=@$2" >/dev/null
  else
    glab api -X POST "projects/$PROJECT/variables" -f key="$1" -f variable_type=file -f protected=true -f raw=true -F "value=@$2" >/dev/null
  fi
  echo "set $1"
}
set_var SOPS_AGE_KEY_FILE "$tmp/age"
set_var SUDOSTAMP_SIGNING_SOPS "$tmp/vault"
if ! glab api "projects/$PROJECT/protected_tags" | grep -q '"name":"v\*"'; then
  glab api -X POST "projects/$PROJECT/protected_tags" -f name='v*' -f create_access_level=40 >/dev/null
  echo "protected tags v*"
fi
echo; echo "variables now:"
glab api "projects/$PROJECT/variables" | python3 -I -c "
import json,sys
for v in json.load(sys.stdin): print('  %-24s type=%s protected=%s' % (v['key'], v['variable_type'], v['protected']))"
