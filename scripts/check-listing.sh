#!/usr/bin/env bash
# Store listing (fastlane/metadata/android/en-US): what IzzyOnDroid and F-Droid read. Fails on
# anything they would reject or show wrong. Run by release-check.sh and by CI on every change.
#
#   scripts/check-listing.sh
#
# POSIX tools only (bare CI image): lengths are counted in characters, not bytes, by dropping
# UTF-8 continuation bytes, since `wc -m` in a C-locale image counts bytes.
set -euo pipefail
cd "$(dirname "$0")/.."
M=fastlane/metadata/android/en-US
fail=0
bad() { echo "check-listing: $*" >&2; fail=1; }
len() { LC_ALL=C tr -d '\200-\277\n' < "$1" | wc -c | tr -d ' '; }
limit() { # file max
  [ -s "$1" ] || { bad "$1 missing or empty"; return; }
  [ "$(len "$1")" -le "$2" ] || bad "$1 is $(len "$1") characters (limit $2)"
}
limit "$M/title.txt" 30
limit "$M/short_description.txt" 80
limit "$M/full_description.txt" 4000
grep -q SudoStamp "$M/title.txt" || bad "title must name SudoStamp"
grep -q 'https://gitlab.com/ritwick7/sudostamp' "$M/full_description.txt" || bad "full description must link the source"
for f in "$M"/changelogs/*.txt; do limit "$f" 500; done

png_size() { # prints "W H" of a PNG, or nothing
  [ "$(head -c 8 "$1" | od -An -tx1 | tr -d ' \n')" = 89504e470d0a1a0a ] || return 0
  od -An -tu1 -j16 -N8 "$1" | awk '{print $1*16777216+$2*65536+$3*256+$4, $5*16777216+$6*65536+$7*256+$8}'
}
[ "$(png_size "$M/images/icon.png")" = "512 512" ] || bad "$M/images/icon.png must be a 512x512 PNG"
n=0
for f in "$M"/images/phoneScreenshots/*; do
  [ -e "$f" ] || continue
  [ -n "$(png_size "$f")" ] || bad "$f is not a PNG"
  n=$((n + 1))
done
[ "$n" -ge 2 ] && [ "$n" -le 8 ] || bad "need 2-8 phone screenshots, found $n"
[ "$fail" = 0 ] && echo "check-listing: ok ($n screenshots)"
exit "$fail"
