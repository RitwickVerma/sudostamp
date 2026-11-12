#!/bin/bash
# Install SudoStamp's host side: pam_rssh, the pinned phone key, and a marked block in
# sudo's PAM stack that asks the phone first and falls through to the password.
#
#   P=192.168.1.50:7777                                  # the phone, from its setup screen
#   sudo tools/install.sh stage --phone $P   # check the fingerprint, pam_rssh, pinned key
#   sudo tools/install.sh test  --phone $P   # prove it on a scratch PAM service
#   sudo tools/install.sh apply --phone $P   # add the block to sudo's PAM file
#   sudo tools/install.sh rollback           # take the block out again
#   tools/install.sh status                  # what is in place
#   sudo tools/install.sh doctor             # is it healthy? read-only; exit 0 OK, 1 FAIL, 2 WARN
#   sudo tools/install.sh uninstall [--yes]  # remove everything SudoStamp installed, nothing else
#
# Options: --fingerprint SHA256:... skips the interactive fingerprint check (the app's "Copy
# setup command" fills it in); --allow-rustup pre-approves a throwaway Rust toolchain when
# the distribution's is too old to build pam_rssh (see build_pam_rssh). The same settings
# are read from SUDOSTAMP_PHONE / SUDOSTAMP_FINGERPRINT / SUDOSTAMP_ALLOW_RUSTUP, and
# SUDOSTAMP_USER=<user> names the user when not run via sudo.
#
# PLATFORMS. Linux: Arch, Debian/Ubuntu, Fedora/RHEL, openSUSE and their derivatives,
# found through /etc/os-release. Each is exercised end to end in CI by tools/test/e2e.sh.
# macOS (13+, via /etc/pam.d/sudo_local) and FreeBSD are written to the same rules but
# NOT tested here: treat them as experimental.
#
# WHY STAGED: the PAM file is the one edit that can lock you out of admin. Testing the same
# lines against a throwaway service first means the risky write happens only after the
# mechanism is proven on this machine.
#
# WHY A MARKED BLOCK, not a replaced file: every distribution's sudo stack is different
# (`@include common-auth`, `auth include system-auth`, a vendor file in /usr/lib/pam.d).
# Writing a whole file from a template is a guess about all of them, and a wrong guess in
# /etc/pam.d/sudo is a lockout. Inserting our lines above the first auth line and leaving
# the rest alone works for every layout, and rollback removes exactly what was added.
#
# DESIGN DECISIONS, each traceable to a line of pam_rssh's source:
#
#   ssh_agent_addr=...  SET EXPLICITLY. lib.rs:176-188 falls back to $SSH_AUTH_SOCK when
#                       this is empty -- an environment variable a user-level process
#                       controls. Never leave it unset.
#   auth_key_file=...   NOT the default ~/.ssh/authorized_keys (auth_keys.rs:101). The
#                       default is user-writable, so a program running as the user could
#                       add its own key. /etc/authorized_keys is root-owned.
#   ${user}             The substitution syntax is the `subst` crate's ${...}, fed by
#                       pam_items.rs (keys: service/user/tty/rhost/ruser). pam_unix's
#                       `%u` does NOT work here and raises OptVarErr -> PAM_SYSTEM_ERR.
#   NO SPACES           in any argument. PAM splits module args on whitespace, so a value
#                       like `cue_prompt=Touch your phone` becomes three args and the two
#                       bare words hit the unknown-option arm -> PAM_SYSTEM_ERR.
#   password fallback   DELIBERATE. `sufficient` + everything below untouched, so a dead
#                       sensor or phone cannot lock you out.
#   timeouts            pam_rssh v1.2.1 opens the agent socket with NO timeout (ssh_agent_auth.rs,
#                       Stream::connect), so a peer that passes the probe and then goes quiet
#                       would hold sudo for good. The build therefore applies
#                       tools/patches/pam_rssh-timeouts.patch (pinned by SHA-256 below; refused
#                       if it differs or does not apply) and records the result in a root-owned
#                       marker next to the backups. `doctor` reports it; `uninstall` removes the
#                       module only when that marker says this installer built it.
#
# Portable bash: macOS still ships bash 3.2, so no associative arrays, no ${x,,}, no mapfile,
# and no GNU-only flags (stat -c, sed -i, install -o root).
set -uo pipefail
# Our own PATH, not the caller's: this runs as root, and where sudoers sets no secure_path a
# python3 or git earlier in the user's PATH would run as root. Homebrew's last, for macOS.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/homebrew/bin
export PATH

PHONE_ADDR="${SUDOSTAMP_PHONE:-}"
# Whose key is pinned: SUDOSTAMP_USER, else the user who ran sudo, else (for a plain
# `status`) whoever is running this.
TARGET_USER="${SUDOSTAMP_USER:-${SUDO_USER:-}}"
[ -z "$TARGET_USER" ] && [ "$(id -u)" -ne 0 ] && TARGET_USER="$(id -un)"
KEYDIR="/etc/authorized_keys"
KEYFILE="${KEYDIR}/${TARGET_USER}.keys"
# What the phone's hardware attestation said about the pinned key (tools/pair.py --attest-out).
# Beside the key file, not in it: pam_rssh reads every line of the key file.
ATTESTFILE="${KEYDIR}/${TARGET_USER}.attestation"
# The one shape a pinned-key line has: exactly what acquire_key accepts, and what uninstall
# treats as "ours".
KEY_RE='ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABB[A-Za-z0-9+/]{87}= sudostamp'
GATE="/usr/local/sbin/sudostamp-is-local"
PROBE="/usr/local/sbin/sudostamp-probe"
# The gate's control flags. NOT `[success=ok default=1]`: in Linux-PAM `ok` makes a
# successful gate count towards the stack's result, after which a failing `sufficient` module
# changes nothing -- on a stack with no required module below (a hand-written one), every
# check failing would still have authenticated. `ignore` makes success mean only "carry on".
# The probe in front of pam_rssh uses the same flags: success carries on, failure skips one line.
GATE_CONTROL='[success=ignore ignore=ignore default=1]'
# How long the LOCAL sensor waits for a finger. Only ever paid at the desk: the gate skips
# pam_fprintd on remote (SSH/mosh) sessions.
FPRINT_TIMEOUT=15
HERE="$(cd "$(dirname "$0")" && pwd)"
# How to tell the user to run us again: `sudostamp` when installed as a package, the bundle's
# file name when run from the single-file download, else the path they used.
PROG="${SUDOSTAMP_PROG:-$0}"

# pam_rssh is built from this exact commit when the platform has no package: tag v1.2.1.
# A tag can be moved; a commit cannot.
RSSH_REPO="https://github.com/z4yx/pam_rssh.git"
RSSH_TAG="v1.2.1"
RSSH_COMMIT="e8dd046c423f85df266c23bcc3d7033bfee81255"
# The one change made to that checkout before building: connect, read and write timeouts (see
# the patch's own comments for the numbers). Pinned like the commit; the patch is looked up
# beside this script (tools/patches/ in a checkout, patches/ in the bundle and the AUR package).
PATCH_NAME="pam_rssh-timeouts.patch"
PATCH_SHA256="35a6bc40580b18bf76ea65064b3cd14a245d7d128e0a823cf2bce5bcdf754893"
# The oldest Rust its Cargo.lock builds with: time-core 0.1.8 needs 1.88. (Debian 13 has
# 1.85, Ubuntu 24.04 1.75: found by building, not by reading.)
CARGO_MIN_MINOR=88

BEGIN_MARK="# >>> SudoStamp >>> managed by tools/install.sh; 'install.sh rollback' removes it"
# The form a 1.3 install wrote, recognised so 'status' can say the block needs updating.
OLD_GATE_CONTROL='[success=ok default=1]'

END_MARK="# <<< SudoStamp <<<"
VENDOR_MARK="# SudoStamp: copied from the vendor file; rollback deletes this file"

say()  { printf '%s\n' "$*"; }
ok()   { printf '  \033[32mOK\033[0m   %s\n' "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
warn() { printf '  \033[33mWARN\033[0m %s\n' "$*"; }
die()  { bad "$*"; exit 1; }

# Temporary files root writes live in ONE private directory (0700, root), created with an
# explicit template so a caller's TMPDIR cannot steer it into a user-writable parent. Names
# derived from a mktemp file in /tmp ("$f.src") are guessable from a directory anyone can
# list, and a pre-planted symlink at such a name would be written through as root.
ROOT_TMP=""
BUILD_DIR=""
cleanup() { rm -rf "${BUILD_DIR:-}" "${ROOT_TMP:-}" "${SUDOSTAMP_BUNDLE_DIR:-}"; }
trap cleanup EXIT
root_tmp() {
  [ -n "$ROOT_TMP" ] || ROOT_TMP="$(mktemp -d /tmp/sudostamp.XXXXXXXX)" || die "mktemp failed"
  echo "$ROOT_TMP"
}

# ------------------------------------------------------------------ platform

OS="$(uname -s)"
FAMILY=""
case "$OS" in
  Linux)
    # ID first, then ID_LIKE: derivatives (Mint, Pop!_OS, Rocky, EndeavourOS, ...) name
    # their parent there.
    ids=""
    if [ -r /etc/os-release ]; then
      ids="$(. /etc/os-release; echo "${ID:-} ${ID_LIKE:-}")"
    fi
    for id in $ids; do
      case "$id" in
        arch|archarm|manjaro|endeavouros) FAMILY=arch; break ;;
        debian|ubuntu|linuxmint|pop|raspbian) FAMILY=debian; break ;;
        fedora|rhel|centos|rocky|almalinux|ol) FAMILY=fedora; break ;;
        opensuse*|suse|sles|sled) FAMILY=suse; break ;;
      esac
    done
    ;;
  Darwin)  FAMILY=macos ;;
  FreeBSD) FAMILY=freebsd ;;
esac

# Where sudo's PAM stack lives, and where an override must be written.
pam_dir() {
  case "$FAMILY" in
    freebsd) echo /usr/local/etc/pam.d ;;
    *)       echo /etc/pam.d ;;
  esac
}
# The file the block goes into. macOS reads /etc/pam.d/sudo_local, which survives OS
# updates; everyone else edits sudo itself.
pam_target() {
  case "$FAMILY" in
    macos) echo /etc/pam.d/sudo_local ;;
    *)     echo "$(pam_dir)/sudo" ;;
  esac
}
PAM_TEST="$(pam_dir)/sudostamp-test"

# Where the module goes on macOS. NOT /usr/local/lib: Intel Homebrew makes /usr/local/lib the
# user's, and a user-writable directory anywhere on the path to a module sudo loads lets
# anything running as the user swap in its own module -- root on the next sudo.
MACOS_MODULE_DIR=/opt/sudostamp/lib

# Create $1 (and its parents) root-owned, and refuse if any directory on its path can be
# written by anyone but root.
root_owned_dir() {
  local d="$1" p
  mkdir -p "$d" || die "cannot create $d"
  chown 0:0 "$d" && chmod 0755 "$d"
  p="$d"
  while [ "$p" != / ] && [ -n "$p" ]; do
    [ -L "$p" ] && die "$p is a symbolic link -- refusing to install a PAM module under it"
    # shellcheck disable=SC2012,SC2046  # ls -ldn, split: the portable way to read owner and mode
    set -- $(ls -ldn "$p")
    [ "$3" = 0 ] || die "$p is not owned by root -- refusing to install a PAM module under it"
    case "$1" in ?????w????*|????????w?*) die "$p is writable by others -- refusing to install a PAM module under it" ;; esac
    p="$(dirname "$p")"
  done
}

# The directory PAM loads bare module names from: wherever pam_unix.so lives.
module_dir() {
  local d
  for d in /usr/lib/security /usr/lib64/security /lib64/security /lib/security \
           /usr/lib/x86_64-linux-gnu/security /lib/x86_64-linux-gnu/security \
           /usr/lib/aarch64-linux-gnu/security /lib/aarch64-linux-gnu/security; do
    [ -f "$d/pam_unix.so" ] && { echo "$d"; return 0; }
  done
  return 1
}

# The record of the module THIS installer built: where it put it, that file's SHA-256 and the
# patch's. Root-owned, in the state directory. It is what lets `uninstall` remove only our own
# module (never a distribution's pam_rssh) and `doctor` say whether the timeouts are in.
# A module that no longer hashes to the recorded value is not ours any more (a package
# upgrade overwrote it, say) and is treated as such.
rssh_marker() { echo "$(state_dir)/pam_rssh.built"; }
sha256_file() { sha256_stdin < "$1"; }
marker_get() { [ -f "$(rssh_marker)" ] && sed -n "s/^$1=//p" "$(rssh_marker)" | head -1; }
# The module file we built, if it is still exactly what we installed.
ours_module() {
  local m h
  m="$(marker_get module)"; h="$(marker_get module_sha256)"
  [ -n "$m" ] && [ -n "$h" ] && [ -f "$m" ] && [ "$(sha256_file "$m")" = "$h" ] && echo "$m"
}
write_marker() {
  local d; d="$(state_dir)"
  mkdir -p "$d" && chown 0:0 "$d" && chmod 0755 "$d" || return 1
  printf 'module=%s\nmodule_sha256=%s\npatch_sha256=%s\ncommit=%s\n' \
    "$1" "$(sha256_file "$1")" "$PATCH_SHA256" "$RSSH_COMMIT" | write_atomic "$(rssh_marker)"
}
# patched | stale (built with a different patch than this installer carries) | unpatched
rssh_state() {
  ours_module >/dev/null || { echo unpatched; return; }
  [ "$(marker_get patch_sha256)" = "$PATCH_SHA256" ] && echo patched || echo stale
}
# Does the package manager own this file? Then it is not ours to replace or delete.
pkg_owns() {
  local r; r="$(readlink -f "$1" 2>/dev/null || echo "$1")"
  case "$FAMILY" in
    arch)         pacman -Qo "$1" >/dev/null 2>&1 ;;
    debian)       dpkg -S "$1" >/dev/null 2>&1 || dpkg -S "$r" >/dev/null 2>&1 ;;
    fedora|suse)  rpm -qf "$1" >/dev/null 2>&1 ;;
    freebsd)      pkg which "$1" >/dev/null 2>&1 ;;
    *)            return 1 ;;
  esac
}

# Find an installed pam_rssh WITHOUT assuming its filename: Arch's package installs
# pam_rssh.so, a bare cargo build produces libpam_rssh.so. Checking only one once made a
# successful install read as a failure. The one we built wins: it may sit beside a packaged one.
find_pam_rssh() {
  local d c
  ours_module && return 0
  case "$FAMILY" in
    macos)   [ -f "$MACOS_MODULE_DIR/pam_rssh.so" ] && { echo "$MACOS_MODULE_DIR/pam_rssh.so"; return 0; }; return 1 ;;
    freebsd) for c in /usr/local/lib/pam_rssh.so /usr/local/lib/security/pam_rssh.so; do
               [ -f "$c" ] && { echo "$c"; return 0; }; done; return 1 ;;
  esac
  d="$(module_dir)" || return 1
  for c in "$d/pam_rssh.so" "$d/libpam_rssh.so"; do
    [ -f "$c" ] && { echo "$c"; return 0; }
  done
  return 1
}

# How the PAM line names the module: bare on Linux (PAM's search path), absolute on
# OpenPAM, where third-party modules live outside the system directory.
module_ref() {
  local m; m="$(find_pam_rssh)" || return 1
  case "$FAMILY" in
    macos|freebsd) echo "$m" ;;
    *)             basename "$m" ;;
  esac
}

need_root() {
  local more=" --phone <phone-ip>:7777"
  case "$1" in rollback|uninstall|doctor) more="" ;; esac
  [ "$(id -u)" -eq 0 ] || { echo "This needs root. Run: sudo $PROG $1$more" >&2; exit 1; }
}
need_platform() {
  [ -n "$FAMILY" ] || die "unsupported platform ($OS, /etc/os-release: ${ids:-none}). See README.md for the lines to add by hand."
}
# host:port, strictly: this string is written into a PAM configuration line. An IPv4 address
# or a bracketed IPv6 address ([fd00::1]:7777), and a port 1-65535 -- nothing else, and checked
# character by character FIRST: a test that matches one line (grep -x) passed a value whose
# second line was a whole PAM rule. No host names either: pam_rssh parses only literal
# addresses, so a name could never work at sudo time anyway.
# Is $1 an address fit to go into a PAM line? (need_phone's check, for callers that must not exit.)
phone_valid() {
  local ok=0
  case "$1" in
    *[!0-9A-Fa-f.:\[\]]*) ok=0 ;;                       # any other character, newline included
    *) python3 -I - "$1" <<'PY' && ok=1 ;;
import ipaddress, sys
v = sys.argv[1]
host, _, port = v.rpartition(":")
try:
    if host.startswith("[") and host.endswith("]"):
        ipaddress.IPv6Address(host[1:-1])
    else:
        ipaddress.IPv4Address(host)
    if not (port.isdigit() and 1 <= int(port) <= 65535 and str(int(port)) == port):
        raise ValueError
except ValueError:
    sys.exit(1)
PY
  esac
  [ "$ok" = 1 ]
}
need_phone() {
  if [ -z "$PHONE_ADDR" ]; then
    echo "Which phone? Pass --phone <phone-ip>:7777 (the address on the app's pairing screen)" >&2; exit 2
  fi
  phone_valid "$PHONE_ADDR" || {
    echo "--phone must be an address and port, e.g. 192.168.1.50:7777 or [fd00::1]:7777" >&2; exit 2
  }
}
need_user() {
  if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = root ] || ! id "$TARGET_USER" >/dev/null 2>&1; then
    echo "Run via sudo from your own account, or set SUDOSTAMP_USER=<user>" >&2
    exit 2
  fi
}

# Root-owned and world-readable, numerically: macOS and FreeBSD have no `root` group.
own_root() { chown 0:0 "$@" && chmod 0644 "$@"; }

# Backups of sudo's PAM file. NOT next to it: every file in /etc/pam.d is a PAM service that
# any program may name, and 1.3 left a sudo.bak-<time> there on every apply.
state_dir() {
  case "$FAMILY" in
    macos) echo /var/db/sudostamp ;;
    *)     echo /var/lib/sudostamp ;;
  esac
}
backup_dir() { echo "$(state_dir)/backups"; }
# Copy $1 into the backup directory; prints the copy's path.
backup_of() {
  local d; d="$(backup_dir)"
  mkdir -p "$d" && chown 0:0 "$d" && chmod 0700 "$d" || return 1
  local b
  b="$d/$(basename "$1").bak-$(date -u +%Y%m%dT%H%M%SZ)"
  cp -p "$1" "$b" && echo "$b"
}
# Move backups an older version left inside the PAM directory into the backup directory.
tidy_old_backups() {
  local target="$1" b d moved=0
  d="$(backup_dir)"
  for b in "${target}".bak-*; do
    [ -f "$b" ] || continue
    mkdir -p "$d" && chown 0:0 "$d" && chmod 0700 "$d" || return 0
    mv -f "$b" "$d/" && moved=$((moved + 1))
  done
  [ "$moved" -eq 0 ] || ok "moved $moved old backup(s) of $target out of $(dirname "$target") into $d"
}
# Every backup of $1 without pam_rssh, oldest first (names end in a UTC timestamp).
clean_backups() {
  local b
  for b in "$(backup_dir)/$(basename "$1")".bak-* "${1}".bak-*; do
    [ -f "$b" ] || continue
    grep -q pam_rssh "$b" || echo "$b"
  done | awk -F'.bak-' '{print $NF "\t" $0}' | sort | cut -f2-
}

# Write stdin to $1 atomically: sudo only ever sees the old file or the complete new one.
# Writing in place left a window -- a full disk, a kill mid-write -- with a truncated PAM
# file, which is a lockout.
write_atomic() {
  local tmp="$1.sudostamp-new"
  cat > "$tmp" || { rm -f "$tmp"; die "could not write $tmp"; }
  own_root "$tmp" && mv -f "$tmp" "$1"
}

# ------------------------------------------------------------------ packages

pkg_install() {
  case "$FAMILY" in
    arch)    pacman -S --needed --noconfirm "$@" ;;
    debian)  DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "$@" ;;
    fedora)  dnf install -y -q "$@" ;;
    suse)    zypper -q --non-interactive install -y "$@" ;;
    freebsd) pkg install -y "$@" ;;
    macos)   sudo -u "$TARGET_USER" brew install "$@" ;;
  esac
}

# What the host needs to fetch the key and run the check (python3, ssh-keygen), and to
# fetch pam_rssh's source (git, curl) -- installed only where the COMMAND is missing. Asking
# for a package anyway is not harmless: RHEL images ship curl-minimal, and requesting
# `curl` there is a conflict that fails the whole install.
base_deps() {
  local missing="" c
  for c in python3 ssh-keygen git curl; do
    command -v "$c" >/dev/null 2>&1 || missing="$missing $c"
  done
  [ -z "$missing" ] && return 0
  [ "$FAMILY" = macos ] && die "missing:$missing -- install the Xcode Command Line Tools (xcode-select --install)"
  local pkgs=""
  for c in $missing; do
    case "$FAMILY:$c" in
      arch:python3)        pkgs="$pkgs python" ;;
      arch:ssh-keygen)     pkgs="$pkgs openssh" ;;
      debian:ssh-keygen)   pkgs="$pkgs openssh-client" ;;
      fedora:ssh-keygen|suse:ssh-keygen) pkgs="$pkgs openssh-clients" ;;
      freebsd:ssh-keygen|freebsd:curl|freebsd:git) [ "$c" = ssh-keygen ] || pkgs="$pkgs $c" ;;
      debian:curl)         pkgs="$pkgs curl ca-certificates" ;;
      *)                   pkgs="$pkgs $c" ;;
    esac
  done
  [ "$FAMILY" = debian ] && apt-get update -q >/dev/null
  # shellcheck disable=SC2086  # word-splitting the package list is the point
  pkg_install $pkgs
}
build_deps() {
  case "$FAMILY" in
    arch)    pkg_install rust gcc pkgconf openssl pam ;;
    debian)  apt-get update -q >/dev/null; pkg_install cargo gcc libc6-dev pkg-config libssl-dev libpam0g-dev ;;
    fedora)
      # RHEL and its rebuilds keep pam-devel in the CodeReady Builder repo, off by default.
      if ! dnf -q list pam-devel >/dev/null 2>&1; then
        pkg_install dnf-plugins-core && dnf config-manager --set-enabled crb
      fi
      pkg_install cargo gcc pkgconf-pkg-config openssl-devel pam-devel ;;
    suse)    pkg_install cargo gcc pkg-config libopenssl-devel pam-devel ;;
    macos)   pkg_install rust openssl@3 pkg-config ;;
  esac
}

# A cargo that can read pam_rssh's lockfile. Older stable distributions ship a newer
# toolchain beside the default one: Debian 12 as cargo-web, Ubuntu LTS as cargo-1.NN.
cargo_ok() {
  local v; v="$("$1" --version 2>/dev/null | awk '{print $2}')" || return 1
  [ "${v%%.*}" = 1 ] && [ "$(echo "$v" | cut -d. -f2)" -ge "$CARGO_MIN_MINOR" ]
}
find_cargo() {
  local c
  for c in cargo /usr/lib/rust-web/bin/cargo /usr/bin/cargo-web; do
    command -v "$c" >/dev/null 2>&1 && cargo_ok "$c" && { command -v "$c"; return 0; }
  done
  for c in $(ls /usr/bin/cargo-1.* 2>/dev/null | sort -t. -k2 -n -r); do
    cargo_ok "$c" && { echo "$c"; return 0; }
  done
  return 1
}
newer_cargo() {
  local p
  [ "$FAMILY" = debian ] || return 1
  if apt-cache show cargo-web >/dev/null 2>&1; then pkg_install cargo-web rustc-web && return 0; fi
  p="$(apt-cache search --names-only '^cargo-1\.[0-9]+$' | awk '{print $1}' | sort -t. -k2 -n | tail -1)"
  [ -n "$p" ] && pkg_install "$p" "rustc-${p#cargo-}"
}

# Last resort when the distribution has no new-enough Rust: the official rustup, installed
# into the build directory and deleted with it. Nothing lands in the user's home or PATH.
# It downloads and runs a toolchain, so it needs consent: SUDOSTAMP_ALLOW_RUSTUP=1, or a
# yes at the prompt. The binary is checked against the checksum rust-lang publishes.
rustup_cargo() {
  local work="$1" triple answer
  case "$(uname -m)" in
    x86_64|amd64) triple=x86_64 ;;
    aarch64|arm64) triple=aarch64 ;;
    *) return 1 ;;
  esac
  case "$OS" in
    Linux)  triple="$triple-unknown-linux-gnu" ;;
    Darwin) triple="$triple-apple-darwin" ;;
    *) return 1 ;;
  esac
  if [ "${SUDOSTAMP_ALLOW_RUSTUP:-}" != 1 ]; then
    # stderr: this runs inside $(...), whose stdout is the cargo path.
    say "     The system Rust is too old to build pam_rssh (needs 1.$CARGO_MIN_MINOR)." >&2
    read -r -p "     Download a temporary toolchain with rustup (deleted afterwards)? [yes/no] " answer
    [ "$answer" = yes ] || return 1
  fi
  local url="https://static.rust-lang.org/rustup/dist/$triple/rustup-init"
  local dir="$work/rust" sum
  sudo -u "$TARGET_USER" mkdir -p "$dir"
  sudo -u "$TARGET_USER" curl -fsSL --proto '=https' --tlsv1.2 -o "$dir/rustup-init" "$url" || return 1
  sum="$(curl -fsSL --proto '=https' --tlsv1.2 "$url.sha256" | awk '{print $1}')"
  # Read and chmod AS THE USER: the directory is theirs, and root following a symlink they
  # planted there (chmod -> /etc/shadow) would be a privilege escalation.
  [ -n "$sum" ] && [ "$(sudo -u "$TARGET_USER" cat "$dir/rustup-init" | sha256_stdin)" = "$sum" ] || \
    { bad "rustup-init checksum mismatch" >&2; return 1; }
  sudo -u "$TARGET_USER" chmod 0755 "$dir/rustup-init"
  sudo -u "$TARGET_USER" env RUSTUP_HOME="$dir/rustup" CARGO_HOME="$dir/cargo" \
    "$dir/rustup-init" -y -q --no-modify-path --profile minimal --default-toolchain stable >/dev/null 2>&1 || return 1
  echo "$dir/cargo/bin/cargo"
}
sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | awk '{print $1}'
  else shasum -a 256 | awk '{print $1}'; fi
}

# Build the pinned commit as the invoking user (never compile as root), then install the
# one file as root.
build_pam_rssh() {
  local cargo dest
  RUSTUP_ENV=()
  build_deps || die "could not install build dependencies"
  # Global, not local: the EXIT trap fires after this function's locals are gone.
  BUILD_DIR="$(sudo -u "$TARGET_USER" mktemp -d)"
  local work="$BUILD_DIR"
  # EXIT, not RETURN: die() exits, and the checkout (and any rustup) must not outlive it.
  trap cleanup EXIT
  say "  building pam_rssh $RSSH_TAG (a few minutes)"
  sudo -u "$TARGET_USER" git -c advice.detachedHead=false clone -q --depth 1 --branch "$RSSH_TAG" \
      --recurse-submodules --shallow-submodules "$RSSH_REPO" "$work/pam_rssh" || die "git clone failed"
  # As the user: root reading a user-owned checkout trips git's safe.directory check.
  [ "$(sudo -u "$TARGET_USER" git -C "$work/pam_rssh" rev-parse HEAD)" = "$RSSH_COMMIT" ] || \
    die "pam_rssh $RSSH_TAG is not commit $RSSH_COMMIT -- refusing to build a moved tag"
  ok "source is commit $RSSH_COMMIT"
  apply_timeout_patch "$work/pam_rssh"

  cargo="$(find_cargo)" || { newer_cargo >/dev/null 2>&1; cargo="$(find_cargo)"; } || \
    cargo="$(rustup_cargo "$work")" || \
    die "no Rust >= 1.$CARGO_MIN_MINOR. Install a current toolchain (https://rustup.rs) and re-run."
  # Set here, not in rustup_cargo: that ran in a $(...) subshell.
  case "$cargo" in "$work"/rust/*) RUSTUP_ENV=("RUSTUP_HOME=$work/rust/rustup" "CARGO_HOME=$work/rust/cargo") ;; esac
  ok "toolchain: $(sudo -u "$TARGET_USER" env "${RUSTUP_ENV[@]}" "$cargo" --version)"
  # A versioned cargo must drive ITS rustc, not the old default one: cargo-1.91 pairs with
  # rustc-1.91 beside it, a cargo in a private bin dir with the rustc in that same dir.
  local rustc
  rustc="$(dirname "$cargo")/$(basename "$cargo" | sed 's/^cargo/rustc/')"
  [ -x "$rustc" ] || rustc="$(dirname "$cargo")/rustc"
  [ -x "$rustc" ] || die "no rustc beside $cargo"

  local env=(env "${RUSTUP_ENV[@]}" "RUSTC=$rustc")
  [ "$FAMILY" = macos ] && env+=("OPENSSL_DIR=$(sudo -u "$TARGET_USER" brew --prefix openssl@3)")
  (cd "$work/pam_rssh" && sudo -u "$TARGET_USER" "${env[@]}" "$cargo" build --release --locked -q) || \
    die "cargo build failed"

  case "$FAMILY" in
    macos) dest="$MACOS_MODULE_DIR/pam_rssh.so"; root_owned_dir "$MACOS_MODULE_DIR" ;;
    *)     dest="$(module_dir)/pam_rssh.so" || die "no PAM module directory found"
           # A package owns this name: put ours beside it rather than over it, or the next
           # upgrade of that package silently takes the timeouts out again (and uninstall
           # could never tell which file is whose). find_pam_rssh prefers ours.
           if pkg_owns "$dest"; then dest="$(module_dir)/pam_rssh_sudostamp.so"; fi ;;
  esac
  local built="$work/pam_rssh/target/release/libpam_rssh.so"
  [ -f "$built" ] || built="$work/pam_rssh/target/release/libpam_rssh.dylib"
  # Copied out BY THE USER (root never opens a path inside their directory: a symlink there
  # to /etc/shadow would otherwise be published world-readable), then checked to really be a
  # shared library before it goes anywhere PAM will load it.
  # shellcheck disable=SC2024  # intended: read as the user, write (the redirect) as root
  sudo -u "$TARGET_USER" cat "$built" > "$dest.sudostamp-new" || die "could not read the built module"
  case "$(head -c 4 "$dest.sudostamp-new" | od -An -tx1 | tr -d ' \n')" in
    7f454c46|cffaedfe|cefaedfe) ;;          # ELF, Mach-O 64/32
    *) rm -f "$dest.sudostamp-new"; die "the built module is not a shared library" ;;
  esac
  own_root "$dest.sudostamp-new" && mv -f "$dest.sudostamp-new" "$dest" || die "could not install $dest"
  # SELinux (Fedora/RHEL): a file copied from a build dir keeps the wrong label, and PAM
  # then fails to load it with a misleading "cannot open shared object".
  command -v restorecon >/dev/null 2>&1 && restorecon "$dest"
  write_marker "$dest" || die "could not record the build in $(state_dir)"
  ok "installed $dest (patched: connect/read/write timeouts)"
}

# Apply the pinned timeouts patch to the checkout $1 (user-owned). The patch is read AS THE
# USER like every other file from this directory, but into a root-private copy that is hashed
# and then applied from: what is checked is what is used. Refuses on any mismatch; a build
# without the timeouts is not "the same, but slower", it is the stall the patch exists to close.
apply_timeout_patch() {
  local src="$HERE/patches/$PATCH_NAME" copy
  root_tmp >/dev/null            # set ROOT_TMP in THIS shell, not in the $(...) below
  copy="$ROOT_TMP/$PATCH_NAME"
  # shellcheck disable=SC2024  # intended: read as the user, write (the redirect) as root
  sudo -u "$TARGET_USER" cat "$src" > "$copy" 2>/dev/null || die "cannot read $src"
  [ "$(sha256_file "$copy")" = "$PATCH_SHA256" ] || \
    die "$src does not match its pinned SHA-256 -- refusing to build pam_rssh with it"
  sudo -u "$TARGET_USER" git -C "$1" apply --check - < "$copy" 2>/dev/null || \
    die "$PATCH_NAME does not apply to pam_rssh $RSSH_COMMIT -- refusing to build without it"
  sudo -u "$TARGET_USER" git -C "$1" apply - < "$copy" || die "could not apply $PATCH_NAME"
  ok "timeouts patch applied ($PATCH_NAME, sha256 $(printf '%.12s' "$PATCH_SHA256")...)"
}

install_pam_rssh() {
  local mod
  if mod="$(find_pam_rssh)"; then
    case "$(rssh_state)" in
      patched) ok "pam_rssh already installed, with timeouts: $mod"; return 0 ;;
      stale)   say "  $mod was built with an older timeouts patch: rebuilding" ;;
      *)
        # FreeBSD installs the package and cannot patch it: say so, once, and carry on.
        if [ "$FAMILY" = freebsd ]; then
          warn "pam_rssh already installed: $mod -- its build has NO timeouts (FreeBSD uses the package)"
          return 0
        fi
        say "  $mod has no timeouts (installed by 1.4 or earlier, or by a package): building the patched one" ;;
    esac
  fi
  case "$FAMILY" in
    # Arch too: an AUR helper would install whatever the AUR package says today, with no
    # version or commit pin and no review. The pinned build below is the same everywhere.
    freebsd)
      pkg_install pam_rssh || die "pkg install pam_rssh failed"
      warn "pam_rssh from the FreeBSD package has NO timeouts: a peer that stalls after the probe can hold sudo" ;;
    *)
      build_pam_rssh ;;
  esac
  mod="$(find_pam_rssh)" || die "pam_rssh not found after install"
  ok "module: $mod"
}

# Install one of our helper scripts ($1, from tools/) as root-owned $2.
install_helper() {
  mkdir -p "$(dirname "$2")"
  # Read as the user, for the same reason as the module: never follow their symlinks as root.
  # shellcheck disable=SC2024  # intended: read as the user, write (the redirect) as root
  sudo -u "$TARGET_USER" cat "$HERE/$1" > "$2.sudostamp-new" && \
    chown 0:0 "$2.sudostamp-new" && chmod 0755 "$2.sudostamp-new" && mv -f "$2.sudostamp-new" "$2"
}
# The local-vs-remote gate, only where a local sensor can exist (Linux with pam_fprintd), and
# the reachability probe, wherever the PAM syntax can skip a line on its answer (Linux-PAM).
install_helpers() {
  linux_pam || return 0
  install_helper sudostamp-probe.sh "$PROBE" || die "could not install $PROBE"
  if has_fprintd; then
    install_helper sudostamp-is-local.sh "$GATE" || die "could not install $GATE"
    ok "local fingerprint reader found: it is tried first at the desk"
  fi
}
# Linux-PAM, with its [value=action] syntax. OpenPAM (macOS, FreeBSD) has no way to skip a line.
linux_pam() { [ "$OS" = Linux ]; }
has_fprintd() {
  [ "$OS" = Linux ] || return 1
  local d; d="$(module_dir)" || return 1
  [ -f "$d/pam_fprintd.so" ]
}

# True when sudo authenticates as the TARGET (root), not the invoking user: `Defaults
# targetpw` (openSUSE's default), `rootpw` or `runaspw`, without a per-user `!` override.
# PAM then sees user=root, so pam_rssh looks for root.keys and the phone is never asked --
# sudo just wants root's password, as if SudoStamp were not there. Reported, never edited:
# sudoers is the user's policy, not ours.
sudo_auths_as_root() {
  local files="" f
  for f in /etc/sudoers /usr/etc/sudoers /usr/local/etc/sudoers /etc/sudoers.d/* /usr/etc/sudoers.d/*; do
    [ -f "$f" ] && files="$files $f"
  done
  [ -n "$files" ] || return 1
  # shellcheck disable=SC2086
  grep -hE '^[[:space:]]*Defaults[[:space:]][^#]*(targetpw|rootpw|runaspw)' $files 2>/dev/null \
    | grep -vqE '!(targetpw|rootpw|runaspw)' || return 1
  # shellcheck disable=SC2086
  ! grep -hqE "^[[:space:]]*Defaults:${TARGET_USER}[[:space:]][^#]*!(targetpw|rootpw|runaspw)" $files 2>/dev/null
}
warn_targetpw() {
  sudo_auths_as_root || return 0
  warn "sudo here asks for the TARGET's (root's) password: 'Defaults targetpw' or 'rootpw' is set."
  say  "     The phone would never be asked. To use SudoStamp, authenticate as yourself instead:"
  say  "         echo 'Defaults:$TARGET_USER !targetpw, !rootpw, !runaspw' | sudo tee /etc/sudoers.d/50-sudostamp"
  say  "         sudo chmod 0440 /etc/sudoers.d/50-sudostamp && sudo visudo -cf /etc/sudoers.d/50-sudostamp"
  say  "     (and make sure $TARGET_USER is allowed to sudo, e.g. in the wheel group)."
}

# ------------------------------------------------------------------ the block

# Our lines, on Linux-PAM:
#   gate   (only with a local reader) remote session? then skip the reader
#   reader (only with a local reader) pam_fprintd, sufficient
#   probe  phone not answering with this user's key within seconds? then skip pam_rssh
#   phone  pam_rssh, sufficient
# Nothing here can grant anything by itself: only pam_fprintd and pam_rssh say yes, and both
# are `sufficient` -- on failure the stack below (the password) decides, untouched. OpenPAM has
# no skipping syntax, so there it is the phone line alone.
block_lines() {
  local mod; mod="$(module_ref)" || die "pam_rssh is not installed -- run 'stage' first"
  if linux_pam && has_fprintd; then
    printf 'auth       %s  pam_exec.so quiet %s\n' "$GATE_CONTROL" "$GATE"
    printf 'auth       sufficient   pam_fprintd.so timeout=%s max-tries=1\n' "$FPRINT_TIMEOUT"
  fi
  if linux_pam; then
    printf 'auth       %s  pam_exec.so quiet %s phone=%s keys=%s\n' "$GATE_CONTROL" "$PROBE" "$PHONE_ADDR" "$KEYDIR"
  fi
  printf 'auth       sufficient   %s ssh_agent_addr=%s auth_key_file=%s/${user}.keys cue cue_prompt=SudoStamp-approve-on-your-phone-(up-to-60s)\n' \
    "$mod" "$PHONE_ADDR" "$KEYDIR"
}
block() { echo "$BEGIN_MARK"; block_lines; echo "$END_MARK"; }

has_block()  { [ -f "$1" ] && grep -qF "$BEGIN_MARK" "$1"; }
# pam_rssh lines that this script did not write (an earlier version's whole-file stack, or
# a hand edit). Never stacked on top of: two pam_rssh lines would each ask the phone.
has_foreign_rssh() {
  [ -f "$1" ] && awk -v b="$BEGIN_MARK" -v e="$END_MARK" \
    '$0==b{i=1} $0==e{i=0; next} !i && /pam_rssh/ && !/^[[:space:]]*#/ {f=1} END{exit !f}' "$1"
}

# Print $1 with the block inserted above its first auth rule (`auth ...`, `-auth ...`, or
# Debian's `@include common-auth`). No auth rule found means a layout we do not
# understand: fail rather than guess where the block belongs.
with_block() {
  block > "$1.sudostamp-block" || return 1
  awk -v blockfile="$1.sudostamp-block" '
    !done && ($0 ~ /^[[:space:]]*-?auth[[:space:]]/ || $0 ~ /^@include[[:space:]]+common-auth/) {
      while ((getline l < blockfile) > 0) print l
      done = 1
    }
    { print }
    END { exit !done }' "$1"
  local rc=$?
  rm -f "$1.sudostamp-block"
  return $rc
}
# $1 without our block. Refuses unless the markers are exactly one BEGIN followed by one END:
# a BEGIN with no END (a hand edit, a truncated file) would otherwise drop every line after
# it -- the whole auth stack, which locks out the password too.
without_block() {
  awk -v b="$BEGIN_MARK" -v e="$END_MARK" '
    $0==b { nb++; if (s || ne) bad=1; s=1; next }
    $0==e { ne++; if (!s) bad=1; s=0; next }
    !s { print }
    END { exit (bad || s || nb > 1 || ne > 1 || nb != ne) }' "$1"
}

# The vendor file sudo falls back to when there is no override in /etc (openSUSE).
vendor_pam_file() {
  local f
  for f in /usr/lib/pam.d/sudo /usr/etc/pam.d/sudo; do [ -f "$f" ] && { echo "$f"; return 0; }; done
  return 1
}

# ------------------------------------------------------------------ live key fetch
# Fetched from the phone rather than hardcoded: a stale or mismatched pinned key is a
# silent auth failure, and the whole point of pinning is that the two agree.
#
# But fetched over plain TCP, so it is trust-on-first-use: anything answering at that
# address during `stage` would get ITS key pinned, and could then approve sudo. So the
# fingerprint is checked against the one the app shows before anything is written --
# SUDOSTAMP_FINGERPRINT for scripted installs, otherwise by eye.
fetch_key() {
  # -I: isolated mode. This runs as root, and plain `python3 -` puts the CURRENT directory
  # first on the import path, so a stray socket.py wherever the user happened to be would
  # run as root.
  python3 -I - "$PHONE_ADDR" "$SUDOSTAMP_FINGERPRINT" <<'PY'
import base64, hashlib, socket, struct, sys
host, port = sys.argv[1].rsplit(":", 1)
want = sys.argv[2]
s = socket.create_connection((host.strip("[]"), int(port)), timeout=10)
s.settimeout(10)
s.sendall(struct.pack(">I", 1) + bytes([11]))      # REQUEST_IDENTITIES
def rx(n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise SystemExit("agent closed early")
        b += c
    return b
ln = struct.unpack(">I", rx(4))[0]
if not 5 <= ln <= 65536:                           # a real answer is ~130 bytes
    raise SystemExit("implausible answer length %d" % ln)
body = rx(ln)
if body[0] != 12:
    raise SystemExit("unexpected reply type %d" % body[0])
n = struct.unpack(">I", body[1:5])[0]
if not 1 <= n <= 64:
    raise SystemExit("expected 1 to 64 keys, got %d" % n)

def string(buf, o):
    if o + 4 > len(buf):
        raise SystemExit("truncated answer")
    l = struct.unpack(">I", buf[o:o+4])[0]
    if o + 4 + l > len(buf):
        raise SystemExit("truncated answer")
    return buf[o+4:o+4+l], o + 4 + l

# One key per paired computer: take the one whose fingerprint is the one we were given.
o = 5
for _ in range(n):
    blob, o = string(body, o)
    _, o = string(body, o)
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    if fp != want:
        continue
    # The key must be exactly what the app makes: an uncompressed P-256 point, nothing more.
    t, p = string(blob, 0)
    c, p = string(blob, p)
    q, p = string(blob, p)
    if (t, c) != (b"ecdsa-sha2-nistp256", b"nistp256") or len(q) != 65 or q[0] != 4 or p != len(blob):
        raise SystemExit("not a SudoStamp key (expected one ecdsa-sha2-nistp256 public key)")
    # The phone's comment is ignored, deliberately: it is attacker-controlled text that would go
    # verbatim into a root-owned key file, and a newline in it pins a SECOND key.
    print("ecdsa-sha2-nistp256 %s sudostamp" % base64.b64encode(blob).decode())
    raise SystemExit(0)
raise SystemExit("fingerprint mismatch: no key with %s at this address" % want)
PY
}

# ------------------------------------------------------------------ the key

# The phone's public key, verified. Three ways, strongest friction-free one by default:
#   pairing (default)    the 6-digit code the person types (tools/pair.py, Pairing.kt)
#   --fingerprint FP     scripted installs: fetched over TCP, must match FP exactly
#   --key "LINE"         pasted from the app's "Copy public key": no network at all
acquire_key() {
  local key fp
  if [ -n "${SUDOSTAMP_KEY:-}" ]; then
    key="$(printf '%s' "$SUDOSTAMP_KEY" | awk '{print $1, $2, "sudostamp"}')"
  elif [ -n "${SUDOSTAMP_FINGERPRINT:-}" ]; then
    key="$(fetch_key)" || { bad "could not fetch the public key from $PHONE_ADDR" >&2; return 1; }
    fp="$(printf '%s\n' "$key" | ssh-keygen -lf - | awk '{print $2}')"
    [ "$fp" = "$SUDOSTAMP_FINGERPRINT" ] || { bad "fingerprint mismatch: the phone's key is $fp" >&2; return 1; }
  else
    local addr_file extra=(); addr_file="$(root_tmp)/phone-addr"
    [ -z "${SUDOSTAMP_REQUIRE_ATTESTATION:-}" ] || extra+=(--require-attestation)
    [ -z "${SUDOSTAMP_CHECK_REVOCATION:-}" ] || extra+=(--check-revocation)
    key="$(python3 -I "$HERE/pair.py" pair --phone "$PHONE_ADDR" --label "$(hostname 2>/dev/null || uname -n)" \
             --addr-out "$addr_file" --attest-out "$(root_tmp)/attest" ${extra[@]+"${extra[@]}"})" || return 1
  fi
  # Exactly one line of exactly this shape, whatever produced it: this is the content of a
  # root-owned file that decides who may approve sudo.
  printf '%s\n' "$key" | grep -qxE "$KEY_RE" && \
    [ "$(printf '%s\n' "$key" | wc -l | tr -d ' ')" = 1 ] || { bad "not a single SudoStamp key" >&2; return 1; }
  printf '%s\n' "$key"
}

# After pairing: the address the phone vouched for (its stable one, if this computer reaches
# it there), checked again before it can go into a PAM line. acquire_key runs in a subshell,
# so it hands this over in a file in the private temporary directory.
adopt_paired_addr() {
  local f="$ROOT_TMP/phone-addr"
  [ -s "$f" ] || return 0
  PHONE_ADDR="$(head -1 "$f")"
  need_phone
  rm -f "$f"
}

# Root-owned dir AND file. auth_keys.rs:87 does a bare read_to_string with no symlink or
# ownership check, so the DIRECTORY must be unwritable by the user too.
pin_key() {
  mkdir -p "$KEYDIR" && chown 0:0 "$KEYDIR" && chmod 0755 "$KEYDIR"
  printf '%s\n' "$1" | write_atomic "$KEYFILE"
  ok "pinned $(printf '%s\n' "$1" | ssh-keygen -lf - | awk '{print $2}') in $KEYFILE"
  # A key pinned any other way (--key, --fingerprint) has no attestation; it must not keep the
  # line of the key it replaced.
  if [ -s "${ROOT_TMP:-/nonexistent}/attest" ]; then write_atomic "$ATTESTFILE" < "$ROOT_TMP/attest"
  else rm -f "$ATTESTFILE"; fi
}

# The pinned key's hardware attestation, as recorded when it was paired: "<fingerprint> TAB
# <sentence>". Shown only if it is about the key that is pinned now.
attest_line() {
  local fp rec
  fp="$(ssh-keygen -lf "$KEYFILE" 2>/dev/null | awk 'NR==1 {print $2}')"
  rec="$(head -1 "$ATTESTFILE" 2>/dev/null | tr -cd '[:print:]\t')"
  if [ -n "$fp" ] && [ "${rec%%$'\t'*}" = "$fp" ]; then echo "${rec#*$'\t'}"
  else echo "not attested (paired before 1.5, or pinned without the pairing code)"; fi
}

# Find the phone on the LAN (it advertises only while its pairing screen is open), or ask.
find_phone() {
  local found n choice
  # One listening window, opened BEFORE the person taps: the phone announces itself the
  # moment it starts advertising, and pair.py returns as soon as it hears it (up to 2 min).
  say "  On the phone: open SudoStamp and tap 'Pair a computer' (or 'Get started')."
  say "  Waiting for it to appear on the network..."
  found="$(python3 -I "$HERE/pair.py" discover --timeout 120 2>/dev/null)" || true
  n="$(printf '%s' "$found" | grep -c . || true)"
  if [ "$n" = 1 ]; then
    PHONE_ADDR="$(printf '%s' "$found" | cut -f1)"
    ok "found $(printf '%s' "$found" | cut -f2) at $PHONE_ADDR"
  elif [ "$n" -gt 1 ]; then
    say "  More than one phone is pairing right now:"
    printf '%s\n' "$found" | awk -F'\t' '{printf "    %d) %s  (%s)\n", NR, $2, $1}'
    read -r -p "  Which one? [1-$n] " choice
    # A number, and only a number: it is used to pick a line.
    case "$choice" in ''|*[!0-9]*) die "not a choice: $choice" ;; esac
    [ "$choice" -ge 1 ] && [ "$choice" -le "$n" ] || die "not a choice: $choice"
    PHONE_ADDR="$(printf '%s\n' "$found" | awk -v n="$choice" 'NR==n' | cut -f1)"
  else
    say "  Not found automatically. Something on this network blocks mDNS (port 5353):"
    say "  a firewall here (firewalld: firewall-cmd --add-service=mdns), or Wi-Fi client isolation."
    read -r -p "  Type the address shown on the phone, e.g. 192.168.1.50:7777: " PHONE_ADDR
  fi
}

# ---------------------------------------------------------------------- steps

# The scratch PAM service: only our lines, then deny. Success here can only have come from
# the phone (or the local sensor), never from a password.
run_test() {
  { echo "#%PAM-1.0"; block; echo "auth       required     pam_deny.so"; \
    echo "account    required     pam_permit.so"; } | write_atomic "$PAM_TEST"
  say "  Approve the request on your phone now (a local fingerprint reader, if any, is asked first):"
  local rc=0
  python3 -I "$HERE/pam_check.py" "$(basename "$PAM_TEST")" "$TARGET_USER" || rc=1
  # Never left behind: every file in the PAM directory is a service any program can name.
  rm -f "$PAM_TEST"
  if [ "$rc" = 0 ]; then
    ok "the phone approved through PAM"
  else
    bad "the test did not succeed -- see the result above. sudo is untouched."
    return 1
  fi
}

# An older SudoStamp replaced the whole sudo file. Its backups (*.bak-<UTC time>, written only
# by this script) hold the stack from before it; restore the newest one without pam_rssh, after
# keeping a copy of what is there now. Asks first: other edits made since would go too.
migrate_legacy() {
  local target bak answer
  target="$(pam_target)"
  has_foreign_rssh "$target" || return 0
  bak="$(clean_backups "$target" | tail -1)"
  [ -n "$bak" ] || die "$target has pam_rssh lines this script did not write, and no backup from before them. Remove those lines by hand, then run setup again."
  warn "$target holds an older SudoStamp stack (or hand-added pam_rssh lines)."
  say "     It will be replaced by $bak (from before SudoStamp), and then get the new block."
  say "     Any other change made to $target since then is lost; a copy is kept."
  if [ "${SUDOSTAMP_YES:-}" != 1 ]; then
    read -r -p "     Continue? [yes/no] " answer
    [ "$answer" = yes ] || die "stopped; nothing changed"
  fi
  backup_of "$target" >/dev/null || die "could not back up $target"
  cp -p "$bak" "$target.sudostamp-new" && mv -f "$target.sudostamp-new" "$target"
  ok "restored $target from $bak"
}

# Insert (or replace) our block in sudo's stack, atomically, keeping a backup. Idempotent:
# an existing SudoStamp block is taken out before the new one goes in, so re-running never
# stacks two blocks (two pam_rssh lines would each ask the phone).
do_apply() {
  local target src bak vendor="" new
  target="$(pam_target)"
  if has_foreign_rssh "$target"; then
    die "$target already has pam_rssh lines this script did not write. 'sudo $PROG setup' migrates an older SudoStamp; otherwise remove them first."
  fi
  if [ -f "$target" ]; then
    src="$target"
  elif [ "$FAMILY" = macos ]; then
    # sudo_local does not exist until someone creates it. Sonoma+ ship the include.
    grep -q 'sudo_local' /etc/pam.d/sudo || die "/etc/pam.d/sudo has no sudo_local include (macOS 14+ required)"
    src=/dev/null
  elif vendor="$(vendor_pam_file)"; then
    # An /etc override REPLACES the vendor file wholesale, so start from a copy of it.
    src="$vendor"
  else
    die "no $target to modify. Is sudo installed?"
  fi
  if [ -f "$target" ]; then
    bak="$(backup_of "$target")" || die "could not back up $target"
    ok "backed up $bak"
  fi
  tidy_old_backups "$target"
  new="$(root_tmp)/new"
  if [ "$FAMILY" = macos ]; then
    # sudo_local holds only additions: our block first, then whatever else is there.
    { block; [ "$src" = /dev/null ] || without_block "$src" || exit 1; } > "$new" || \
      die "$src has damaged SudoStamp markers -- fix them by hand first"
  else
    if [ -n "$vendor" ]; then
      { head -1 "$vendor"; echo "$VENDOR_MARK"; tail -n +2 "$vendor"; } > "$new.src"
    else
      without_block "$src" > "$new.src" || die "$src has damaged SudoStamp markers -- fix them by hand first"
    fi
    with_block "$new.src" > "$new" || die "no auth rule found in $src -- not guessing where the block goes"
  fi
  write_atomic "$target" < "$new"
  ok "wrote $target"
  rm -f "$PAM_TEST"
}

# ---------------------------------------------------------------------- setup

cmd_setup() {
  need_root setup; need_platform; need_user
  say "=== SudoStamp setup ($FAMILY) ==="
  base_deps >/dev/null || die "could not install base dependencies (python3, ssh-keygen, git)"
  root_tmp >/dev/null
  [ -n "$PHONE_ADDR" ] || find_phone
  need_phone

  say
  say "1/4  Pairing with the phone at $PHONE_ADDR"
  local key
  key="$(acquire_key)" || die "not paired; nothing on this computer was changed"
  adopt_paired_addr
  ok "the phone will be reached at $PHONE_ADDR"

  say
  say "2/4  Installing pam_rssh"
  install_pam_rssh
  install_helpers
  pin_key "$key"

  say
  say "3/4  Testing, without touching sudo yet"
  run_test || exit 1

  say
  say "4/4  Turning it on for sudo"
  migrate_legacy
  do_apply
  warn_targetpw

  say
  ok "Done. Every sudo now asks your phone first; your password still works as before."
  say "     Try it in a second terminal:   sudo -k && sudo true"
  say "     Undo at any time:              sudo $PROG rollback"
}

# ---------------------------------------------------- stage / test / apply (scripts)

cmd_stage() {
  need_root stage; need_platform; need_phone; need_user
  say "=== stage: pam_rssh + pinned key ($FAMILY). No PAM changes. ==="
  base_deps || die "could not install base dependencies (python3, ssh-keygen, git)"
  # The key first: a wrong phone or an impostor is refused before minutes of building.
  local key
  root_tmp >/dev/null
  key="$(acquire_key)" || die "no key pinned"
  adopt_paired_addr
  install_pam_rssh
  install_helpers
  warn_targetpw
  pin_key "$key"
  say
  say "Next: sudo $PROG test --phone $PHONE_ADDR"
}

cmd_test() {
  need_root test; need_platform; need_phone; need_user
  [ -f "$KEYFILE" ] || die "no pinned key -- run 'stage' first"
  install_helpers
  say "=== test: a scratch PAM service. $(pam_target) is NOT touched. ==="
  run_test || exit 1
  say
  say "Next: sudo $PROG apply --phone $PHONE_ADDR   (keep a root shell open while you do)"
}

cmd_apply() {
  need_root apply; need_platform; need_phone; need_user
  [ -f "$KEYFILE" ] || die "no pinned key -- run 'stage' first"
  find_pam_rssh >/dev/null || die "pam_rssh is not installed -- run 'stage' first"
  # An install from 1.4 or earlier has no timeouts: build the patched module now, without pairing again.
  if [ "$(rssh_state)" != patched ] && [ "$FAMILY" != freebsd ]; then
    base_deps || die "could not install base dependencies (python3, ssh-keygen, git)"
    root_tmp >/dev/null
    install_pam_rssh
  fi
  install_helpers
  say "=== apply: add the SudoStamp block to $(pam_target) ==="
  do_apply
  sed 's/^/     /' "$(pam_target)"
  warn_targetpw
  say
  say "The password path below the block is untouched: if the phone misbehaves, the password still works."
  say "Check in a SECOND terminal, keeping this one open:   sudo -k && sudo true"
  say "Undo:   sudo $PROG rollback"
}

# ------------------------------------------------------------------- rollback

# Take our block out of $1. Dies, having changed nothing, on damaged markers or when nothing
# that authenticates would be left. Shared by rollback and uninstall: both refuse alike.
strip_block() {
  local target="$1" new
  if grep -qF "$VENDOR_MARK" "$target"; then
    # We created this override from the vendor file; removing it restores the vendor
    # stack exactly.
    rm -f "$target" && ok "removed $target (the vendor file applies again)"
  else
    root_tmp >/dev/null
    new="$ROOT_TMP/rollback"
    without_block "$target" > "$new" || \
      die "$target has damaged SudoStamp markers (a BEGIN without its END, or two blocks). Nothing changed; fix it by hand."
    # The result must still authenticate somehow, or the password would be locked out too.
    # (macOS sudo_local holds additions only, and may legitimately end up empty.)
    if [ "$FAMILY" != macos ] && ! grep -qE '^[[:space:]]*-?auth[[:space:]]|^@include[[:space:]]+common-auth' "$new"; then
      die "removing the block would leave $target with no auth rule at all. Nothing changed."
    fi
    write_atomic "$target" < "$new"
    ok "removed the SudoStamp block from $target"
  fi
}
# An older SudoStamp replaced the whole file. Put back the newest backup WITHOUT pam_rssh:
# re-applying that old version made a backup of its own previous output each time, so "the
# latest backup" is usually just another SudoStamp stack.
restore_legacy() {
  local target="$1" bak
  bak="$(clean_backups "$target" | tail -1)"
  [ -n "$bak" ] || die "no SudoStamp block in $target and no backup without pam_rssh to restore"
  cp -p "$bak" "$target.sudostamp-new" && mv -f "$target.sudostamp-new" "$target"
  ok "restored $target from $bak"
}

cmd_rollback() {
  need_root rollback; need_platform
  local target
  target="$(pam_target)"
  if has_block "$target"; then strip_block "$target"; else restore_legacy "$target"; fi
  rm -f "$PAM_TEST" "$GATE" "$PROBE"
  tidy_old_backups "$target"
  say "Check the password works:   sudo -k && sudo true"
}

# ------------------------------------------------------------------ uninstall

# The key files that hold at least one SudoStamp line (any user's: setup may have run for several).
our_key_files() {
  local f
  for f in "$KEYDIR"/*.keys; do
    [ -f "$f" ] && grep -qxE "$KEY_RE" "$f" && echo "$f"
  done
}

# The file that defines sudo's PAM stack, for the sanity check below.
sudo_stack_file() {
  local f
  for f in "$(pam_dir)/sudo" /etc/pam.d/sudo; do [ -f "$f" ] && { echo "$f"; return 0; }; done
  vendor_pam_file
}

# After removal, sudo must still have a way in and the way must be the password: the stack has
# an auth rule, and PAM run on the real `sudo` service refuses an empty password (pam_check.py
# answers every prompt with an empty string, so only a module that needs no input -- the
# phone -- could say yes). Anything else means uninstall left sudo in a state to look at before
# the next `sudo`. (On Fedora/RHEL this counts as one failed login for pam_faillock.)
pam_sanity() {
  local f out rc=0
  f="$(sudo_stack_file)" || { bad "sudo has no PAM stack file at all"; return 1; }
  if ! grep -qE '^[[:space:]]*-?auth[[:space:]]|^@include[[:space:]]+common-auth|^auth[[:space:]]+include' "$f"; then
    bad "$f has no auth rule: sudo cannot authenticate anyone"; return 1
  fi
  # (A variable, not `grep | grep -q`: under pipefail the early exit of the second can fail the pipe.)
  out="$(cat "$f" "$(pam_target)" 2>/dev/null | grep -v '^[[:space:]]*#' | grep 'pam_rssh\|sudostamp')" || out=""
  if [ -n "$out" ]; then
    bad "SudoStamp lines are still in $f"; return 1
  fi
  if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = root ] || ! id "$TARGET_USER" >/dev/null 2>&1; then
    warn "no user to check sudo's stack against (run via sudo from your account, or set SUDOSTAMP_USER); the file itself looks right"
    return 0
  fi
  out="$(python3 -I "$HERE/pam_check.py" sudo "$TARGET_USER" 2>&1)" || rc=$?
  case "$rc:$out" in
    1:*"(7)"|1:*"(11)")
      ok "sudo's PAM stack runs and refuses an empty password: only the password gets in now" ;;
    0:*)
      bad "sudo's stack let an EMPTY password through -- that is not SudoStamp's doing, but look at $f now"; return 1 ;;
    *)
      bad "sudo's PAM stack misbehaves: $(printf '%s' "$out" | tail -2 | tr '\n' ' ')"; return 1 ;;
  esac
}

cmd_uninstall() {
  need_root uninstall; need_platform
  local target f m mod keyfiles have_block=0 have_foreign=0 any=0 ans others
  target="$(pam_target)"
  has_block "$target" && have_block=1
  has_foreign_rssh "$target" && have_foreign=1
  keyfiles="$(our_key_files)"
  m="$(ours_module)" || m=""
  [ "$have_block" = 1 ] || [ "$have_foreign" = 1 ] || [ -n "$keyfiles" ] || [ -n "$m" ] || \
    [ -e "$GATE" ] || [ -e "$PROBE" ] || [ -e "$PAM_TEST" ] || [ -d "$(state_dir)" ] && any=1
  if [ "$any" = 0 ]; then
    say "=== uninstall ==="
    ok "SudoStamp is not installed here: nothing to remove, nothing changed"
    return 0
  fi

  say "=== uninstall: what SudoStamp installed, and nothing else ==="
  [ "$have_block" = 1 ] && say "  - the SudoStamp block in $target"
  [ "$have_foreign" = 1 ] && [ "$have_block" = 0 ] && say "  - the pam_rssh stack an older SudoStamp wrote to $target (its backup is put back)"
  for f in "$GATE" "$PROBE" "$PAM_TEST"; do [ -e "$f" ] && say "  - $f"; done
  for f in $keyfiles; do say "  - SudoStamp's key line(s) in $f"; done
  [ -n "$m" ] && say "  - the pam_rssh module SudoStamp built: $m"
  [ -d "$(state_dir)" ] && say "  - $(state_dir) (backups of sudo's PAM file, the build record)"
  if [ -z "$m" ] && mod="$(find_pam_rssh)"; then
    say "  (kept: $mod -- not built by this installer: a package's, or SudoStamp 1.4's or earlier)"
  fi
  if [ "${SUDOSTAMP_YES:-}" != 1 ]; then
    read -r -p "  Remove these? [yes/no] " ans || ans=""
    [ "$ans" = yes ] || die "stopped; nothing changed"
  fi

  # The PAM file FIRST: it is the step that can refuse (damaged markers), and when it does
  # nothing else has been touched.
  if [ "$have_block" = 1 ]; then strip_block "$target"
  elif [ "$have_foreign" = 1 ]; then restore_legacy "$target"; fi
  for f in "$PAM_TEST" "$GATE" "$PROBE"; do
    [ -e "$f" ] && rm -f "$f" && ok "removed $f"
  done

  # A key file that is only ours goes; one that holds other keys loses just our lines.
  for f in $keyfiles; do
    others="$(grep -vxE "$KEY_RE" "$f" | grep -c '[^[:space:]]')" || others=0
    if [ "$others" = 0 ]; then
      rm -f "$f" && ok "removed $f"
    else
      grep -vxE "$KEY_RE" "$f" | write_atomic "$f"
      ok "removed SudoStamp's key line(s) from $f (kept the $others other line(s))"
    fi
  done
  # Only if empty: rmdir never takes anything that is not ours with it.
  rmdir "$KEYDIR" 2>/dev/null && ok "removed the empty $KEYDIR"

  # The module only if the marker says we built it AND it is still what we built. The name and
  # place are checked too: the marker is root's, but a path read from a file is not removed blind.
  if [ -n "$m" ]; then
    case "$(basename "$m"):$(dirname "$m")" in
      pam_rssh.so:"$MACOS_MODULE_DIR"|pam_rssh.so:"$(module_dir 2>/dev/null)"|pam_rssh_sudostamp.so:"$(module_dir 2>/dev/null)")
        rm -f "$m" && ok "removed $m (built by SudoStamp)" ;;
      *) warn "the build record names $m, which is not where this installer puts it: left alone" ;;
    esac
  elif [ -f "$(rssh_marker)" ]; then
    say "  the pam_rssh module named in the build record is gone or was replaced since: not touching it"
  fi
  rm -f "$(rssh_marker)"
  [ "$FAMILY" = macos ] && rmdir "$MACOS_MODULE_DIR" /opt/sudostamp 2>/dev/null

  say
  if ! pam_sanity; then
    say "     The backups in $(backup_dir) were kept. Do not log out of your root shell."
    exit 1
  fi
  # Last, and only once the stack is proven: the backups are what would repair it.
  rm -f "$(backup_dir)"/*.bak-* 2>/dev/null
  rmdir "$(backup_dir)" "$(state_dir)" 2>/dev/null
  [ -d "$(state_dir)" ] && warn "$(state_dir) holds files that are not SudoStamp's backups: left in place"
  ok "SudoStamp is removed. Check:   sudo -k && sudo true   (it asks for your password)"
}

# --------------------------------------------------------------------- status

rssh_label() {
  case "$(rssh_state)" in
    patched) echo "patched (timeouts)" ;;
    stale)   echo "built by SudoStamp with an older timeouts patch" ;;
    *)       echo "NOT patched: no timeouts" ;;
  esac
}

cmd_status() {
  local target mod
  target="$(pam_target)"
  say "=== status ==="
  say "platform        : $OS ${FAMILY:-unsupported}"
  if mod="$(find_pam_rssh)"; then say "pam_rssh        : $mod -- $(rssh_label)"; else say "pam_rssh        : MISSING"; fi
  if [ -f "$KEYFILE" ]; then say "pinned key      : $KEYFILE ($(ls -l "$KEYFILE" | awk '{print $1, $3":"$4}'))"
  else say "pinned key      : absent ($KEYFILE)"; fi
  [ -f "$KEYFILE" ] && say "key attestation : $(attest_line)"
  say "local reader    : $(has_fprintd && echo "pam_fprintd (gate: $GATE)" || echo none)"
  say "probe           : $([ -x "$PROBE" ] && echo "$PROBE" || echo "absent$(linux_pam || echo ' (not used on OpenPAM)')")"
  if has_block "$target" && grep -qF "$OLD_GATE_CONTROL" "$target"; then
    say "PAM             : SudoStamp block from an older version in $target -- run 'sudo $PROG setup' to update it"
  elif has_block "$target"; then say "PAM             : SudoStamp block present in $target"
  elif has_foreign_rssh "$target"; then say "PAM             : pam_rssh lines NOT written by this script in $target"
  else say "PAM             : not applied ($target)"; fi
  say "scratch service : $([ -f "$PAM_TEST" ] && echo present || echo absent)"
  if sudo_auths_as_root; then say "sudo auth as    : ROOT (targetpw/rootpw) -- the phone is never asked; see 'stage' output"
  else say "sudo auth as    : the invoking user"; fi
  say "backups         : $(ls -1 "$(backup_dir)/$(basename "$target")".bak-* "${target}".bak-* 2>/dev/null | wc -l | tr -d ' ') ($(backup_dir))"
  [ -f "$target" ] && { say "--- $target ---"; sed 's/^/  /' "$target"; }
}

# --------------------------------------------------------------------- doctor
#
# READ ONLY, by construction: nothing below writes a file, takes a lock or calls a function that
# does (no root_tmp, no write_atomic, no package manager). One line per check; every line that
# is not OK is followed by the command that fixes it. Exit 0 all OK, 1 any FAIL, 2 only WARN.

DOC_FAIL=0
DOC_WARN=0
d_ok()   { ok "$*"; }
d_warn() { warn "$1"; DOC_WARN=$((DOC_WARN + 1)); [ -z "${2:-}" ] || say "       fix: $2"; }
d_bad()  { bad "$1"; DOC_FAIL=$((DOC_FAIL + 1)); [ -z "${2:-}" ] || say "       fix: $2"; }

# "<uid> <mode>" of $1.
file_facts() { ls -ldn "$1" 2>/dev/null | awk '{print $3, $1}'; }
# Owned by root and not writable by group or others: what may be loaded or trusted by root.
root_safe() {
  local facts p="$1"
  [ -d "$p" ] && p="$p/"          # a symlinked directory is judged by what it points at
  facts="$(file_facts "$p")"
  [ "${facts%% *}" = 0 ] || return 1
  case "${facts#* }" in ?????w????*|????????w?*) return 1 ;; esac
  return 0
}
doctor_end() {
  say
  if [ "$DOC_FAIL" -gt 0 ]; then
    say "$DOC_FAIL problem(s), $DOC_WARN warning(s). Nothing was changed: run the fix commands above."
    exit 1
  elif [ "$DOC_WARN" -gt 0 ]; then
    say "$DOC_WARN warning(s), no problems. Nothing was changed."
    exit 2
  fi
  say "All checks passed. Nothing was changed."
  exit 0
}
# Does something answer on $1 (host:port) within 4 seconds?
phone_reachable() {
  python3 -I - "$1" <<'PY'
import socket, sys
host, port = sys.argv[1].rsplit(":", 1)
try:
    socket.create_connection((host.strip("[]"), int(port)), timeout=4).close()
except Exception:
    sys.exit(1)
PY
}
# A helper script: present, root-owned, identical to this installer's copy ($2 = its name in tools/).
doctor_helper() {
  local path="$1" src="$HERE/$2" fix="$3"
  if [ ! -f "$path" ]; then
    d_bad "helper $path is missing: the PAM block calls it" "$fix"
  elif ! root_safe "$path"; then
    d_bad "helper $path is not root-owned or is writable by others: root runs it on every sudo" "sudo chown 0:0 $path && sudo chmod 0755 $path"
  elif [ -f "$src" ] && [ "$(sha256_file "$path")" != "$(sha256_file "$src")" ]; then
    d_warn "helper $path differs from this installer's copy" "$fix"
  else
    d_ok "helper $path: present, root-owned, matches this installer"
  fi
}

cmd_doctor() {
  local target block expected mod st addr="" found newaddr facts user_ok=1 gate_expected=0
  target="$(pam_target)"
  say "=== doctor: read-only, changes nothing ==="

  # 1. platform
  if [ -z "$FAMILY" ]; then
    d_bad "platform: $OS is not supported (/etc/os-release: ${ids:-none})" "see README.md for the lines to add by hand"
    doctor_end
  fi
  d_ok "platform: $FAMILY"
  if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = root ] || ! id "$TARGET_USER" >/dev/null 2>&1; then
    user_ok=0
    d_warn "user: cannot tell whose key to check" "sudo $PROG doctor   (from your own account), or SUDOSTAMP_USER=<user> $PROG doctor"
  fi

  # 2. the PAM block
  if has_block "$target"; then
    if ! without_block "$target" >/dev/null; then
      d_bad "PAM block: damaged markers in $target (a BEGIN without its END, or two blocks)" \
        "edit $target: keep exactly one '# >>> SudoStamp >>>' ... '# <<< SudoStamp <<<' pair, or delete both; backups are in $(backup_dir). Then: sudo $PROG setup"
    else
      block="$(awk -v b="$BEGIN_MARK" -v e="$END_MARK" '$0==b{i=1} i{print} $0==e{i=0}' "$target")"
      addr="$(printf '%s\n' "$block" | sed -n 's/.*ssh_agent_addr=\([^ ]*\).*/\1/p' | head -1)"
      if [ -z "$addr" ] || ! phone_valid "$addr"; then
        d_bad "PAM block: no usable phone address in the pam_rssh line" "sudo $PROG apply --phone <phone-ip>:7777"
        addr=""
      fi
      # What THIS installer would write for that phone on this machine.
      expected="$( (PHONE_ADDR="$addr"; block) 2>/dev/null )" || expected=""
      if printf '%s\n' "$block" | grep -qF "$OLD_GATE_CONTROL"; then
        d_warn "PAM block: written by an older version (its gate counts as success)" "sudo $PROG apply --phone ${addr:-<phone-ip>:7777}"
      elif [ -z "$expected" ]; then
        d_bad "PAM block: present, but pam_rssh is not installed to compare it with" "sudo $PROG stage --phone ${addr:-<phone-ip>:7777}"
      elif [ "$block" != "$expected" ]; then
        d_warn "PAM block: differs from what this installer writes (flags, helper paths, module name or local reader changed)" "sudo $PROG apply --phone ${addr:-<phone-ip>:7777}"
      else
        d_ok "PAM block: present in $target, current, intact"
      fi
      if has_foreign_rssh "$target"; then
        d_warn "PAM: $target also has pam_rssh lines SudoStamp did not write (the phone would be asked twice)" "remove those lines by hand: sudoedit $target"
      fi
    fi
  elif has_foreign_rssh "$target"; then
    d_bad "PAM block: $target has pam_rssh lines SudoStamp did not write, and no block" "sudo $PROG setup   (migrates an older SudoStamp)"
  else
    d_bad "PAM block: not applied: sudo does not ask the phone ($target)" "sudo $PROG setup   (or, if paired already: sudo $PROG apply --phone <phone-ip>:7777)"
  fi
  [ -n "$addr" ] || { phone_valid "${PHONE_ADDR:-}" && addr="$PHONE_ADDR"; }

  # 3. the module: present, safe to load, loads, has the timeouts
  if mod="$(find_pam_rssh)"; then
    if ! root_safe "$mod" || ! root_safe "$(dirname "$mod")"; then
      d_bad "pam_rssh: $mod or its directory is not root-owned or is writable by others: root would load whatever is put there (not loaded by doctor)" \
        "sudo chown 0:0 $mod && sudo chmod 0644 $mod"
    elif ! st="$(python3 -I -c 'import ctypes, sys; ctypes.CDLL(sys.argv[1]).pam_sm_authenticate' "$mod" 2>&1)"; then
      d_bad "pam_rssh: $mod does not load or lacks pam_sm_authenticate: $(printf '%s' "$st" | tail -1)" \
        "sudo rm -f $mod && sudo $PROG stage --phone ${addr:-<phone-ip>:7777}   (rebuilds it)"
    else
      case "$(rssh_state)" in
        patched) d_ok "pam_rssh: patched (timeouts): $mod, loads, exports pam_sm_authenticate" ;;
        stale)   d_warn "pam_rssh: $mod was built with an older timeouts patch" "sudo $PROG apply --phone ${addr:-<phone-ip>:7777}   (rebuilds it)" ;;
        *)
          if [ "$FAMILY" = freebsd ]; then
            d_warn "pam_rssh: $mod loads, but is NOT patched: the FreeBSD package has no timeouts, so a peer that answers the probe and stalls can hold sudo" \
              "no fix on FreeBSD yet: keep a second root shell open"
          else
            d_warn "pam_rssh: $mod loads, but is NOT patched: no timeouts, so a peer that answers the probe and then stalls can hold sudo" \
              "sudo $PROG apply --phone ${addr:-<phone-ip>:7777}   (builds the patched module; setup and stage do too)"
          fi ;;
      esac
    fi
  else
    d_bad "pam_rssh: not installed" "sudo $PROG stage --phone ${addr:-<phone-ip>:7777}"
  fi

  # 4. helper scripts (Linux-PAM only: OpenPAM cannot skip a line, so it has none)
  if linux_pam; then
    doctor_helper "$PROBE" sudostamp-probe.sh "sudo $PROG apply --phone ${addr:-<phone-ip>:7777}"
    if [ -f "$target" ] && grep -qF "$GATE" "$target"; then gate_expected=1; fi
    if [ "$gate_expected" = 1 ]; then
      doctor_helper "$GATE" sudostamp-is-local.sh "sudo $PROG apply --phone ${addr:-<phone-ip>:7777}"
      d_ok "local fingerprint reader: pam_fprintd is tried first at the desk (not over SSH)"
    elif has_fprintd; then
      d_ok "local fingerprint reader: pam_fprintd is installed; the block does not use it (re-run apply to include it)"
    else
      d_ok "local fingerprint reader: none (the phone is asked directly)"
    fi
  else
    d_ok "helper scripts: not used on OpenPAM ($FAMILY)"
  fi

  # 5. the pinned key
  if [ "$user_ok" = 1 ]; then
    if [ ! -f "$KEYFILE" ]; then
      d_bad "pinned key: $KEYFILE does not exist: pam_rssh has nothing to check the phone against" "sudo $PROG setup"
    elif ! root_safe "$KEYDIR" || ! root_safe "$KEYFILE"; then
      d_bad "pinned key: $KEYFILE or $KEYDIR is not root-owned or is writable by others: anything running as a user could pin its own key" \
        "sudo chown 0:0 $KEYDIR $KEYFILE && sudo chmod 0755 $KEYDIR && sudo chmod 0644 $KEYFILE"
    elif ! grep -qxE "$KEY_RE" "$KEYFILE"; then
      d_bad "pinned key: $KEYFILE holds no valid ecdsa-sha2-nistp256 SudoStamp key line" "sudo $PROG setup   (pairs again and rewrites it)"
    else
      d_ok "pinned key: $KEYFILE: root-owned, mode $(file_facts "$KEYFILE" | cut -d' ' -f2), valid ecdsa-sha2-nistp256 key"
      if [ "$(grep -cv '^[[:space:]]*$' "$KEYFILE")" != "$(grep -cxE "$KEY_RE" "$KEYFILE")" ]; then
        d_warn "pinned key: $KEYFILE also holds keys that are not SudoStamp's: each can approve sudo for $TARGET_USER" "review it: sudoedit $KEYFILE"
      fi
    fi
  fi

  # 6. the phone: reachable, and offering THIS user's pinned key (the probe's own logic)
  if [ "$user_ok" = 0 ]; then
    :
  elif [ -z "$addr" ]; then
    d_warn "phone: no address to check (none in the PAM block, none given)" "sudo $PROG doctor --phone <phone-ip>:7777"
  elif ! phone_reachable "$addr"; then
    found="$(python3 -I "$HERE/pair.py" discover --timeout 6 2>/dev/null)" || found=""
    newaddr="$(printf '%s\n' "$found" | cut -f1 | grep -vxF "$addr" | grep . | head -1)" || newaddr=""
    if [ -n "$newaddr" ]; then
      d_bad "phone: nothing answers at $addr within 4 s, but a SudoStamp phone is now at $newaddr (its address changed). Nothing was rewritten." \
        "sudo $PROG setup --phone $newaddr"
    elif printf '%s\n' "$found" | cut -f1 | grep -qxF "$addr"; then
      d_bad "phone: $addr is advertising on the network but does not answer on its port within 4 s" \
        "open the SudoStamp app once so it restarts its listener, then: sudo $PROG doctor"
    else
      d_bad "phone: nothing answers at $addr within 4 s, and none shows up on the network (discovery only sees it while its 'Pair a computer' screen is open)" \
        "open the app, tap 'Pair a computer', then: sudo $PROG setup"
    fi
  elif [ ! -f "$HERE/sudostamp-probe.sh" ]; then
    d_warn "phone: answers at $addr, but this installer has no probe to check the key with" "re-download the installer"
  elif PAM_USER="$TARGET_USER" sh "$HERE/sudostamp-probe.sh" "phone=$addr" "keys=$KEYDIR"; then
    d_ok "phone: $addr answers within 4 s and offers $TARGET_USER's pinned key"
  else
    d_bad "phone: $addr answers but does not offer the key pinned for $TARGET_USER (paired with another computer, or the app was reinstalled)" \
      "sudo $PROG setup --phone $addr"
  fi

  # 7. things that make sudo skip the phone altogether
  if sudo_auths_as_root; then
    d_warn "sudoers: sudo authenticates as ROOT here (targetpw/rootpw): the phone is never asked" \
      "echo 'Defaults:$TARGET_USER !targetpw, !rootpw, !runaspw' | sudo tee /etc/sudoers.d/50-sudostamp && sudo chmod 0440 /etc/sudoers.d/50-sudostamp && sudo visudo -cf /etc/sudoers.d/50-sudostamp"
  fi
  [ -f "$PAM_TEST" ] && d_warn "a scratch PAM service was left behind: $PAM_TEST" "sudo rm -f $PAM_TEST"
  doctor_end
}

# Arguments. Preferred over the environment: passing settings via `sudo -E` hands the
# caller's ENTIRE environment to a root process (APT_CONFIG, for one, survives sudo's
# filter), and a sudoers env_reset policy may drop them anyway. The SUDOSTAMP_* variables
# still work, for scripts and CI.
CMD="${1:-status}"
[ $# -gt 0 ] && shift
while [ $# -gt 0 ]; do
  case "$1" in
    --phone)        PHONE_ADDR="${2:-}"; shift 2 ;;
    --phone=*)      PHONE_ADDR="${1#*=}"; shift ;;
    --fingerprint)  SUDOSTAMP_FINGERPRINT="${2:-}"; shift 2 ;;
    --fingerprint=*) SUDOSTAMP_FINGERPRINT="${1#*=}"; shift ;;
    --allow-rustup) SUDOSTAMP_ALLOW_RUSTUP=1; shift ;;
    --key)          SUDOSTAMP_KEY="${2:-}"; shift 2 ;;
    --yes|-y)       SUDOSTAMP_YES=1; shift ;;
    --require-attestation) SUDOSTAMP_REQUIRE_ATTESTATION=1; shift ;;
    --check-revocation)    SUDOSTAMP_CHECK_REVOCATION=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

case "$CMD" in
  setup)    cmd_setup ;;
  stage)    cmd_stage ;;
  test)     cmd_test ;;
  apply)    cmd_apply ;;
  rollback) cmd_rollback ;;
  status)   cmd_status ;;
  doctor)   cmd_doctor ;;
  uninstall) cmd_uninstall ;;
  *)        echo "usage: $PROG {setup|stage|test|apply|rollback|status|doctor|uninstall} [--phone host:port] [--fingerprint SHA256:..] [--key LINE] [--yes] [--require-attestation] [--check-revocation]"; exit 2 ;;
esac
