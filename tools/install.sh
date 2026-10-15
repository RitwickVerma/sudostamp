#!/bin/bash
# Install SudoStamp's host side: pam_rssh, the pinned phone key, and a marked block in
# sudo's PAM stack that asks the phone first and falls through to the password.
#
#   export SUDOSTAMP_PHONE=192.168.1.50:7777          # the phone, from its setup screen
#   sudo -E tools/install.sh stage                    # pam_rssh + pinned key. No PAM change.
#   sudo -E tools/install.sh test                     # prove it on a scratch PAM service
#   sudo -E tools/install.sh apply                    # add the block to sudo's PAM file
#   sudo -E tools/install.sh rollback                 # take the block out again
#   sudo -E tools/install.sh status                   # what is in place
#
# Optional: SUDOSTAMP_FINGERPRINT=SHA256:... skips the interactive fingerprint check (the
# app's "Copy setup command" fills it in); SUDOSTAMP_USER=<user> when not run via sudo;
# SUDOSTAMP_ALLOW_RUSTUP=1 pre-approves a throwaway Rust toolchain when the distribution's
# is too old to build pam_rssh (see build_pam_rssh).
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
#
# Portable bash: macOS still ships bash 3.2, so no associative arrays, no ${x,,}, no mapfile,
# and no GNU-only flags (stat -c, sed -i, install -o root).
set -uo pipefail

PHONE_ADDR="${SUDOSTAMP_PHONE:-}"
# Whose key is pinned: SUDOSTAMP_USER, else the user who ran sudo, else (for a plain
# `status`) whoever is running this.
TARGET_USER="${SUDOSTAMP_USER:-${SUDO_USER:-}}"
[ -z "$TARGET_USER" ] && [ "$(id -u)" -ne 0 ] && TARGET_USER="$(id -un)"
KEYDIR="/etc/authorized_keys"
KEYFILE="${KEYDIR}/${TARGET_USER}.keys"
GATE="/usr/local/sbin/sudostamp-is-local"
# How long the LOCAL sensor waits for a finger. Only ever paid at the desk: the gate skips
# pam_fprintd on remote (SSH/mosh) sessions.
FPRINT_TIMEOUT=15
HERE="$(cd "$(dirname "$0")" && pwd)"

# pam_rssh is built from this exact commit when the platform has no package: tag v1.2.1.
# A tag can be moved; a commit cannot.
RSSH_REPO="https://github.com/z4yx/pam_rssh.git"
RSSH_TAG="v1.2.1"
RSSH_COMMIT="e8dd046c423f85df266c23bcc3d7033bfee81255"
# The oldest Rust its Cargo.lock builds with: time-core 0.1.8 needs 1.88. (Debian 13 has
# 1.85, Ubuntu 24.04 1.75: found by building, not by reading.)
CARGO_MIN_MINOR=88

BEGIN_MARK="# >>> SudoStamp >>> managed by tools/install.sh; 'install.sh rollback' removes it"
END_MARK="# <<< SudoStamp <<<"
VENDOR_MARK="# SudoStamp: copied from the vendor file; rollback deletes this file"

say()  { printf '%s\n' "$*"; }
ok()   { printf '  \033[32mOK\033[0m   %s\n' "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
warn() { printf '  \033[33mWARN\033[0m %s\n' "$*"; }
die()  { bad "$*"; exit 1; }

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

# Find an installed pam_rssh WITHOUT assuming its filename: Arch's package installs
# pam_rssh.so, a bare cargo build produces libpam_rssh.so. Checking only one once made a
# successful install read as a failure.
find_pam_rssh() {
  local d c
  case "$FAMILY" in
    macos)   [ -f /usr/local/lib/pam/pam_rssh.so ] && { echo /usr/local/lib/pam/pam_rssh.so; return 0; }; return 1 ;;
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
  [ "$(id -u)" -eq 0 ] || { echo "This needs root. Run: sudo -E $0 $1" >&2; exit 1; }
}
need_platform() {
  [ -n "$FAMILY" ] || die "unsupported platform ($OS, /etc/os-release: ${ids:-none}). See README.md for the lines to add by hand."
}
need_phone() {
  case "$PHONE_ADDR" in
    ""|*[[:space:]]*|*:*:*|*:) echo "Set SUDOSTAMP_PHONE=<phone-ip>:7777 and run with sudo -E" >&2; exit 2 ;;
    *:*) ;;
    *) echo "SUDOSTAMP_PHONE must be host:port, e.g. 192.168.1.50:7777" >&2; exit 2 ;;
  esac
}
need_user() {
  if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = root ] || ! id "$TARGET_USER" >/dev/null 2>&1; then
    echo "Run via sudo from your own account, or set SUDOSTAMP_USER=<user>" >&2
    exit 2
  fi
}

# Root-owned and world-readable, numerically: macOS and FreeBSD have no `root` group.
own_root() { chown 0:0 "$@" && chmod 0644 "$@"; }

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
  [ -n "$sum" ] && [ "$(sha256_of "$dir/rustup-init")" = "$sum" ] || { bad "rustup-init checksum mismatch" >&2; return 1; }
  chmod 0755 "$dir/rustup-init"
  sudo -u "$TARGET_USER" env RUSTUP_HOME="$dir/rustup" CARGO_HOME="$dir/cargo" \
    "$dir/rustup-init" -y -q --no-modify-path --profile minimal --default-toolchain stable >/dev/null 2>&1 || return 1
  echo "$dir/cargo/bin/cargo"
}
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
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
  trap 'rm -rf "${BUILD_DIR:-}"' EXIT
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

  say "  building pam_rssh $RSSH_TAG (a few minutes)"
  sudo -u "$TARGET_USER" git -c advice.detachedHead=false clone -q --depth 1 --branch "$RSSH_TAG" \
      --recurse-submodules --shallow-submodules "$RSSH_REPO" "$work/pam_rssh" || die "git clone failed"
  # As the user: root reading a user-owned checkout trips git's safe.directory check.
  [ "$(sudo -u "$TARGET_USER" git -C "$work/pam_rssh" rev-parse HEAD)" = "$RSSH_COMMIT" ] || \
    die "pam_rssh $RSSH_TAG is not commit $RSSH_COMMIT -- refusing to build a moved tag"
  ok "source is commit $RSSH_COMMIT"

  local env=(env "${RUSTUP_ENV[@]}" "RUSTC=$rustc")
  [ "$FAMILY" = macos ] && env+=("OPENSSL_DIR=$(sudo -u "$TARGET_USER" brew --prefix openssl@3)")
  (cd "$work/pam_rssh" && sudo -u "$TARGET_USER" "${env[@]}" "$cargo" build --release --locked -q) || \
    die "cargo build failed"

  case "$FAMILY" in
    macos) dest=/usr/local/lib/pam/pam_rssh.so; mkdir -p /usr/local/lib/pam ;;
    *)     dest="$(module_dir)/pam_rssh.so" || die "no PAM module directory found" ;;
  esac
  local built="$work/pam_rssh/target/release/libpam_rssh.so"
  [ -f "$built" ] || built="$work/pam_rssh/target/release/libpam_rssh.dylib"
  cp "$built" "$dest.sudostamp-new" && own_root "$dest.sudostamp-new" && mv -f "$dest.sudostamp-new" "$dest" || \
    die "could not install $dest"
  # SELinux (Fedora/RHEL): a file copied from a build dir keeps the wrong label, and PAM
  # then fails to load it with a misleading "cannot open shared object".
  command -v restorecon >/dev/null 2>&1 && restorecon "$dest"
  ok "installed $dest"
}

install_pam_rssh() {
  local mod
  if mod="$(find_pam_rssh)"; then ok "pam_rssh already installed: $mod"; return 0; fi
  case "$FAMILY" in
    arch)
      local aur
      for aur in yay paru; do
        if command -v "$aur" >/dev/null 2>&1; then
          warn "installing pam_rssh from the AUR with $aur"
          sudo -u "$TARGET_USER" "$aur" -S --noconfirm pam_rssh && find_pam_rssh >/dev/null && return 0
        fi
      done
      build_pam_rssh ;;
    freebsd)
      pkg_install pam_rssh || die "pkg install pam_rssh failed" ;;
    *)
      build_pam_rssh ;;
  esac
  mod="$(find_pam_rssh)" || die "pam_rssh not found after install"
  ok "module: $mod"
}

# The local-vs-remote gate, only where a local sensor can exist (Linux with pam_fprintd).
install_gate() {
  mkdir -p "$(dirname "$GATE")"
  cp "$HERE/sudostamp-is-local.sh" "$GATE.sudostamp-new" && chown 0:0 "$GATE.sudostamp-new" && \
    chmod 0755 "$GATE.sudostamp-new" && mv -f "$GATE.sudostamp-new" "$GATE"
}
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

# Our lines. The sensor pair only with a local fingerprint reader, and only on Linux-PAM:
# `[success=ok default=1]` is Linux-PAM syntax that OpenPAM does not have.
block_lines() {
  local mod; mod="$(module_ref)" || die "pam_rssh is not installed -- run 'stage' first"
  if has_fprintd; then
    printf 'auth       [success=ok default=1]  pam_exec.so quiet %s\n' "$GATE"
    printf 'auth       sufficient   pam_fprintd.so timeout=%s max-tries=1\n' "$FPRINT_TIMEOUT"
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
without_block() {
  awk -v b="$BEGIN_MARK" -v e="$END_MARK" '$0==b{s=1; next} $0==e{s=0; next} !s' "$1"
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
  python3 - "$PHONE_ADDR" <<'PY'
import base64, socket, struct, sys
host, port = sys.argv[1].rsplit(":", 1)
s = socket.create_connection((host, int(port)), timeout=10)
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
body = rx(ln)
if body[0] != 12:
    raise SystemExit("unexpected reply type %d" % body[0])
n = struct.unpack(">I", body[1:5])[0]
if n != 1:
    raise SystemExit("expected exactly 1 key, got %d" % n)
o = 5
klen = struct.unpack(">I", body[o:o+4])[0]; o += 4
blob = body[o:o+klen]; o += klen
clen = struct.unpack(">I", body[o:o+4])[0]; o += 4
comment = body[o:o+clen].decode()
print("ecdsa-sha2-nistp256 %s %s" % (base64.b64encode(blob).decode(), comment))
PY
}

# ---------------------------------------------------------------------- stage

cmd_stage() {
  need_root stage; need_platform; need_phone; need_user
  say "=== stage: pam_rssh + pinned key ($FAMILY). No PAM changes. ==="
  base_deps || die "could not install base dependencies (python3, ssh-keygen, git)"

  # The key first: a wrong phone or an impostor is refused before minutes of building.
  local key fp answer
  key="$(fetch_key)" || die "could not fetch the public key from $PHONE_ADDR -- is the app open and Ready?"
  fp="$(printf '%s\n' "$key" | ssh-keygen -lf - | awk '{print $2}')" || die "the phone's answer is not a valid public key"
  say "     key at $PHONE_ADDR: $fp"
  if [ -n "${SUDOSTAMP_FINGERPRINT:-}" ]; then
    [ "$fp" = "$SUDOSTAMP_FINGERPRINT" ] || die "fingerprint mismatch: expected $SUDOSTAMP_FINGERPRINT"
    ok "fingerprint matches SUDOSTAMP_FINGERPRINT"
  else
    say "     Compare with the KEY FINGERPRINT on the SudoStamp screen. Every character must match."
    read -r -p "     Does it match? Type 'yes' to pin it: " answer
    [ "$answer" = yes ] || die "not pinned"
  fi

  install_pam_rssh
  has_fprintd && { install_gate; ok "local fingerprint reader found; gate installed: $GATE"; }
  warn_targetpw

  # Root-owned dir AND file. auth_keys.rs:87 does a bare read_to_string with no symlink or
  # ownership check, so the DIRECTORY must be unwritable by the user too.
  mkdir -p "$KEYDIR" && chown 0:0 "$KEYDIR" && chmod 0755 "$KEYDIR"
  ok "$KEYDIR (root, 0755)"
  printf '%s\n' "$key" | write_atomic "$KEYFILE"
  ok "pinned key written to $KEYFILE"
  say
  say "Next: sudo -E $0 test"
}

# ----------------------------------------------------------------------- test

cmd_test() {
  need_root test; need_platform; need_phone; need_user
  [ -f "$KEYFILE" ] || die "no pinned key -- run 'stage' first"
  say "=== test: a scratch PAM service. $(pam_target) is NOT touched. ==="
  # Only our lines, then deny: success here can only have come from the phone (or the
  # local sensor), never from a password.
  { echo "#%PAM-1.0"; block; echo "auth       required     pam_deny.so"; \
    echo "account    required     pam_permit.so"; } | write_atomic "$PAM_TEST"
  ok "wrote $PAM_TEST"
  sed 's/^/     /' "$PAM_TEST"
  say
  say "Approve on the phone now (a local reader, if any, is asked first):"
  if python3 "$HERE/pam_check.py" "$(basename "$PAM_TEST")" "$TARGET_USER"; then
    ok "the phone approved through PAM"
    say
    say "Next: sudo -E $0 apply   (keep a root shell open while you do)"
  else
    bad "authentication did not succeed -- see the result above. sudo is untouched."
    exit 1
  fi
}

# ---------------------------------------------------------------------- apply

cmd_apply() {
  need_root apply; need_platform; need_phone; need_user
  [ -f "$KEYFILE" ] || die "no pinned key -- run 'stage' first"
  find_pam_rssh >/dev/null || die "pam_rssh is not installed -- run 'stage' first"
  has_fprintd && install_gate
  local target src bak vendor=""
  target="$(pam_target)"
  say "=== apply: add the SudoStamp block to $target ==="

  if has_foreign_rssh "$target"; then
    die "$target already has pam_rssh lines this script did not write (an older SudoStamp, or a hand edit). Remove them first, or run 'rollback' to restore a backup."
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
    bak="${target}.bak-$(date +%Y%m%dT%H%M%SZ)"
    cp -p "$target" "$bak" && ok "backed up $bak"
  fi

  local new; new="$(mktemp)"
  if [ "$src" = /dev/null ]; then
    { echo "# sudo_local: local additions to sudo's PAM stack (macOS keeps this across updates)"; block; } > "$new"
  else
    { [ -n "$vendor" ] && { head -1 "$vendor"; echo "$VENDOR_MARK"; }
      if [ -n "$vendor" ]; then tail -n +2 "$vendor"; else cat "$src"; fi; } > "$new.src"
    with_block "$new.src" > "$new" || { rm -f "$new" "$new.src"; die "no auth rule found in $src -- not guessing where the block goes"; }
    rm -f "$new.src"
  fi
  write_atomic "$target" < "$new"; rm -f "$new"
  ok "wrote $target"
  sed 's/^/     /' "$target"
  warn_targetpw
  rm -f "$PAM_TEST"
  say
  say "The password path below the block is untouched: if the phone misbehaves, the password still works."
  say "Check in a SECOND terminal, keeping this one open:   sudo -k && sudo true"
  say "Undo:   sudo -E $0 rollback"
}

# ------------------------------------------------------------------- rollback

cmd_rollback() {
  need_root rollback; need_platform
  local target bak
  target="$(pam_target)"
  if has_block "$target"; then
    if grep -qF "$VENDOR_MARK" "$target"; then
      # We created this override from the vendor file; removing it restores the vendor
      # stack exactly.
      rm -f "$target" && ok "removed $target (the vendor file applies again)"
    else
      without_block "$target" | write_atomic "$target"
      ok "removed the SudoStamp block from $target"
    fi
  else
    # An older SudoStamp replaced the whole file. Put back the newest backup WITHOUT
    # pam_rssh: re-applying that old version made a backup of its own previous output each
    # time, so "the latest backup" is usually just another SudoStamp stack.
    local b
    bak=""
    # Names end in a UTC timestamp (YYYYmmddTHHMMSSZ), so glob order is age order: the last
    # match is the newest.
    for b in "${target}".bak-*; do
      [ -f "$b" ] || continue
      grep -q pam_rssh "$b" || bak="$b"
    done
    [ -n "$bak" ] || die "no SudoStamp block in $target and no backup without pam_rssh to restore"
    cp -p "$bak" "$target.sudostamp-new" && mv -f "$target.sudostamp-new" "$target"
    ok "restored $target from $bak"
  fi
  rm -f "$PAM_TEST" "$GATE"
  say "Check the password works:   sudo -k && sudo true"
}

# --------------------------------------------------------------------- status

cmd_status() {
  local target mod
  target="$(pam_target)"
  say "=== status ==="
  say "platform        : $OS ${FAMILY:-unsupported}"
  if mod="$(find_pam_rssh)"; then say "pam_rssh        : $mod"; else say "pam_rssh        : MISSING"; fi
  if [ -f "$KEYFILE" ]; then say "pinned key      : $KEYFILE ($(ls -l "$KEYFILE" | awk '{print $1, $3":"$4}'))"
  else say "pinned key      : absent ($KEYFILE)"; fi
  say "local reader    : $(has_fprintd && echo "pam_fprintd (gate: $GATE)" || echo none)"
  if has_block "$target"; then say "PAM             : SudoStamp block present in $target"
  elif has_foreign_rssh "$target"; then say "PAM             : pam_rssh lines NOT written by this script in $target"
  else say "PAM             : not applied ($target)"; fi
  say "scratch service : $([ -f "$PAM_TEST" ] && echo present || echo absent)"
  if sudo_auths_as_root; then say "sudo auth as    : ROOT (targetpw/rootpw) -- the phone is never asked; see 'stage' output"
  else say "sudo auth as    : the invoking user"; fi
  say "backups         : $(ls -1 "${target}".bak-* 2>/dev/null | wc -l | tr -d ' ')"
  [ -f "$target" ] && { say "--- $target ---"; sed 's/^/  /' "$target"; }
}

case "${1:-status}" in
  stage)    cmd_stage ;;
  test)     cmd_test ;;
  apply)    cmd_apply ;;
  rollback) cmd_rollback ;;
  status)   cmd_status ;;
  *)        echo "usage: $0 {stage|test|apply|rollback|status}"; exit 2 ;;
esac
