#!/bin/bash
# End-to-end test of the host side on one distribution, as root, in a THROWAWAY container
# (it installs packages, creates a user and rewrites /etc/pam.d/sudo):
#
#   podman run --rm -v "$PWD":/src:ro <image> bash /src/tools/test/e2e.sh
#
# The phone is tools/test/mock_agent.py (a software key, loopback only), so this proves
# everything except the biometric itself: install.sh on this distribution's packages and
# PAM layout, pam_rssh built from source and loaded, and a real `sudo`:
#
#   1. stage  -> pam_rssh installed, key pinned only after the fingerprint matched
#   2. test   -> the scratch service authenticates through the phone; a denial fails
#   3. apply  -> sudo succeeds with NO password while the phone approves
#   4. phone denies -> sudo falls through to the password, which still works
#   5. rollback -> the stack is byte-identical to before; the phone is no longer asked
#
# Exit 0 only if every step behaved. CI runs this for each supported family.
set -uo pipefail

PASS=0; FAIL=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
step() { printf '\n=== %s ===\n' "$*"; }
check() { local name="$1"; shift; if "$@"; then pass "$name"; else fail "$name"; fi; }
# Byte comparison with coreutils only: minimal images lack diffutils (cmp, diff), and a
# missing cmp once read as "the stack changed" on Fedora.

U=tester
PW='correct horse battery staple'
PORT=7777
W=/w

step "setup: $( . /etc/os-release; echo "$PRETTY_NAME")"
# SUDOSTAMP_SRC: the checkout (CI points it at $CI_PROJECT_DIR). Copied, so the test never
# writes into it.
rm -rf "$W"; cp -a "${SUDOSTAMP_SRC:-/src}" "$W"
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
  *" arch "*)
    pacman -Sy --noconfirm --needed sudo python python-cryptography procps-ng >/dev/null ;;
  *" debian "*|*" ubuntu "*)
    apt-get update -q >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends sudo python3 python3-cryptography procps passwd >/dev/null ;;
  *" fedora "*|*" rhel "*)
    dnf install -y -q sudo python3 python3-cryptography procps-ng shadow-utils >/dev/null ;;
  *suse*)
    zypper -q --non-interactive install -y sudo python3 python3-cryptography procps shadow >/dev/null ;;
esac
command -v sudo >/dev/null || { echo "sudo did not install"; exit 1; }

useradd -m "$U" 2>/dev/null
echo "$U:$PW" | chpasswd
# A sudoers rule for the user alone, so the test does not depend on each distribution's
# wheel/sudo group conventions. -k and no cached credentials: every sudo below authenticates.
echo "$U ALL=(ALL) ALL" > /etc/sudoers.d/90-sudostamp-test
echo "Defaults:$U timestamp_timeout=0" >> /etc/sudoers.d/90-sudostamp-test
chmod 0440 /etc/sudoers.d/90-sudostamp-test

TARGET=/etc/pam.d/sudo
before="$(mktemp)"
if [ -f "$TARGET" ]; then cp "$TARGET" "$before"; had_target=1; else had_target=0; fi

echo approve > /tmp/mode
python3 "$W/tools/test/mock_agent.py" --port "$PORT" --pubkey-out /tmp/mock.pub --mode-file /tmp/mode \
  > /tmp/mock.log 2>&1 &
for _ in $(seq 1 50); do [ -s /tmp/mock.pub ] && break; sleep 0.1; done
FP="$(ssh-keygen -lf /tmp/mock.pub 2>/dev/null | awk '{print $2}')"
# ssh-keygen may not be installed yet; stage installs it. Compute the fingerprint in Python.
[ -n "$FP" ] || FP="$(python3 -c '
import base64,hashlib,sys
b=base64.b64decode(open("/tmp/mock.pub").read().split()[1])
print("SHA256:"+base64.b64encode(hashlib.sha256(b).digest()).decode().rstrip("="))')"
echo "  mock phone on 127.0.0.1:$PORT, key $FP"

# ALLOW_RUSTUP: distributions whose own Rust is too old take the throwaway-toolchain path,
# which is then tested too.
export SUDOSTAMP_PHONE="127.0.0.1:$PORT" SUDOSTAMP_USER="$U" SUDOSTAMP_ALLOW_RUSTUP=1
I="$W/tools/install.sh"

# sudo as the test user, the way a person types it: -k (no cached credentials), the
# password (if any is asked for) from stdin.
as_user_sudo() { su "$U" -c "sudo -k; printf '%s\n' \"$1\" | sudo -S -p '' true" >/dev/null 2>&1; }

step "0. a hostile phone cannot pin a second key"
# A phone that hides an extra (ed25519) key behind a newline in its key comment. pam_rssh
# accepts any key type in the pinned file, so a pinned extra line would let its holder
# approve this user's sudo. stage must pin exactly the one key the fingerprint names.
EVIL_PUB="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl evil"
echo approve > /tmp/mode-evil
python3 "$W/tools/test/mock_agent.py" --port 7778 --pubkey-out /tmp/evil.pub --mode-file /tmp/mode-evil \
  --comment "$(printf 'phone\n%s' "$EVIL_PUB")" > /tmp/evil.log 2>&1 &
EVIL_PID=$!
for _ in $(seq 1 50); do [ -s /tmp/evil.pub ] && break; sleep 0.1; done
# The fingerprint path (pairing never reads the comment at all): the fingerprint of the
# phone's real key matches, which is exactly where the old installer pinned both lines.
EVIL_FP="$(python3 -c '
import base64,hashlib
b=base64.b64decode(open("/tmp/evil.pub").read().split()[1])
print("SHA256:"+base64.b64encode(hashlib.sha256(b).digest()).decode().rstrip("="))')"
bash "$W/tools/install.sh" stage --phone 127.0.0.1:7778 --fingerprint "$EVIL_FP" >/tmp/stage-evil.log 2>&1
check "only one key is pinned, and not the smuggled one" \
  bash -c "[ \"\$(wc -l < /etc/authorized_keys/$U.keys)\" = 1 ] && ! grep -q evil /etc/authorized_keys/$U.keys"
kill "$EVIL_PID" 2>/dev/null
rm -f "/etc/authorized_keys/$U.keys"

step "1. stage"
SUDOSTAMP_FINGERPRINT="SHA256:wrong" bash "$I" stage >/tmp/stage-wrong.log 2>&1
check "a wrong fingerprint is refused and nothing is pinned" \
  bash -c "grep -q 'fingerprint mismatch' /tmp/stage-wrong.log && [ ! -f /etc/authorized_keys/$U.keys ]"
# Arguments, the documented form (the environment form is covered by the steps below).
bash "$I" stage --phone "127.0.0.1:$PORT" --fingerprint "$FP" 2>&1 | tee /tmp/stage.log | grep -vE '^\s*$'
check "stage exits cleanly (no shell errors)" bash -c "! grep -qE 'unbound variable|command not found|syntax error' /tmp/stage.log"
check "the key is pinned, root-owned" bash -c "[ \"\$(stat -c %U /etc/authorized_keys/$U.keys)\" = root ]"
check "pam_rssh is installed" bash -c "bash '$I' status | grep -q 'pam_rssh        : /'"

# openSUSE's default `Defaults targetpw` makes sudo authenticate as root, which bypasses the
# phone entirely. The installer must SAY so (it never edits sudoers), and the documented
# one-line override must make SudoStamp work.
# Only the files that exist: grep exits 2 for a missing one even on a match, and under
# pipefail so does `cat a b | grep`. Both silently skipped this block on openSUSE.
sudoers_files="$(ls /etc/sudoers /usr/etc/sudoers 2>/dev/null)"
# shellcheck disable=SC2086
if [ -n "$sudoers_files" ] && grep -hqE '^[[:space:]]*Defaults[[:space:]][^#]*targetpw' $sudoers_files; then
  check "stage warns that sudo authenticates as root here" grep -q "TARGET's (root's) password" /tmp/stage.log
  echo "Defaults:$U !targetpw, !rootpw, !runaspw" > /etc/sudoers.d/50-sudostamp
  chmod 0440 /etc/sudoers.d/50-sudostamp
  # -f our file: a whole `visudo -c` fails on openSUSE regardless, because its vendor
# /usr/etc/sudoers is mode 0444 rather than 0440.
check "the documented override is accepted by visudo" visudo -c -q -f /etc/sudoers.d/50-sudostamp
  check "status no longer reports root authentication" bash -c "bash '$I' status | grep -q 'sudo auth as    : the invoking user'"
fi

step "2. test (scratch service; sudo untouched)"
check "the scratch service authenticates through the phone" bash "$I" test
check "the sudo stack is untouched by stage and test" \
  bash -c "if [ $had_target = 1 ]; then [ \"\$(cksum < '$before')\" = \"\$(cksum < '$TARGET')\" ]; else [ ! -f '$TARGET' ]; fi"
echo deny > /tmp/mode
check "the scratch service FAILS when the phone denies" \
  bash -c "! python3 '$W/tools/pam_check.py' sudostamp-test '$U'"
echo approve > /tmp/mode

step "3. apply"
bash "$I" apply 2>&1 | tail -3
check "sudo succeeds with NO password while the phone approves" as_user_sudo ""
check "the phone was asked" grep -q "sign: approved" /tmp/mock.log

step "4. the phone denies"
echo deny > /tmp/mode
check "sudo without the password fails" \
  bash -c "! su $U -c \"sudo -k; sudo -S -p '' true </dev/null\" >/dev/null 2>&1"
check "sudo WITH the password still works (fallback intact)" as_user_sudo "$PW"
echo approve > /tmp/mode

step "5. rollback"
bash "$I" rollback 2>&1 | tail -2
check "the stack is back exactly as it was" \
  bash -c "if [ $had_target = 1 ]; then [ \"\$(cksum < '$before')\" = \"\$(cksum < '$TARGET')\" ]; else [ ! -f '$TARGET' ]; fi"
check "sudo no longer asks the phone (needs the password)" \
  bash -c "! su $U -c \"sudo -k; sudo -S -p '' true </dev/null\" >/dev/null 2>&1"
check "the password works after rollback" as_user_sudo "$PW"

# ------------------------------------------------------------- the one-command setup
# A fresh mock phone per run: pairing allows one exchange per arming, like the app.
pairing_phone() {   # $1 = port; writes /tmp/p$1.pub and, once paired, /tmp/p$1.code
  rm -f "/tmp/p$1.code"
  python3 "$W/tools/test/mock_agent.py" --port "$1" --pubkey-out "/tmp/p$1.pub" --mode-file /tmp/mode \
    --code-file "/tmp/p$1.code" "${@:2}" > "/tmp/p$1.log" 2>&1 &
  for _ in $(seq 1 50); do [ -s "/tmp/p$1.pub" ] && break; sleep 0.1; done
}
# The person: waits for the phone to show a code, then types it (and answers yes, if asked).
type_code_from() { for _ in $(seq 1 100); do [ -s "$1" ] && break; sleep 0.1; done; cat "$1"; echo yes; }

step "6. setup: pair + install + test + apply, one command"
pairing_phone 7781
# Exactly as the README says to run it: executed directly, not via `bash`. (Running it
# through bash everywhere once hid that the file had lost its executable bit.)
type_code_from /tmp/p7781.code | "$I" setup --phone 127.0.0.1:7781 > /tmp/setup1.log 2>&1
check "setup succeeds" grep -q "Done. Every sudo now asks your phone first" /tmp/setup1.log
check "the paired phone's key is the one pinned" \
  bash -c "[ \"\$(awk '{print \$2}' /etc/authorized_keys/$U.keys)\" = \"\$(awk '{print \$2}' /tmp/p7781.pub)\" ]"
check "sudo succeeds with NO password via the paired phone" as_user_sudo ""
check "exactly one SudoStamp block" bash -c "[ \"\$(grep -c '^# >>> SudoStamp >>>' '$TARGET')\" = 1 ]"

step "7. setup again (a new phone): still one block"
pairing_phone 7782
type_code_from /tmp/p7782.code | bash "$I" setup --phone 127.0.0.1:7782 > /tmp/setup2.log 2>&1
check "re-running setup leaves exactly one block" bash -c "[ \"\$(grep -c '^# >>> SudoStamp >>>' '$TARGET')\" = 1 ]"
check "and the block points at the new phone" grep -q "ssh_agent_addr=127.0.0.1:7782" "$TARGET"
check "sudo works via the new phone" as_user_sudo ""

step "8. a man in the middle cannot pin its key"
pairing_phone 7783
# The attacker answers at the address setup dials (7784) and pairs with the real phone (7783)
# behind its back; the person types the code their REAL phone shows.
python3 "$W/tools/test/mock_agent.py" --port 7784 --pubkey-out /tmp/mitm.pub --mode-file /tmp/mode \
  --mitm-to 127.0.0.1:7783 > /tmp/mitm.log 2>&1 &
for _ in $(seq 1 50); do [ -s /tmp/mitm.pub ] && break; sleep 0.1; done
cp /etc/authorized_keys/$U.keys /tmp/keys.before
cp "$TARGET" /tmp/pam.before
type_code_from /tmp/p7783.code | bash "$I" setup --phone 127.0.0.1:7784 > /tmp/setup-mitm.log 2>&1
check "setup refuses" bash -c "! grep -q 'Done.' /tmp/setup-mitm.log && grep -q 'NOTHING was pinned' /tmp/setup-mitm.log"
check "the pinned key and the PAM stack are unchanged" \
  bash -c "[ \"\$(cksum < /tmp/keys.before)\" = \"\$(cksum < /etc/authorized_keys/$U.keys)\" ] && [ \"\$(cksum < /tmp/pam.before)\" = \"\$(cksum < '$TARGET')\" ]"
check "the attacker's key is nowhere" bash -c "! grep -qF \"\$(awk '{print \$2}' /tmp/mitm.pub)\" /etc/authorized_keys/$U.keys"

step "9. an older whole-file SudoStamp is migrated"
bash "$I" rollback > /dev/null 2>&1
if [ -f "$TARGET" ]; then
  # What the old installer left: a timestamped backup of the original, and a stack with
  # pam_rssh lines but no markers.
  cp "$TARGET" "$TARGET.bak-20260101T000000Z"
  { head -1 "$TARGET"; echo "auth sufficient pam_rssh.so ssh_agent_addr=127.0.0.1:7781 auth_key_file=/etc/authorized_keys/\${user}.keys"; tail -n +2 "$TARGET"; } > /tmp/legacy
  cp /tmp/legacy "$TARGET"
  pairing_phone 7785
  type_code_from /tmp/p7785.code | bash "$I" setup --phone 127.0.0.1:7785 > /tmp/setup-legacy.log 2>&1
  check "setup migrates it" grep -q "Done." /tmp/setup-legacy.log
  check "one block, no unmarked pam_rssh lines left" \
    bash -c "[ \"\$(grep -c pam_rssh '$TARGET')\" = 1 ] && grep -q '^# >>> SudoStamp >>>' '$TARGET'"
  check "sudo works via the phone" as_user_sudo ""
  echo deny > /tmp/mode
  check "and the password still works when the phone denies" as_user_sudo "$PW"
  echo approve > /tmp/mode
fi

printf '\n%s: %d passed, %d failed\n' "$( . /etc/os-release; echo "$ID $VERSION_ID")" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
