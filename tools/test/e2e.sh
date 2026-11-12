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
#   6-10. one-command setup, the single-file installer, a key-swapping man in the middle,
#         migration from 1.2, an IPv6 address
#   11. what must NOT work: a relay that passes pairing through unchanged, a phone that
#       stalls (sudo must not hang), a phone with the wrong key, no phone at all, a hostile
#       --phone value, a gate whose success must not count as authentication, a damaged
#       block that rollback must refuse to "fix"
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
    # -Syu, not -Sy: a synced database over a stale image is a partial upgrade (openssl moves).
    pacman -Syu --noconfirm --needed sudo python python-cryptography procps-ng >/dev/null ;;
  *" debian "*|*" ubuntu "*)
    apt-get update -q >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends sudo python3 python3-cryptography procps passwd >/dev/null ;;
  *" fedora "*|*" rhel "*)
    # util-linux: the test switches users with `su`, which Fedora 45's container image dropped.
    dnf install -y -q sudo python3 python3-cryptography procps-ng shadow-utils util-linux >/dev/null ;;
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
# What the sudo stack is right now, as one comparable line: openSUSE may have no /etc file at all
# (the vendor file applies), and a `cp` of a missing file would silently compare stale copies.
stack_state() { if [ -f "$TARGET" ]; then cksum < "$TARGET"; else echo absent; fi; }
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
  for _ in $(seq 1 300); do [ -s "/tmp/p$1.pub" ] && break; sleep 0.1; done
}
# The person: waits for the phone to show a code, then types it (and answers yes, if asked).
type_code_from() { for _ in $(seq 1 600); do [ -s "$1" ] && break; sleep 0.1; done; cat "$1"; echo yes; }

step "6. setup: pair + install + test + apply, one command"
pairing_phone 7781
# Exactly as the README says to run it: executed directly, not via `bash`. (Running it
# through bash everywhere once hid that the file had lost its executable bit.)
type_code_from /tmp/p7781.code | "$I" setup --phone 127.0.0.1:7781 > /tmp/setup1.log 2>&1
check "setup succeeds" grep -q "Done. Every sudo now asks your phone first" /tmp/setup1.log
check "the paired phone's key is the one pinned" \
  bash -c "[ \"\$(awk '{print \$2}' /etc/authorized_keys/$U.keys)\" = \"\$(awk '{print \$2}' /tmp/p7781.pub)\" ]"
check "sudo succeeds with NO password via the paired phone" as_user_sudo ""
# The mock sends what an emulator would: a software chain under a root that is nobody's.
check "setup says the key is not hardware-attested, and goes on" grep -q "Key NOT hardware-attested (the chain does not end at a Google" /tmp/setup1.log
check "status shows it" bash -c "bash '$I' status 2>&1 | grep -q 'key attestation : Key NOT hardware-attested'"
check "the record sits beside the key, root-owned, and the key file is still one line" \
  bash -c "[ \"\$(stat -c '%u %a' /etc/authorized_keys/$U.attestation)\" = '0 644' ] && [ \"\$(wc -l < /etc/authorized_keys/$U.keys)\" = 1 ]"
check "exactly one SudoStamp block" bash -c "[ \"\$(grep -c '^# >>> SudoStamp >>>' '$TARGET')\" = 1 ]"

step "7. setup again (a new phone), from the single-file download: still one block"
# What users actually download: dist/sudostamp-setup.sh, built from this tree.
"$W/scripts/bundle-host.sh" > /dev/null
pairing_phone 7782
type_code_from /tmp/p7782.code | bash "$W/dist/sudostamp-setup.sh" --phone 127.0.0.1:7782 > /tmp/setup2.log 2>&1
check "the single-file installer runs setup by default" grep -q "Done. Every sudo now asks your phone first" /tmp/setup2.log
check "and leaves nothing behind in /tmp" bash -c "! ls -d /tmp/sudostamp-setup.* >/dev/null 2>&1"
check "re-running setup leaves exactly one block" bash -c "[ \"\$(grep -c '^# >>> SudoStamp >>>' '$TARGET')\" = 1 ]"
check "and the block points at the new phone" grep -q "ssh_agent_addr=127.0.0.1:7782" "$TARGET"
check "sudo works via the new phone" as_user_sudo ""
check "no backups or scratch services left in the PAM directory" \
  bash -c "! ls /etc/pam.d/sudo.bak-* /etc/pam.d/sudostamp-test >/dev/null 2>&1"
check "the backups are in /var/lib/sudostamp/backups, root-only" \
  bash -c "ls /var/lib/sudostamp/backups/sudo.bak-* >/dev/null 2>&1 && [ \"\$(stat -c %a /var/lib/sudostamp/backups)\" = 700 ]"
check "the probe guards pam_rssh" grep -q "pam_exec.so quiet /usr/local/sbin/sudostamp-probe phone=127.0.0.1:7782 keys=/etc/authorized_keys" "$TARGET"

# The phone's address is held by something that accepts and never answers (another device
# after a DHCP change, or someone squatting). pam_rssh has no timeout; the probe must keep sudo
# from hanging, and the password must still work -- within seconds, not minutes.
echo stall > /tmp/mode
t0=$(date +%s)
check "a stalling phone does not hang sudo: the password works" timeout 60 bash -c "$(declare -f as_user_sudo); U=$U; as_user_sudo '$PW'"
check "and it took seconds, not the minute" bash -c "[ \$(( \$(date +%s) - $t0 )) -lt 30 ]"
echo foreign > /tmp/mode
before_signs=$(grep -c "^sign:" /tmp/p7782.log)
check "a phone with a key nobody pinned: the password works" timeout 60 bash -c "$(declare -f as_user_sudo); U=$U; as_user_sudo '$PW'"
check "and without the password sudo fails" \
  bash -c "! timeout 60 su $U -c \"sudo -k; sudo -S -p '' true </dev/null\" >/dev/null 2>&1"
check "and that phone was never asked to sign" bash -c "[ \"\$(grep -c '^sign:' /tmp/p7782.log)\" = '$before_signs' ]"
echo approve > /tmp/mode
pkill -f -- "--port 7782 " 2>/dev/null; sleep 0.5
t0=$(date +%s)
check "no phone at all: the password works, quickly" timeout 60 bash -c "$(declare -f as_user_sudo); U=$U; as_user_sudo '$PW'"
check "and it took seconds" bash -c "[ \$(( \$(date +%s) - $t0 )) -lt 20 ]"

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

step "8b. a relay that passes pairing through unchanged cannot pin its address"
# Answering discovery first and relaying every byte, untouched, to the real phone: the codes
# would match, and the relay's address would go into sudo's configuration for good. The phone
# reports the address it was dialled on; it is not the relay's.
pairing_phone 7787
python3 "$W/tools/test/mock_agent.py" --port 7786 --relay-to 127.0.0.1:7787 > /tmp/relay.log 2>&1 &
for _ in $(seq 1 50); do grep -q "relay on" /tmp/relay.log 2>/dev/null && break; sleep 0.1; done
state0="$(stack_state)"
type_code_from /tmp/p7787.code | bash "$I" setup --phone 127.0.0.1:7786 > /tmp/setup-relay.log 2>&1
check "setup refuses: something answered in the phone's place" \
  bash -c "! grep -q 'Done.' /tmp/setup-relay.log && grep -q 'answered in the phone' /tmp/setup-relay.log"
check "the PAM stack is unchanged and never names the relay" \
  bash -c "[ '$state0' = \"\$($(declare -f stack_state); TARGET='$TARGET'; stack_state)\" ] && ! grep -qs 7786 '$TARGET'"

step "8c. --require-attestation refuses a phone that cannot prove its key is in hardware"
pairing_phone 7788
cp /etc/authorized_keys/$U.keys /tmp/keys.before
cp /etc/authorized_keys/$U.attestation /tmp/attest.before
state0="$(stack_state)"
type_code_from /tmp/p7788.code | bash "$I" setup --phone 127.0.0.1:7788 --require-attestation > /tmp/setup-req.log 2>&1
check "setup refuses" bash -c "! grep -q 'Done.' /tmp/setup-req.log && grep -q 'NOT pinned (--require-attestation)' /tmp/setup-req.log"
check "the key, its attestation record and the PAM stack are unchanged" \
  bash -c "[ \"\$(cksum < /tmp/keys.before)\" = \"\$(cksum < /etc/authorized_keys/$U.keys)\" ] && [ \"\$(cksum < /tmp/attest.before)\" = \"\$(cksum < /etc/authorized_keys/$U.attestation)\" ] && [ '$state0' = \"\$($(declare -f stack_state); TARGET='$TARGET'; stack_state)\" ]"
check "the refused phone's key is nowhere" bash -c "! grep -qF \"\$(awk '{print \$2}' /tmp/p7788.pub)\" /etc/authorized_keys/$U.keys"
check "the phone was asked for its attestation only after pair-done" \
  bash -c "[ \"\$(grep -n 'pairing: done' /tmp/p7788.log | cut -d: -f1)\" -lt \"\$(grep -n 'attest: software chain sent' /tmp/p7788.log | cut -d: -f1)\" ]"

step "8d. a phone of the app before 1.5 (no attestation extension) still pairs"
pairing_phone 7789 --attest none
type_code_from /tmp/p7789.code | bash "$I" setup --phone 127.0.0.1:7789 > /tmp/setup-old.log 2>&1
check "setup goes on, saying why there is no attestation" \
  bash -c "grep -q 'Done. Every sudo now asks your phone first' /tmp/setup-old.log && grep -q 'app is older than 1.5' /tmp/setup-old.log"
check "status shows that, for the key pinned now (not the previous one)" \
  bash -c "bash '$I' status 2>&1 | grep -q 'key attestation : Key NOT hardware-attested (the phone sent no attestation'"
check "a key pinned without pairing drops the record" \
  bash -c "bash '$I' stage --phone 127.0.0.1:7789 --key \"\$(cat /tmp/p7789.pub)\" >/dev/null 2>&1; [ ! -e /etc/authorized_keys/$U.attestation ] && bash '$I' status 2>&1 | grep -q 'key attestation : not attested (paired before 1.5'"

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

step "10. an IPv6 phone address (stable across DHCP changes) works through pam_rssh"
if python3 -c 'import socket; s=socket.socket(socket.AF_INET6); s.bind(("::1",0))' 2>/dev/null; then
  pairing_phone 7791 --host ::1
  type_code_from /tmp/p7791.code | "$I" setup --phone "[::1]:7791" > /tmp/setup-v6.log 2>&1
  check "setup accepts a bracketed IPv6 address" grep -q "Done. Every sudo now asks your phone first" /tmp/setup-v6.log
  check "the PAM line carries the IPv6 literal" grep -qF "ssh_agent_addr=[::1]:7791" "$TARGET"
  check "and so does the probe, in a form PAM does not mangle" grep -qF "sudostamp-probe phone=[::1]:7791 keys=" "$TARGET"
  check "pam_rssh dials it: sudo works with NO password" as_user_sudo ""
  echo deny > /tmp/mode
  check "and the password still works when that phone denies" as_user_sudo "$PW"
  echo approve > /tmp/mode
else
  echo "  (no IPv6 loopback in this container: skipped)"
fi

step "11. what must not work"
# A --phone value with a second line is a second PAM rule. It must be refused before anything.
state0="$(stack_state)"
bash "$I" stage --phone "$(printf '127.0.0.1:7777 x\nauth sufficient pam_permit.so\n127.0.0.1:7777')" >/tmp/evil-phone.log 2>&1
check "a --phone value with a hidden PAM rule is refused" \
  bash -c "grep -q 'must be an address and port' /tmp/evil-phone.log && [ '$state0' = \"\$($(declare -f stack_state); TARGET='$TARGET'; stack_state)\" ]"
bash "$I" stage --phone "phone.example:7777" >/tmp/name-phone.log 2>&1
check "a host name is refused (pam_rssh could never dial it)" grep -q 'must be an address and port' /tmp/name-phone.log

# The gate's control flags: its success must not count as authentication. With 1.3's
# [success=ok default=1], a stack of gate + failing `sufficient` modules and nothing required
# below AUTHENTICATED. (pam_fprintd is not in these images; pam_deny stands in for every check.)
GC="$(sed -n "s/^GATE_CONTROL='\(.*\)'\$/\1/p" "$I")"
TRUE_BIN="$(ls /usr/bin/true /bin/true 2>/dev/null | head -1)"
for form in new old; do
  [ $form = new ] && ctl="$GC" || ctl='[success=ok default=1]'
  { echo "#%PAM-1.0"; echo "auth $ctl pam_exec.so quiet $TRUE_BIN"; echo "auth sufficient pam_deny.so"
    echo "auth sufficient pam_deny.so"; echo "account required pam_permit.so"; } > /etc/pam.d/sudostamp-gatecheck
  if python3 "$W/tools/pam_check.py" sudostamp-gatecheck "$U" >/dev/null 2>&1; then echo "$form: authenticated"; else echo "$form: refused"; fi
done > /tmp/gate.log
rm -f /etc/pam.d/sudostamp-gatecheck
check "the installer's gate flags do not authenticate when every check fails" grep -qx "new: refused" /tmp/gate.log
check "(and 1.3's did -- the test can tell the difference)" grep -qx "old: authenticated" /tmp/gate.log

# Rollback with a BEGIN marker and no END would have dropped every line after it -- the
# whole auth stack, password included. It must refuse and change nothing.
BEGIN_LINE="$(sed -n 's/^BEGIN_MARK="\(.*\)"$/\1/p' "$I")"
# Needs a sudo stack carrying a block; set one up if an earlier step left none.
if ! grep -qsF '# >>> SudoStamp >>>' "$TARGET"; then
  pairing_phone 7792
  type_code_from /tmp/p7792.code | bash "$I" setup --phone 127.0.0.1:7792 > /tmp/setup-rb.log 2>&1
fi
cp "$TARGET" /tmp/pam.good
{ head -1 /tmp/pam.good; echo "$BEGIN_LINE"; tail -n +2 /tmp/pam.good | grep -vF '# >>> SudoStamp >>>' | grep -vF '# <<< SudoStamp <<<'; } > "$TARGET"
cp "$TARGET" /tmp/pam.broken
bash "$I" rollback >/tmp/rollback-broken.log 2>&1
if grep -qF "SudoStamp: copied from the vendor file" /tmp/pam.good; then
  # openSUSE: the whole file is our copy of the vendor stack, so rollback deletes it and the
  # vendor file applies again, exactly -- markers or not, nothing of the user's is lost.
  check "rollback of our own vendor copy removes it, whatever its markers" \
    bash -c "[ ! -f '$TARGET' ] && { [ -f /usr/lib/pam.d/sudo ] || [ -f /usr/etc/pam.d/sudo ]; }"
else
  check "rollback refuses a block with no end marker, and changes nothing" \
    bash -c "grep -q 'damaged SudoStamp markers' /tmp/rollback-broken.log && [ \"\$(cksum < /tmp/pam.broken)\" = \"\$(cksum < '$TARGET')\" ]"
fi
cp /tmp/pam.good "$TARGET"

# ------------------------------------------------- the timeouts patch, doctor, uninstall
MARK=/var/lib/sudostamp/pam_rssh.built
PATCH="$W/tools/patches/pam_rssh-timeouts.patch"
PINNED="$(sed -n 's/^PATCH_SHA256="\(.*\)"$/\1/p' "$I")"

step "12. pam_rssh's timeouts: pinned, recorded, and rebuilt on old installs"
check "the pinned patch hash is the patch file's" \
  bash -c "[ \"\$(sha256sum < '$PATCH' | awk '{print \$1}')\" = '$PINNED' ]"
check "the build is recorded and status says patched" \
  bash -c "[ -s $MARK ] && bash '$I' status | grep -q 'patched (timeouts)'"
check "the single-file installer carries the same patch, byte for byte" \
  bash -c "[ \"\$(sed -n '/^cat > .*patches\\/pam_rssh-timeouts.patch/,/^SUDOSTAMP_BUNDLE_EOF\$/p' '$W/dist/sudostamp-setup.sh' | sed '1d;\$d' | sha256sum | awk '{print \$1}')\" = '$PINNED' ]"
MOD="$(sed -n 's/^module=//p' $MARK)"
rm -f "$MARK"                          # what a 1.4 install looks like: a module and no record
check "status calls an unrecorded module unpatched" bash -c "bash '$I' status | grep -q 'NOT patched'"
mod_sum="$(cksum < "$MOD")"
KEYLINE="$(cat "/etc/authorized_keys/$U.keys")"

# A patch that differs from the pinned hash must stop the build before anything is installed.
rm -rf /w2; cp -a "$W" /w2
echo "# tampered" >> /w2/tools/patches/pam_rssh-timeouts.patch
bash /w2/tools/install.sh stage --phone 127.0.0.1:7777 --key "$KEYLINE" > /tmp/stage-tamper.log 2>&1
check "a patch that does not match its pinned hash is refused" grep -q "does not match its pinned SHA-256" /tmp/stage-tamper.log
check "and the module and the record are untouched" bash -c "[ ! -e $MARK ] && [ \"\$(cksum < '$MOD')\" = '$mod_sum' ]"
# A patch with the right hash that does not apply (its context is wrong): same.
rm -rf /w3; cp -a "$W" /w3
sed -i 's/^ static NET_RETRY_CNT: u32 = 3;/ static NET_RETRY_CNT: u32 = 9;/' /w3/tools/patches/pam_rssh-timeouts.patch
BAD_SHA="$(sha256sum < /w3/tools/patches/pam_rssh-timeouts.patch | awk '{print $1}')"
sed -i "s/^PATCH_SHA256=.*/PATCH_SHA256=\"$BAD_SHA\"/" /w3/tools/install.sh
bash /w3/tools/install.sh stage --phone 127.0.0.1:7777 --key "$KEYLINE" > /tmp/stage-noapply.log 2>&1
check "a pinned patch that does not apply is refused" grep -q "does not apply to pam_rssh" /tmp/stage-noapply.log
check "(and the test patch really differs from the real one)" bash -c "[ '$BAD_SHA' != '$PINNED' ]"
rm -rf /w2 /w3

# The real one: stage rebuilds the unrecorded module with the timeouts.
bash "$I" stage --phone 127.0.0.1:7777 --key "$KEYLINE" > /tmp/stage-rebuild.log 2>&1
check "stage rebuilds a module that has no timeouts record" \
  bash -c "[ -s $MARK ] && bash '$I' status | grep -q 'patched (timeouts)' && grep -q 'timeouts patch applied' /tmp/stage-rebuild.log"

# The reason for all of it: a phone that answers the probe (so it passes the 4 s check) and
# then never answers the SIGN_REQUEST. Without a timeout in pam_rssh, sudo waits forever. The
# module's limit is 75 s (the phone's own approval window is 60 s), so the password must come
# up after about that long: not at once (the probe did not skip the phone) and not much later.
pairing_phone 7795
type_code_from /tmp/p7795.code | bash "$I" setup --phone 127.0.0.1:7795 > /tmp/setup-sstall.log 2>&1
check "setup for the stall test" grep -q "Done. Every sudo now asks your phone first" /tmp/setup-sstall.log
echo signstall > /tmp/mode
t0=$(date +%s)
check "a phone that stalls the signature: sudo falls back to the password" \
  timeout 150 bash -c "$(declare -f as_user_sudo); U=$U; as_user_sudo '$PW'"
el=$(( $(date +%s) - t0 ))
check "that phone really was asked to sign, and never answered" grep -q "^sign: stalled" /tmp/p7795.log
check "pam_rssh gave up after its timeout (${el}s: at least 70, under 90)" bash -c "[ $el -ge 70 ] && [ $el -lt 90 ]"
echo approve > /tmp/mode
pkill -f -- "--port 7795 " 2>/dev/null; sleep 0.5

step "13. doctor"
pairing_phone 7801
type_code_from /tmp/p7801.code | bash "$I" setup --phone 127.0.0.1:7801 > /tmp/setup-doc.log 2>&1
check "setup for doctor" grep -q "Done. Every sudo now asks your phone first" /tmp/setup-doc.log
# Everything doctor must leave alone: contents and metadata.
snap() {
  cksum "$TARGET" "/etc/authorized_keys/$U.keys" /usr/local/sbin/sudostamp-probe "$MARK" "$MOD" 2>&1
  # Not the "total" lines: they count allocated blocks, which a filesystem may still change for a
  # file written before doctor ran (CI's ZFS commits every ~5 s; doctor's no-phone path takes ~10 s).
  # Every entry's name, owner, mode, size and timestamp still must not move, and a file created and
  # deleted would show in its directory's timestamp.
  ls -la --time-style=full-iso /etc/pam.d /etc/authorized_keys /usr/local/sbin /var/lib/sudostamp "$(dirname "$MOD")" 2>&1 | sed '/^total /d'
}
doc() {   # $1 = log name; sets rc, and fails the run if doctor changed anything
  snap > "/tmp/doctor-$1.before"
  bash "$I" doctor > "/tmp/doctor-$1.log" 2>&1; rc=$?
  sed 's/^/    | /' "/tmp/doctor-$1.log"     # what a person would see
  snap > "/tmp/doctor-$1.after"
  # cksum, not cmp: minimal images have no diffutils (pitfall 15).
  if [ "$(cksum < "/tmp/doctor-$1.before")" = "$(cksum < "/tmp/doctor-$1.after")" ]; then pass "doctor ($1) changed nothing"
  else
    fail "doctor ($1) changed something"
    # Say WHAT, or the next person reruns blind: lines only in before (-) or only in after (+).
    grep -vxFf "/tmp/doctor-$1.after" "/tmp/doctor-$1.before" | sed 's/^/    - /'
    grep -vxFf "/tmp/doctor-$1.before" "/tmp/doctor-$1.after" | sed 's/^/    + /'
  fi
}
doc healthy
check "doctor on a healthy install exits 0" test "$rc" = 0
check "and prints no FAIL or WARN" bash -c "! grep -qE 'FAIL|WARN' /tmp/doctor-healthy.log"
check "and says pam_rssh is patched" grep -q "pam_rssh: patched (timeouts)" /tmp/doctor-healthy.log
check "and that the phone offers the pinned key" grep -q "offers $U's pinned key" /tmp/doctor-healthy.log

# Something answers at the phone's address, but it is not the paired phone.
pkill -f -- "--port 7801 " 2>/dev/null; sleep 0.5
python3 "$W/tools/test/mock_agent.py" --port 7801 --pubkey-out /tmp/doc2.pub --mode-file /tmp/mode > /tmp/doc2.log 2>&1 &
for _ in $(seq 1 50); do [ -s /tmp/doc2.pub ] && break; sleep 0.1; done
doc wrongkey
check "a phone that does not offer the pinned key: exit 1, FAIL, a fix command" \
  bash -c "[ $rc = 1 ] && grep -q 'FAIL.*does not offer the key pinned' /tmp/doctor-wrongkey.log && grep -q 'fix: sudo .* setup' /tmp/doctor-wrongkey.log"

pkill -f -- "--port 7801 " 2>/dev/null; sleep 0.5
doc nophone
check "with the phone stopped: exit 1, FAIL on the phone, a fix command" \
  bash -c "[ $rc = 1 ] && grep -q 'FAIL.*phone: nothing answers at 127.0.0.1:7801' /tmp/doctor-nophone.log && grep -q 'fix: ' /tmp/doctor-nophone.log"

chmod 0666 "/etc/authorized_keys/$U.keys"
doc keyperms
check "a key file anyone can write: exit 1 and FAIL on the pinned key" \
  bash -c "[ $rc = 1 ] && grep -q 'FAIL.*pinned key' /tmp/doctor-keyperms.log && grep -q 'fix: sudo chown' /tmp/doctor-keyperms.log"
chmod 0644 "/etc/authorized_keys/$U.keys"

cp "$TARGET" /tmp/pam.doc
{ head -1 /tmp/pam.doc; echo "$BEGIN_LINE"; tail -n +2 /tmp/pam.doc | grep -vF '# >>> SudoStamp >>>' | grep -vF '# <<< SudoStamp <<<'; } > "$TARGET"
doc damaged
check "a damaged block: exit 1 and FAIL on the PAM block" \
  bash -c "[ $rc = 1 ] && grep -q 'FAIL.*PAM block: damaged markers' /tmp/doctor-damaged.log"
cp /tmp/pam.doc "$TARGET"

# No record of a timeouts build: a WARN (only), with the command that builds it.
mv "$MARK" /tmp/marker.hold
doc unpatched
mv /tmp/marker.hold "$MARK"
check "an unpatched module: WARN with a fix" \
  bash -c "grep -q 'WARN.*NOT patched' /tmp/doctor-unpatched.log && grep -q 'fix: sudo .* apply' /tmp/doctor-unpatched.log"
check "the single-file installer has doctor too" bash -c "bash '$W/dist/sudostamp-setup.sh' doctor 2>&1 | grep -q '=== doctor'"

step "14. uninstall"
# A foreign key in the user's file, and a second user's file that is only SudoStamp's.
echo "$EVIL_PUB" >> "/etc/authorized_keys/$U.keys"
grep -v evil "/etc/authorized_keys/$U.keys" > /etc/authorized_keys/other.keys
# And the attestation records setup leaves beside each (pair.py --attest-out), so removal is tested.
for u in "$U" other; do echo "Key NOT hardware-attested (e2e)" > "/etc/authorized_keys/$u.attestation"; done
python3 "$W/tools/test/mock_agent.py" --port 7801 --mode-file /tmp/mode > /tmp/doc3.log 2>&1 &
sleep 1
inst_state() { cksum "$TARGET" /etc/authorized_keys/* /usr/local/sbin/sudostamp-probe "$MARK" "$MOD" 2>&1; }
i0="$(inst_state | cksum)"
echo no | bash "$I" uninstall > /tmp/uninst-no.log 2>&1; rc=$?
if [ "$rc" != 0 ] && [ "$i0" = "$(inst_state | cksum)" ]; then pass "uninstall asks first, and 'no' changes nothing"; else fail "uninstall asks first, and 'no' changes nothing"; fi
# Damaged markers: it must refuse exactly like rollback, before removing anything else.
cp "$TARGET" /tmp/pam.good
{ head -1 /tmp/pam.good; echo "$BEGIN_LINE"; tail -n +2 /tmp/pam.good | grep -vF '# >>> SudoStamp >>>' | grep -vF '# <<< SudoStamp <<<'; } > "$TARGET"
cp "$TARGET" /tmp/pam.broken
if grep -qF "SudoStamp: copied from the vendor file" /tmp/pam.good; then
  echo "  (openSUSE: our vendor copy is removed whole, whatever its markers: refusal not applicable)"
else
  bash "$I" uninstall --yes > /tmp/uninst-damaged.log 2>&1; rc=$?
  check "damaged markers: uninstall refuses and removes nothing" \
    bash -c "[ $rc != 0 ] && grep -q 'damaged SudoStamp markers' /tmp/uninst-damaged.log && [ \"\$(cksum < /tmp/pam.broken)\" = \"\$(cksum < '$TARGET')\" ] && [ -f '$MOD' ] && [ -f /usr/local/sbin/sudostamp-probe ] && [ -f '$MARK' ]"
fi
cp /tmp/pam.good "$TARGET"
calls_before="$(grep -c '^identities:' /tmp/doc3.log)"

bash "$I" uninstall --yes > /tmp/uninst.log 2>&1; rc=$?
sed 's/^/    | /' /tmp/uninst.log
check "uninstall --yes succeeds" test "$rc" = 0
check "the stack is byte for byte what it was before SudoStamp" \
  bash -c "if [ $had_target = 1 ]; then [ \"\$(cksum < '$before')\" = \"\$(cksum < '$TARGET')\" ]; else [ ! -f '$TARGET' ]; fi"
check "the helper scripts, the build record and the backups are gone" \
  bash -c "[ -z \"\$(ls -d /usr/local/sbin/sudostamp-* /var/lib/sudostamp /etc/pam.d/sudostamp-test 2>/dev/null)\" ]"
check "the module SudoStamp built is gone" bash -c "[ ! -e '$MOD' ]"
check "a user's key file that was only SudoStamp's is gone" bash -c "[ ! -e /etc/authorized_keys/other.keys ]"
check "a key file with someone else's key keeps exactly that key" \
  bash -c "[ \"\$(cat /etc/authorized_keys/$U.keys)\" = '$EVIL_PUB' ]"
check "nothing else under /etc/authorized_keys" bash -c "[ \"\$(ls /etc/authorized_keys)\" = '$U.keys' ]"
check "no attestation record is left behind" bash -c "[ -z \"\$(ls /etc/authorized_keys/*.attestation 2>/dev/null)\" ]"
check "it ended with the PAM sanity check" grep -q "only the password gets in now" /tmp/uninst.log
check "sudo with the password still works" as_user_sudo "$PW"
check "sudo without it fails: the phone is not consulted" \
  bash -c "! su $U -c \"sudo -k; sudo -S -p '' true </dev/null\" >/dev/null 2>&1"
check "and nothing connected to the phone's address" bash -c "[ \"\$(grep -c '^identities:' /tmp/doc3.log)\" = '$calls_before' ]"
pkill -f -- "--port 7801 " 2>/dev/null
rm -f "/etc/authorized_keys/$U.keys"; rmdir /etc/authorized_keys 2>/dev/null

step "14b. uninstall where nothing was installed"
i0="$( { cksum < /etc/passwd; stack_state; } | cksum)"
bash "$I" uninstall > /tmp/uninst-none.log 2>&1; rc=$?
if [ "$rc" = 0 ] && grep -q 'not installed here' /tmp/uninst-none.log && [ "$i0" = "$( { cksum < /etc/passwd; stack_state; } | cksum)" ]; then
  pass "a clean no-op: exit 0, says so, changes nothing"; else fail "a clean no-op: exit 0, says so, changes nothing"; fi
# A pam_rssh this installer did not build (a package's) is never removed.
FAKE="$(dirname "$MOD")/pam_rssh.so"
cp "$(dirname "$MOD")/pam_unix.so" "$FAKE"
bash "$I" uninstall --yes > /tmp/uninst-pkg.log 2>&1; rc=$?
check "a pam_rssh with no SudoStamp build record is left alone" bash -c "[ $rc = 0 ] && [ -f '$FAKE' ]"
rm -f "$FAKE"

# On failure, the installer's own output: a CI log shows only PASS/FAIL otherwise.
if [ "$FAIL" -gt 0 ]; then
  for f in /tmp/*.log; do printf '\n--- %s (last 15 lines)\n' "$f"; tail -15 "$f"; done
fi
printf '\n%s: %d passed, %d failed\n' "$( . /etc/os-release; echo "$ID $VERSION_ID")" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
