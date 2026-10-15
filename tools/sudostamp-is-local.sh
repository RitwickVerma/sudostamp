#!/bin/sh
# Gate for SudoStamp's PAM stack. It decides, per authentication, whether the
# local fingerprint sensor should run first (the user is at the desk) or the
# stack should skip straight to the phone (the sudo came in over SSH/Mosh).
#
# Exit 0 = local (try the sensor) ; exit 1 = remote (skip the sensor).
#
# FAILS OPEN: every error path exits 0, so a broken /proc or a missing ancestor
# can only make a remote sudo wait for the sensor's timeout -- it can never lock
# anyone out, and the password fallback in the PAM stack is untouched.
#
# It is a convenience, not a security boundary: a process detached from its SSH
# session (setsid, systemd-run --user) has no sshd ancestor and reads as local.
# SECURITY.md covers what that means for the local sensor.
#
# sshd-session: OpenSSH 9.8+ runs each connection as `sshd-session`, not `sshd`.
# The walk would still reach the `sshd` listener above it, but matching the
# session process itself does not depend on that ancestry surviving.
p=$PPID
while [ -n "$p" ] && [ "$p" -gt 1 ] 2>/dev/null; do
  comm=$(cat "/proc/$p/comm" 2>/dev/null) || exit 0
  case "$comm" in
    sshd|sshd-session|mosh-server) exit 1 ;;
  esac
  p=$(awk '/^PPid:/{print $2}' "/proc/$p/status" 2>/dev/null) || exit 0
done
exit 0
