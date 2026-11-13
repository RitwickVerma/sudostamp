#!/bin/sh
# SudoStamp: is the phone there, holding this user's key? Run by pam_exec right before
# pam_rssh, as /usr/local/sbin/sudostamp-probe phone=<address> keys=<key-directory>:
#
#   auth  [success=ignore ignore=ignore default=1]  pam_exec.so quiet <this> phone=<addr> keys=<dir>
#   auth  sufficient                                pam_rssh.so ...
#   auth  [success=ignore ignore=ignore default=ignore]  pam_exec.so quiet <this> after phone=<addr> keys=<dir>
#
# key=value, not bare values: Linux-PAM reads an argument that STARTS with "[" as bracket-
# quoted, so a bare "[fd00::1]:7777" would arrive mangled (pam_rssh's ssh_agent_addr=[...] is
# safe for the same reason).
#
# Exit 0 only if the agent at <addr> answers REQUEST_IDENTITIES within a few seconds and lists
# a key pinned in <dir>/$PAM_USER.keys. Anything else skips pam_rssh, and sudo goes straight
# to the password.
#
# WHY: pam_rssh sets no timeout on its socket. Whatever holds the pinned address -- another
# device after a DHCP change, or something on the network that accepts the connection and
# never answers -- would hold sudo for as long as it liked, and the password prompt would
# never come. This check bounds that at a few seconds. (It is not a defence against something
# that answers here and then stalls pam_rssh; that needs a timeout in pam_rssh itself.)
#
# THREE MODES, one file (so the bundle and the packages carry one helper, not two):
#   (none)  before pam_rssh: the pause flag, the phone check, then a notification
#   after   the line after pam_rssh: runs only when the phone did not authenticate (denied,
#           timed out, gone, or skipped above). Sends `not-approved` and ALWAYS exits 0
#   check   the phone check alone, for `install.sh doctor` (no flag, no notification)
#
# DESKTOP NOTIFICATIONS (docs/DESKTOP.md). Everything beyond the phone check is a courtesy to
# the person at the desk and can only ever make this probe SKIP the phone (the pause flag):
# nothing here makes anything authenticate, and nothing here changes the exit code or the 4 s
# budget of the phone check. The one place root could be tricked is /run/user/<uid>/sudostamp/,
# which belongs to the user, who can put a symlink there. So every access to it (the flag, the
# socket, /proc/<sudo>/cmdline) is made as the user: under sudo we already are the user (pam_exec
# runs us with the caller's real uid), and from a root caller the access is made after dropping
# to the user with setpriv (real, effective and saved ids, and the groups), so a symlink reaches
# only what the user could reach anyway. No way to be the user: no events and no pause, never "do
# it as root instead". 100 ms budget for the event, every failure ignored.
#
# Read-only, no state. PATH is set here because pam_exec passes the caller's.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
MODE=before
case "${1:-}" in after|check) MODE="$1"; shift ;; esac
# A user name becomes a file name: nothing that could leave the key directory.
case "${PAM_USER:-}" in ''|.*|*/*) exit 1 ;; esac
[ $# -eq 2 ] || exit 1
case "$1" in phone=*) ;; *) exit 1 ;; esac
case "$2" in keys=/*) ;; *) exit 1 ;; esac
PHONE="${1#phone=}"
KEYFILE="${2#keys=}/$PAM_USER.keys"

# ----------------------------------------------------------- who runs the helpers, as whom
# pam_exec runs us with the caller's REAL uid unless told `seteuid`, and sudo's real uid is the
# user's: under sudo this script is already the person it is about, with no privilege at all
# (found by looking: `id` in a probe under sudo). Then the helpers run as we are. From a root
# caller (pam_check.py, `su`, polkit, pam_exec seteuid) they run after dropping to the user with
# setpriv, so that root never follows anything the user planted. Any other uid, or no setpriv:
# no helpers at all (skip, never "do it as root instead").
CAN_EMIT=0
DROP=0
EV_UID=""
EV_GID=""
if [ "$MODE" != check ]; then
  EV_UID="$(id -u -- "$PAM_USER" 2>/dev/null)"
  case "$EV_UID" in ''|0|*[!0-9]*) ;; *)
    case "$PPID" in ''|*[!0-9]*) ;; *)
      ME="$(id -u 2>/dev/null)"
      if [ "$ME" = "$EV_UID" ]; then
        CAN_EMIT=1
      elif [ "$ME" = 0 ] && command -v setpriv >/dev/null 2>&1; then
        EV_GID="$(id -g -- "$PAM_USER" 2>/dev/null)"
        case "$EV_GID" in ''|*[!0-9]*) ;; *) CAN_EMIT=1; DROP=1 ;; esac
      fi ;;
    esac ;;
  esac
fi

# as_user CMD...: run CMD as the user, within 0.5 s (the helpers keep to 100 ms themselves; this
# is for a hang before they start). No input, no output.
as_user() {
  if [ "$DROP" = 1 ]; then
    set -- setpriv --reuid="$EV_UID" --regid="$EV_GID" --init-groups -- "$@"
  fi
  if command -v timeout >/dev/null 2>&1; then
    timeout -s KILL 0.5 "$@" </dev/null >/dev/null 2>&1
  else
    "$@" </dev/null >/dev/null 2>&1
  fi
}

# ------------------------------------------------- the pause flag (read AS THE USER)
# Exit 0 = paused: the file is empty (or only white space) = until resumed, or holds a decimal
# unix time in the future = until then. Missing, not a regular file (a FIFO would hold sudo),
# unreadable, too long, malformed or in the past = not paused. A symlink is followed, as the
# user: it reaches what the user can read and nothing more.
PAUSE_SH='f="/run/user/$1/sudostamp/paused"
[ -f "$f" ] && [ -r "$f" ] || exit 1
raw="$(head -c 33 "$f" 2>/dev/null)" || exit 1
[ "${#raw}" -le 32 ] || exit 1
c="$(printf "%s" "$raw" | tr -d " \t\r\n")"
case "$c" in
  "") exit 0 ;;
  *[!0-9]*) exit 1 ;;
esac
[ "${#c}" -le 12 ] && [ "$c" -gt "$(date +%s)" ]'

# ---------------------------------------------- the event (sent AS THE USER, 100 ms in all)
# argv: uid sudo-pid event reason phone tty. Every failure exits 0: no socket, a socket of the
# wrong kind, one nobody reads. The alarm is the 100 ms budget; the send itself waits 30 ms at most.
EVENT_PY=$(cat <<'PY'
import _socket, os, signal, sys, time

# _socket and a hand-built JSON string, not socket and json: their imports are most of the start-up.
uid, pid, event, reason, phone, tty = sys.argv[1:7]
signal.signal(signal.SIGALRM, lambda *_: os._exit(0))
signal.setitimer(signal.ITIMER_REAL, 0.07)


def clean(text, limit):
    return "".join("?" if ord(c) < 32 or 0x7f <= ord(c) < 0xa0 else c for c in text)[:limit]


def q(text):                                         # control characters are gone already
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def send():
    try:
        with open("/proc/%s/cmdline" % pid, "rb") as f:
            argv = f.read(65536)
    except OSError:
        argv = b""                                   # hidepid: the notification says "sudo"
    command = clean(argv.rstrip(b"\0").replace(b"\0", b" ").decode("utf-8", "replace"), 512)
    head = '{"v":1,"event":%s,"sudo_pid":%d,"tty":%s,"command":' % (q(event), int(pid), q(clean(tty, 64)))
    tail = ',%s"phone":%s,"ts":%d}' % ('"reason":%s,' % q(reason) if event == "skipped" else "",
                                       q(clean(phone, 64)), int(time.time()))
    while True:
        body = (head + q(command) + tail).encode("utf-8", "replace")
        if len(body) <= 2048 or not command:
            break
        command = command[:max(0, len(command) - 64)]  # multi-byte or quoted text
    s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_DGRAM)
    s.settimeout(0.03)                               # a socket whose buffer is full would block
    s.sendto(body, "/run/user/%s/sudostamp/events.sock" % uid)


try:
    send()
except Exception:
    pass
os._exit(0)
PY
)

# emit EVENT [REASON]
emit() {
  [ "$CAN_EMIT" = 1 ] || return 0
  as_user python3 -I -S -c "$EVENT_PY" "$EV_UID" "$PPID" "$1" "${2:-}" "$PHONE" "${PAM_TTY:-}"
}

# ----------------------------------------------------------- the phone check (as root)
# Exit 0: the phone offers a pinned key. 2: it answers but offers none (the caller turns that
# into 1; it only picks the notification's reason). Anything else: 1.
phone_check() {
python3 -I - "$PHONE" "$KEYFILE" <<'PY'
import base64, socket, struct, sys, time

BUDGET = 4.0                                     # seconds, all of it: connect and answer
end = time.monotonic() + BUDGET
try:
    pinned = set()
    with open(sys.argv[2]) as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 2:
                pinned.add(base64.b64decode(parts[1]))
    host, port = sys.argv[1].rsplit(":", 1)
    s = socket.create_connection((host.strip("[]"), int(port)), timeout=BUDGET)
    s.sendall(struct.pack(">IB", 1, 11))         # REQUEST_IDENTITIES

    def rx(n):
        b = b""
        while len(b) < n:
            left = end - time.monotonic()
            if left <= 0:
                raise TimeoutError
            s.settimeout(left)
            c = s.recv(n - len(b))
            if not c:
                raise EOFError
            b += c
        return b

    n = struct.unpack(">I", rx(4))[0]
    if not 5 <= n <= 65536:
        sys.exit(1)
    body = rx(n)
    if body[0] != 12:
        sys.exit(1)
    count, o = struct.unpack(">I", body[1:5])[0], 5
    for _ in range(min(count, 64)):
        for field in (0, 1):                     # key blob, then comment
            l = struct.unpack(">I", body[o:o + 4])[0]
            if field == 0 and body[o + 4:o + 4 + l] in pinned:
                sys.exit(0)
            o += 4 + l
    sys.exit(2)
except Exception:
    pass
sys.exit(1)
PY
}

case "$MODE" in
  after)
    # Reached only when the phone path did not authenticate. Says so; never matters.
    emit not-approved
    exit 0 ;;
  check)
    phone_check; rc=$?
    [ "$rc" = 2 ] && rc=1
    exit "$rc" ;;
esac

# The pause flag first: paused means the phone is not even dialled, so it sees nothing.
if [ "$CAN_EMIT" = 1 ] && as_user sh -c "$PAUSE_SH" sh "$EV_UID"; then
  emit skipped paused
  exit 1
fi

phone_check; rc=$?
case "$rc" in
  0) emit asking ;;
  2) emit skipped wrong-key; rc=1 ;;
  *) emit skipped away ;;
esac
exit "$rc"
