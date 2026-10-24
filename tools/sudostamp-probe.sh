#!/bin/sh
# SudoStamp: is the phone there, holding this user's key? Run by pam_exec right before
# pam_rssh, as /usr/local/sbin/sudostamp-probe phone=<address> keys=<key-directory>:
#
#   auth  [success=ignore ignore=ignore default=1]  pam_exec.so quiet <this> phone=<addr> keys=<dir>
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
# Read-only, no output, no state. PATH is set here because pam_exec passes the caller's.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
# A user name becomes a file name: nothing that could leave the key directory.
case "${PAM_USER:-}" in ''|.*|*/*) exit 1 ;; esac
[ $# -eq 2 ] || exit 1
case "$1" in phone=*) ;; *) exit 1 ;; esac
case "$2" in keys=/*) ;; *) exit 1 ;; esac
exec python3 -I - "${1#phone=}" "${2#keys=}/$PAM_USER.keys" <<'PY'
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
except Exception:
    pass
sys.exit(1)
PY
