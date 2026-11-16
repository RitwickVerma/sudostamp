"""sudostamp ask: the one way an agent (Hermes, Claude Code, a script) runs something as root.

    sudostamp ask --agent hermes --why "rebuild pam_rssh" --script fix.sh
    sudostamp ask --why "read the unit's log" -- journalctl -u sshd -n 50
    ssh edith sudostamp ask --agent hermes --why "..." --script - < fix.sh
    sudostamp ask --check                         # would an ask be answered right now?

Runs as you. It checks that the phone can be asked at all (set up, not paused, answering with
your pinned key) before asking, so an agent never waits on a prompt nobody can get; then runs
`sudo -k -- sudostamp-run <sha256> <agent> -- <why>` with the script on stdin. `-k` ignores any
cached sudo, so every run is its own approval on the phone; the hash, the agent and the reason
are in sudo's command line, which is what sudo logs, the desktop notification shows and the
phone is told (docs/AGENTS-SUDO.md). sudo runs with no controlling terminal, so a refused
approval can never turn into a password prompt that nobody is there to answer.

Exit status: the script's own when it ran; 75 not ready (not set up, paused, phone away: nothing
was asked); 77 not approved (denied, timed out or no SudoStamp: nothing ran); 64 bad usage;
70 the runner refused the script (nothing ran). --json prints one object instead of streaming.
Stdlib only: it runs on every distribution the installer supports.
"""

import argparse
import hashlib
import json
import os
import re
import shlex
import signal
import stat
import subprocess
import sys
import threading
import time

RUNNER = "/usr/local/sbin/sudostamp-run"
PROBE = "/usr/local/sbin/sudostamp-probe"
PAM = "/etc/pam.d/sudo"
BEGIN = "# >>> SudoStamp >>>"
END = "# <<< SudoStamp <<<"
MAX = 1 << 20
MARK = "sudostamp-run: approved "
WAITING = "sudostamp-run: waiting "
AGENT_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")
NOT_READY, NOT_APPROVED, USAGE, REFUSED = 75, 77, 64, 70


class Stop(Exception):
    def __init__(self, code, stage, reason):
        super().__init__(reason)
        self.code, self.stage, self.reason = code, stage, reason


def root_safe(path):
    """Root-owned and writable by nobody else, itself and its directory: what may run as root."""
    try:
        for p in (path, os.path.dirname(path)):
            st = os.stat(p)
            if st.st_uid != 0 or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return False
        return True
    except OSError:
        return False


def block_settings(text):
    """(phone, keydir) from the SudoStamp block of sudo's PAM file, or None without a block."""
    lines = text.splitlines()
    try:
        b = next(i for i, l in enumerate(lines) if l.startswith(BEGIN))
        e = next(i for i, l in enumerate(lines) if i > b and l.startswith(END))
    except StopIteration:
        return None
    phone = keys = None
    for l in lines[b + 1:e]:
        for w in l.split():
            if w.startswith("phone=") and phone is None:
                phone = w[len("phone="):]
            elif w.startswith("keys=") and keys is None:
                keys = w[len("keys="):]
            elif w.startswith("ssh_agent_addr=") and phone is None:
                phone = w[len("ssh_agent_addr="):]
    return phone, keys or "/etc/authorized_keys"


def paused(uid, now=None, f=None):
    """The pause flag, read the way the probe reads it (docs/DESKTOP.md)."""
    f = f or "/run/user/%d/sudostamp/paused" % uid
    try:
        if not stat.S_ISREG(os.stat(f).st_mode):
            return False
        with open(f, "rb") as h:
            raw = h.read(33)
    except OSError:
        return False
    if len(raw) > 32:
        return False
    c = raw.decode("ascii", "replace").strip()
    if c == "":
        return True
    if not c.isdigit() or len(c) > 12:
        return False
    return int(c) > (time.time() if now is None else now)


def ready(user, uid):
    """Raise Stop unless asking the phone now can be answered. Nothing here asks anything."""
    if not root_safe(RUNNER):
        raise Stop(NOT_READY, "ready", "%s is missing or not root-owned: run 'sudo sudostamp apply' "
                   "once to install it" % RUNNER)
    try:
        with open(PAM) as f:
            settings = block_settings(f.read())
    except OSError:
        settings = None
    if settings is None:
        raise Stop(NOT_READY, "ready", "sudo here does not ask the phone (no SudoStamp block in %s): "
                   "run 'sudo sudostamp setup'" % PAM)
    if paused(uid):
        raise Stop(NOT_READY, "ready", "SudoStamp is paused on this computer: resume it (tray, or "
                   "delete /run/user/%d/sudostamp/paused) to let the phone be asked" % uid)
    phone, keys = settings
    if phone and root_safe(PROBE):
        env = dict(os.environ, PAM_USER=user)
        r = subprocess.run([PROBE, "check", "phone=" + phone, "keys=" + keys], env=env,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=10)
        if r.returncode != 0:
            raise Stop(NOT_READY, "ready", "the phone at %s did not answer with %s's key within 4 s: "
                       "it is away, asleep, SudoStamp is closed or set to Away, or it was paired "
                       "again. Nothing was asked." % (phone, user))


def build(args):
    if args.script is not None:
        if args.command:
            raise Stop(USAGE, "usage", "give --script or a command after --, not both")
        if args.script == "-":
            body = sys.stdin.buffer.read(MAX + 1)
        else:
            with open(args.script, "rb") as f:
                body = f.read(MAX + 1)
    elif args.command:
        body = ("exec " + shlex.join(args.command) + "\n").encode()
    else:
        raise Stop(USAGE, "usage", "nothing to run: --script FILE (or - for stdin), or -- COMMAND...")
    if not body.strip():
        raise Stop(USAGE, "usage", "the script is empty")
    if len(body) > MAX:
        raise Stop(USAGE, "usage", "the script is larger than 1 MiB")
    return body


def run(argv, body, approval_s, total_s, capture, sink, out_sink=None):
    """sudo with no controlling terminal (a new session), the script on stdin. Returns
    (approved, returncode, stdout, stderr lines, timed out). stdout is the script's alone: sudo
    prints PAM messages (pam_rssh's cue) on stdout too, buffered until it exits, so only what lies
    between the runner's "output" and "end" lines is the script's; the rest goes to [sink]
    (stderr), never into what the agent reads as the result."""
    out_sink = out_sink or sys.stdout.buffer
    sha = argv[4] if len(argv) > 4 else ""
    begin = ("sudostamp-run: output %s\n" % sha).encode()
    end = ("sudostamp-run: end %s\n" % sha).encode()
    p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, start_new_session=True)
    approved = threading.Event()
    lock = threading.Lock()
    state = {"gave_up": False, "fed": False}
    err, out = [], []

    def feed():
        # Only when the runner has started (sudo approved) and only if we have not given up: a late
        # approval must find an empty stdin, so the runner refuses instead of running something
        # the agent was told did not run.
        with lock:
            if state["gave_up"] or state["fed"]:
                return
            state["fed"] = True
        try:
            p.stdin.write(body)
        except OSError:
            pass
        finally:
            try:
                p.stdin.close()
            except OSError:
                pass

    def give_up():
        with lock:
            state["gave_up"] = True
            fed = state["fed"]
        if not fed:
            try:
                p.stdin.close()
            except OSError:
                pass

    def read_err():
        for raw in iter(p.stderr.readline, b""):
            line = raw.decode("utf-8", "replace")
            if line.startswith(WAITING):
                threading.Thread(target=feed, daemon=True).start()
                continue
            if line.startswith(MARK):
                approved.set()
                continue
            err.append(line)
            if not capture:
                sink.write(line)
                sink.flush()

    def read_out():
        # Three parts: before "output" (sudo), the script, after "end" (sudo again). A marker can
        # be split across reads, so the tail that could still be the start of one is held back.
        state, buf, kept = "before", b"", [0]

        def to_sink(b):
            if b:
                sink.write(b.decode("utf-8", "replace"))
                sink.flush()

        def to_out(b):
            if not b:
                return
            if capture:
                room = 4 * MAX - kept[0]
                if room > 0:
                    out.append(b[:room])
                    kept[0] += len(out[-1])
            else:
                out_sink.write(b)
                out_sink.flush()

        while True:
            chunk = p.stdout.read1(65536) if hasattr(p.stdout, "read1") else p.stdout.read(65536)
            if not chunk:
                break
            buf += chunk
            while True:
                if state == "before":
                    i = buf.find(begin)
                    if i < 0:
                        to_sink(buf[:max(0, len(buf) - len(begin) + 1)])
                        buf = buf[max(0, len(buf) - len(begin) + 1):]
                        break
                    to_sink(buf[:i])
                    buf, state = buf[i + len(begin):], "script"
                elif state == "script":
                    i = buf.find(end)
                    if i < 0:
                        to_out(buf[:max(0, len(buf) - len(end) + 1)])
                        buf = buf[max(0, len(buf) - len(end) + 1):]
                        break
                    to_out(buf[:i])
                    buf, state = buf[i + len(end):], "after"
                else:
                    to_sink(buf)
                    buf = b""
                    break
        # The stream ended: what is held back belongs where the state says (a script killed before
        # "end" keeps its last bytes; sudo's own text never becomes output).
        (to_out if state == "script" else to_sink)(buf)

    threads = [threading.Thread(target=read_err, daemon=True), threading.Thread(target=read_out, daemon=True)]
    for t in threads:
        t.start()

    def stop():
        # sudo relays SIGTERM to what it runs; the session id reaches everything we started.
        for s in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(p.pid, s)
            except OSError:
                pass
            try:
                p.wait(5)
                return
            except subprocess.TimeoutExpired:
                continue

    start = time.monotonic()
    while p.poll() is None:
        limit = total_s if approved.is_set() else approval_s
        if time.monotonic() - start > limit:
            give_up()
            stop()
            break
        time.sleep(0.05)
    give_up()                           # sudo ended without the runner asking: nothing to send
    for t in threads:
        t.join(2)
    return approved.is_set(), p.returncode, b"".join(out), err, time.monotonic() - start > (
        total_s if approved.is_set() else approval_s)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sudostamp ask", description=__doc__.split("\n\n")[0])
    ap.add_argument("--why", help="what this is for, in a few words: shown on the phone and logged")
    ap.add_argument("--agent", default=os.environ.get("SUDOSTAMP_AGENT", "agent"),
                    help="who is asking (default $SUDOSTAMP_AGENT or 'agent'): [a-z0-9._-], 32 at most")
    ap.add_argument("--script", help="the script to run as root (bash), or - for stdin")
    ap.add_argument("--approval-timeout", type=float, default=110,
                    help="seconds to wait for the approval (default 110: the local reader's 15, the phone's 60, margins)")
    ap.add_argument("--timeout", type=float, default=900, help="seconds the whole run may take (default 900)")
    ap.add_argument("--json", action="store_true", help="print one JSON object instead of streaming")
    ap.add_argument("--check", action="store_true", help="only say whether an ask would be answered now")
    ap.add_argument("command", nargs="*", help="a command to run instead of --script (after --)")
    a = ap.parse_args(argv)

    def finish(code, stage, reason, sha="", stdout=b"", stderr=""):
        if a.json:
            print(json.dumps({"v": 1, "ok": code == 0, "stage": stage, "exit": code, "reason": reason,
                              "sha256": sha, "stdout": stdout.decode("utf-8", "replace"),
                              "stderr": stderr}))
        elif reason:
            sys.stderr.write("sudostamp ask: %s\n" % reason)
        return code

    try:
        if os.geteuid() == 0:
            raise Stop(USAGE, "usage", "run this as your own user: it asks the phone for root itself")
        uid = os.getuid()
        user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
        try:
            import pwd
            user = pwd.getpwuid(uid).pw_name
        except (ImportError, KeyError):
            pass
        if a.check:
            ready(user, uid)
            return finish(0, "ready", "ready: the phone answers with %s's key" % user)
        if not a.why or not a.why.strip() or len(a.why) > 300 or any(ord(c) < 32 or ord(c) == 127 for c in a.why):
            raise Stop(USAGE, "usage", "--why is required: one line, 300 characters at most")
        if not AGENT_RE.fullmatch(a.agent):
            raise Stop(USAGE, "usage", "--agent must match [a-z0-9][a-z0-9._-]{0,31}")
        body = build(a)
        sha = hashlib.sha256(body).hexdigest()
        ready(user, uid)
        argv = ["sudo", "-k", "--", RUNNER, sha, a.agent, "--", " ".join(a.why.split())]
        if not a.json:
            sys.stderr.write("sudostamp ask: approve on your phone: %s wants to run script %s (%s)\n"
                             % (a.agent, sha[:16], a.why.strip()))
            sys.stderr.flush()
        approved, rc, out, err, timed_out = run(argv, body, a.approval_timeout, a.timeout, a.json, sys.stderr)
        tail = "".join(err).strip().splitlines()
        if not approved:
            mine = [l for l in tail if l.startswith("sudostamp-run:")]
            if mine:
                return finish(REFUSED, "run", mine[-1], sha, out, "".join(err))
            why = "not approved in time" if timed_out else "not approved (denied, timed out or no phone)"
            return finish(NOT_APPROVED, "approval", "%s: nothing ran" % why, sha, out, "".join(err))
        if timed_out:
            return finish(124, "run", "stopped after %d s" % a.timeout, sha, out, "".join(err))
        return finish(rc, "run", "" if rc == 0 else "the script exited %d" % rc, sha, out, "".join(err))
    except Stop as s:
        return finish(s.code, s.stage, s.reason)
    except (OSError, subprocess.SubprocessError) as e:
        return finish(USAGE, "usage", str(e))


if __name__ == "__main__":
    sys.exit(main())
