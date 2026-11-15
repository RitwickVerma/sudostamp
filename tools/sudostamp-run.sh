#!/bin/sh
# SudoStamp: run one script as root for an agent, exactly as it was approved. Installed as
# /usr/local/sbin/sudostamp-run and only ever started through sudo, by `sudostamp ask`:
#
#   sudo -k -- /usr/local/sbin/sudostamp-run <sha256> <agent> -- <why ...>   < script
#
# WHY ITS ARGUMENTS ARE THE DESCRIPTION: sudo's command line is what everything already shows
# and records -- sudo's own log (COMMAND=...), the probe's notification to the desktop and the
# description the probe hands the phone. Putting the script's hash, the agent and the reason
# there means each of them names this exact script without a new channel to trust.
#
# WHY THE SCRIPT COMES ON STDIN, only once this has started (it says "waiting"), checked against
# the hash: root never opens a file the agent
# could still change (a path the agent names is a race between "what was shown" and "what
# runs", and a symlink is a way to make root read something else). What runs is the bytes
# that hash to what the approval named, copied once into a root-only directory.
#
# Nothing here decides whether anything is allowed: sudo and the phone did that before this
# started. It only refuses what does not match, before running anything. Exit codes: the
# script's own; 64 bad arguments; 65 the script does not match the hash, is empty or too big.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
exec python3 -I -S -c '
import hashlib, os, re, signal, subprocess, sys, tempfile, time

MAX = 1 << 20                                   # 1 MiB: a script, not a payload
KEEP = 200                                      # audit copies kept in RUNS
RUNS = "/var/lib/sudostamp/runs"

def die(code, msg):
    sys.stderr.write("sudostamp-run: %s\n" % msg)
    sys.exit(code)

a = sys.argv[1:]
if len(a) < 4 or a[2] != "--":
    die(64, "usage: sudostamp-run <sha256> <agent> -- <why>")
sha, agent, why = a[0], a[1], " ".join(a[3:]).strip()
if not re.fullmatch(r"[0-9a-f]{64}", sha):
    die(64, "the hash must be 64 lowercase hex digits")
if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,31}", agent):
    die(64, "bad agent name")
if not why or len(why) > 300 or any(ord(c) < 32 or ord(c) == 127 for c in why):
    die(64, "bad reason")

# Ask for the script only now that sudo has let us start: sudostamp ask writes it on seeing this
# line, and not at all once it has given up waiting, so an approval that comes after the agent was
# told "nothing ran" finds an empty stdin and runs nothing.
sys.stderr.write("sudostamp-run: waiting %s\n" % sha)
sys.stderr.flush()
body = sys.stdin.buffer.read(MAX + 1)
if not body or len(body) > MAX:
    die(65, "the script is empty or larger than 1 MiB: nothing ran")
if hashlib.sha256(body).hexdigest() != sha:
    die(65, "the script does not match the approved hash: nothing ran")

# The approval is used: say so on stderr (sudostamp ask tells "approved" from "denied" by this
# line), and log it, then run.
sys.stderr.write("sudostamp-run: approved %s\n" % sha)
sys.stderr.flush()

def private_dir(path):
    # Ours (root), a real directory, not a symlink, 0700: or nothing.
    os.makedirs(path, mode=0o700, exist_ok=True)
    st = os.lstat(path)
    import stat
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0:
        die(65, "%s is not a root-owned directory: nothing ran" % path)
    os.chmod(path, 0o700)

# The audit copy: what root ran, for later. Best effort (a full disk must not stop the run, and
# sudo already logged the hash).
try:
    private_dir(RUNS)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    fd = os.open(os.path.join(RUNS, "%s-%s-%s.sh" % (stamp, agent, sha[:12])),
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(b"# agent: %s\n# why: %s\n# sha256: %s\n# by: %s\n" % (
            agent.encode(), why.encode(), sha.encode(), os.environ.get("SUDO_USER", "?").encode()))
        f.write(body)
    old = sorted(n for n in os.listdir(RUNS) if n.endswith(".sh"))
    for n in old[:-KEEP]:
        os.unlink(os.path.join(RUNS, n))
except OSError as e:
    sys.stderr.write("sudostamp-run: (no audit copy: %s)\n" % e)

work = tempfile.mkdtemp(prefix="sudostamp-run.", dir="/run" if os.path.isdir("/run") else None)
script = os.path.join(work, "script")
fd = os.open(script, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
with os.fdopen(fd, "wb") as f:
    f.write(body)

# A clean, predictable root environment: nothing of the agent but who it was, no pager that
# would wait for a key nobody presses, no terminal assumptions.
env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root",
       "LANG": "C.UTF-8", "TERM": "dumb", "PAGER": "cat", "SYSTEMD_PAGER": "cat",
       "SYSTEMD_COLORS": "0", "MANPAGER": "cat", "GIT_PAGER": "cat", "NO_COLOR": "1",
       "DEBIAN_FRONTEND": "noninteractive", "SUDOSTAMP_AGENT": agent}
for k in ("SUDO_USER", "SUDO_UID", "SUDO_GID"):
    if k in os.environ:
        env[k] = os.environ[k]
child = None
def stop(sig, _):
    if child:
        child.send_signal(sig)
for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(s, stop)
try:
    child = subprocess.Popen(["bash", "--noprofile", "--norc", script], stdin=subprocess.DEVNULL,
                             env=env, cwd="/")
    rc = child.wait()
finally:
    try:
        os.unlink(script)
        os.rmdir(work)
    except OSError:
        pass
sys.exit(rc if rc >= 0 else 128 - rc)
' "$@"
