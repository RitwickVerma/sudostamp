#!/usr/bin/env python3
"""Ask the paired phone for a secret the person types or fills there: `sudostamp input`.

Protocol (secret-hello-v1 / secret-request-v1) and the reasons for it: docs/design/secrets.md and
app/src/main/java/com/ritwick/sudostamp/SecretProtocol.kt, which shares this file's test vectors
(tools/test/test_secret.py, SecretProtocolTest.kt).

Needs pyca `cryptography` (ECDSA, ECDH, AES-GCM): the standard library has no elliptic curves.
Only this command needs it; sudo and pairing do not.
"""
import hashlib
import hmac
import os
import re
import socket
import stat
import struct
import sys
import time

REQUEST_TAG = b"sudostamp-secret-request-v1\0"
ANSWER_TAG = b"sudostamp-secret-answer-v1\0"
INFO_TAG = b"sudostamp-secret-v1\0"
EXT_HELLO = b"secret-hello-v1@sudostamp"
EXT_REQUEST = b"secret-request-v1@sudostamp"
KIND_INPUT = b"input"
NONCE_BYTES = 32
POINT_BYTES = 65
MAX_SECRET_BYTES = 1024


def s(b):
    """An SSH string."""
    return struct.pack(">I", len(b)) + b


def framed(tag, *parts):
    return tag + b"".join(s(p) for p in parts)


def transcript(phone_key, nonce, kind, name, why, pk_r):
    """T: what this computer's host key signs; the answer is bound to it."""
    return framed(REQUEST_TAG, phone_key, nonce, kind, name, why, pk_r)


def info(t):
    return INFO_TAG + hashlib.sha256(t).digest()


def answer_message(t, enc, ct):
    """What the phone's key K signs for an answer (always longer than a 32-byte sudo challenge)."""
    return framed(ANSWER_TAG, t, enc, ct)


def phone_point(key_blob):
    """The 65-byte P-256 point inside an ecdsa-sha2-nistp256 SSH key blob, or ValueError."""
    def take(b, i):
        if i + 4 > len(b):
            raise ValueError("truncated key blob")
        n = struct.unpack(">I", b[i:i + 4])[0]
        if n > len(b) - i - 4:
            raise ValueError("truncated key blob")
        return b[i + 4:i + 4 + n], i + 4 + n
    kt, i = take(key_blob, 0)
    curve, i = take(key_blob, i)
    q, i = take(key_blob, i)
    if kt != b"ecdsa-sha2-nistp256" or curve != b"nistp256" or i != len(key_blob) \
            or len(q) != POINT_BYTES or q[0] != 4:
        raise ValueError("not an ecdsa-sha2-nistp256 key blob")
    return q


# ---------------------------------------------------------------- crypto (pyca)
# Imported here, not at the top, so `doctor` can say "pyca missing" instead of a traceback.

def _ec():
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec


def point(public_key):
    from cryptography.hazmat.primitives import serialization
    return public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def load_point(b):
    """A P-256 public key from 65 uncompressed bytes; pyca checks the point is on the curve."""
    ec = _ec()
    if len(b) != POINT_BYTES or b[0] != 4:
        raise ValueError("not an uncompressed P-256 point")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b)


def sign(private_key, msg):
    from cryptography.hazmat.primitives import hashes
    ec = _ec()
    return private_key.sign(msg, ec.ECDSA(hashes.SHA256()))


def verify(point_bytes, msg, sig_der):
    """True only for a valid DER ECDSA-P256-SHA256 signature by that point."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    ec = _ec()
    try:
        load_point(point_bytes).verify(sig_der, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


# HPKE (RFC 9180) base mode, single shot, DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM:
# the recipient's half of Hpke.kt. Composed from primitives every packaged pyca has (its own HPKE
# is 47+); tests check it against the RFC vectors and against that HPKE.
_KEM_SUITE = b"KEM" + struct.pack(">H", 0x10)
_HPKE_SUITE = b"HPKE" + struct.pack(">HHH", 0x10, 1, 1)


def _extract(salt, ikm):
    return hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()


def _expand(prk, inf, n):
    assert 1 <= n <= 32
    return hmac.new(prk, inf + b"\x01", hashlib.sha256).digest()[:n]


def _lx(suite, salt, label, ikm):
    return _extract(salt, b"HPKE-v1" + suite + label + ikm)


def _le(suite, prk, label, inf, n):
    return _expand(prk, struct.pack(">H", n) + b"HPKE-v1" + suite + label + inf, n)


def hpke_open(sk_r, enc, ct, inf, aad=b""):
    """Plaintext, or raises (InvalidTag, ValueError). sk_r: a pyca P-256 private key."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ec = _ec()
    dh = sk_r.exchange(ec.ECDH(), load_point(enc))
    shared = _le(_KEM_SUITE, _lx(_KEM_SUITE, b"", b"eae_prk", dh), b"shared_secret",
                 enc + point(sk_r.public_key()), 32)
    ctx = b"\x00" + _lx(_HPKE_SUITE, b"", b"psk_id_hash", b"") + _lx(_HPKE_SUITE, b"", b"info_hash", inf)
    secret = _lx(_HPKE_SUITE, shared, b"secret", b"")
    key = _le(_HPKE_SUITE, secret, b"key", ctx, 16)
    nonce = _le(_HPKE_SUITE, secret, b"base_nonce", ctx, 12)
    return AESGCM(key).decrypt(nonce, ct, aad)


# ---------------------------------------------------------------- the host key H
# This computer's identity for secret requests: P-256, one per user, made by `keygen` as that
# user (tools/install.sh runs it before pairing, which hands the phone its public half). Anything
# running as this user can read it and ask the phone; the phone names the computer, not the program.

def key_path():
    # ~/.config, not $XDG_CONFIG_HOME: setup makes the key under `sudo -u <user> -H`, which resets
    # the environment, so a session's XDG_CONFIG_HOME would point `input` somewhere setup never wrote.
    return os.path.join(os.path.expanduser("~"), ".config", "sudostamp", "host-key.pem")


def load_host_key(path=None):
    """The private key, or ValueError if the file is not ours to trust: not a regular file, not
    owned by this user, or readable or writable by anyone else (like ssh with an identity file)."""
    from cryptography.hazmat.primitives import serialization
    path = path or key_path()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise ValueError("%s must be a file of yours that only you can read (chmod 600)" % path)
        with os.fdopen(fd, "rb") as f:
            fd = None
            k = serialization.load_pem_private_key(f.read(), password=None)
    finally:
        if fd is not None:
            os.close(fd)
    if not isinstance(k, _ec().EllipticCurvePrivateKey) or k.curve.name != "secp256r1":
        raise ValueError("%s is not a P-256 key" % path)
    return k


def keygen(path=None):
    """Makes the host key if there is none (0600, in a 0700 directory) and returns its public
    point. An existing one is kept: pairing again must not change who this computer is."""
    from cryptography.hazmat.primitives import serialization
    path = path or key_path()
    if not os.path.lexists(path):
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        k = _ec().generate_private_key(_ec().SECP256R1())
        pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
    return point(load_host_key(path).public_key())


# ---------------------------------------------------------------- `sudostamp input`
# One connection to the phone's agent port: REQUEST_IDENTITIES (which of the pinned keys is K),
# secret-hello (K -> Np), secret-request (signed by H over T), then the sealed answer. The value
# goes to stdout only: never argv, the environment, a file or a log.

EX_OK, EX_USAGE, EX_DATAERR, EX_UNAVAILABLE, EX_TEMPFAIL, EX_NOPERM = 0, 64, 65, 69, 75, 77
NAME_RE = re.compile(r"[A-Za-z0-9._@+-]{1,64}\Z")
MAX_WHY_BYTES = 2048
MAX_FRAME = 64 * 1024
AGENTC_REQUEST_IDENTITIES, AGENT_IDENTITIES_ANSWER = 11, 12
AGENT_FAILURE, AGENT_SUCCESS, AGENTC_EXTENSION = 5, 6, 27
CONNECT_S = 4
BUDGET_S = 25          # the phone allows 30 s per connection, not counting the person's time
WAIT_S = 60 + 10       # APPROVAL_TIMEOUT_MS on the phone, plus the network


class Stop(Exception):
    def __init__(self, code, reason):
        super().__init__(reason)
        self.code, self.reason = code, reason


def _ask_module():
    """tools/ask.py, beside this file: the PAM block and the pause flag are read one way only."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("sudostamp_ask", os.path.join(os.path.dirname(os.path.abspath(__file__)), "ask.py"))
    assert spec is not None and spec.loader is not None
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def why_ok(why):
    """One line of plain text the phone will show as sent: what ask.py's printable() accepts."""
    import unicodedata
    if not why or len(why.encode("utf-8", "surrogatepass")) > MAX_WHY_BYTES:
        return False
    try:
        why.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return all(unicodedata.category(c) not in ("Cc", "Cf", "Zl", "Zp", "Cs", "Co") for c in why)


def parse_addr(a):
    """host:port or [v6]:port -> (host, port), or ValueError."""
    if a.startswith("["):
        host, _, rest = a[1:].partition("]")
        if not rest.startswith(":"):
            raise ValueError(a)
        port = rest[1:]
    else:
        host, _, port = a.rpartition(":")
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError(a)
    return host, int(port)


def pinned_keys(path):
    """The ecdsa-sha2-nistp256 key blobs in an authorized-keys file (the phone's keys for this user)."""
    import base64
    out = []
    with open(path, "rb") as f:
        for line in f.read(MAX_FRAME).splitlines():
            w = line.split()
            if len(w) >= 2 and w[0] == b"ecdsa-sha2-nistp256":
                try:
                    blob = base64.b64decode(w[1], validate=True)
                    phone_point(blob)
                except ValueError:
                    continue
                out.append(blob)
    return out


class Agent:
    """Length-prefixed ssh-agent frames over one socket, every read inside a deadline."""

    def __init__(self, sock):
        self.sock = sock
        self.deadline = time.monotonic() + BUDGET_S

    def send(self, body):
        self.sock.sendall(struct.pack(">I", len(body)) + body)

    def _read(self, n):
        b = b""
        while len(b) < n:
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise Stop(EX_TEMPFAIL, "the phone stopped answering")
            self.sock.settimeout(left)
            try:
                c = self.sock.recv(n - len(b))
            except socket.timeout:
                raise Stop(EX_TEMPFAIL, "the phone stopped answering")
            if not c:
                raise Stop(EX_TEMPFAIL, "the phone closed the connection")
            b += c
        return b

    def recv(self):
        n = struct.unpack(">I", self._read(4))[0]
        if not 0 < n <= MAX_FRAME:
            raise Stop(EX_DATAERR, "the phone sent a frame of %d bytes" % n)
        return self._read(n)


def strings(body, count):
    """Exactly [count] SSH strings filling [body], or ValueError."""
    out, i = [], 0
    for _ in range(count):
        if i + 4 > len(body):
            raise ValueError("truncated")
        n = struct.unpack(">I", body[i:i + 4])[0]
        if n > len(body) - i - 4:
            raise ValueError("truncated")
        out.append(body[i + 4:i + 4 + n])
        i += 4 + n
    if i != len(body):
        raise ValueError("trailing bytes")
    return out


def choose_key(answer, keys):
    """K: the first identity the phone offers that this computer pinned, or None."""
    if not answer or answer[0] != AGENT_IDENTITIES_ANSWER or len(answer) < 5:
        return None
    n, i = struct.unpack(">I", answer[1:5])[0], 5
    for _ in range(min(n, 64)):
        try:
            if i + 4 > len(answer):
                return None
            ln = struct.unpack(">I", answer[i:i + 4])[0]
            blob = answer[i + 4:i + 4 + ln]
            i += 4 + ln
            cl = struct.unpack(">I", answer[i:i + 4])[0]
            i += 4 + cl
        except struct.error:
            return None
        if blob in keys:
            return blob
    return None


def ask_phone(agent, keys, host_key, name, why, waiting=lambda: None):
    """The secret's bytes, or Stop. [name], [why]: bytes, already checked."""
    agent.send(bytes([AGENTC_REQUEST_IDENTITIES]))
    k = choose_key(agent.recv(), keys)
    if k is None:
        raise Stop(EX_TEMPFAIL, "the phone did not offer this computer's key: it was paired again, "
                   "or this address is another phone")
    agent.send(bytes([AGENTC_EXTENSION]) + s(EXT_HELLO) + s(k))
    r = agent.recv()
    if r[:1] != bytes([AGENT_SUCCESS]):
        raise Stop(EX_TEMPFAIL, "the phone will not be asked for a secret: SudoStamp there is older "
                   "than 2.0, this computer was paired before 2.0 (run 'sudo sudostamp setup' again), "
                   "or it is cooling down after a refusal. Nothing was shown.")
    try:
        (np,) = strings(r[1:], 1)
    except ValueError:
        raise Stop(EX_DATAERR, "the phone's hello answer is malformed")
    if len(np) != NONCE_BYTES:
        raise Stop(EX_DATAERR, "the phone's nonce is %d bytes" % len(np))

    # Our HPKE key: made for this one request, never written anywhere, dropped on return.
    sk_r = _ec().generate_private_key(_ec().SECP256R1())
    pk_r = point(sk_r.public_key())
    t = transcript(k, np, KIND_INPUT, name, why, pk_r)
    agent.send(bytes([AGENTC_EXTENSION]) + s(EXT_REQUEST) + s(KIND_INPUT) + s(name) + s(why)
               + s(pk_r) + s(sign(host_key, t)))
    waiting()
    agent.deadline = time.monotonic() + WAIT_S
    r = agent.recv()
    if r[:1] == bytes([AGENT_FAILURE]):
        raise Stop(EX_NOPERM, "refused on the phone (denied, timed out, or the request failed its checks)")
    try:
        if r[:1] != bytes([AGENT_SUCCESS]):
            raise ValueError("not SUCCESS")
        enc, ct, sig = strings(r[1:], 3)
    except ValueError:
        raise Stop(EX_DATAERR, "the phone's answer is malformed: nothing written")
    # K's signature first, then decrypt: an answer K did not sign is never opened.
    if not verify(phone_point(k), answer_message(t, enc, ct), sig):
        raise Stop(EX_DATAERR, "the answer is not signed by the phone's key for this computer: nothing written")
    try:
        value = hpke_open(sk_r, enc, ct, info(t))
    except Exception:
        raise Stop(EX_DATAERR, "the answer does not decrypt: nothing written")
    if not 0 < len(value) <= MAX_SECRET_BYTES:
        raise Stop(EX_DATAERR, "the answer is %d bytes: nothing written" % len(value))
    return value


def harden():
    """No core dump and no ptrace by other processes of this user while the value is in memory."""
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sys.platform.startswith("linux"):
        import ctypes
        PR_SET_DUMPABLE = 4
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE)")


def run_input(name, why, to_tty=False, out=1, pam=None):
    """`sudostamp input`: returns an exit code; on 0 the value has been written to [out]."""
    import pwd
    say = lambda m: sys.stderr.write("sudostamp input: %s\n" % m)
    if not NAME_RE.match(name):
        say("the name must be 1 to 64 of A-Z a-z 0-9 . _ @ + -")
        return EX_USAGE
    if not why_ok(why):
        say("--why must be one line of text, 1 to %d bytes" % MAX_WHY_BYTES)
        return EX_USAGE
    if os.isatty(out) and not to_tty:
        say("stdout is a terminal: pipe it to the program that needs it (or --to-tty, which "
            "leaves the secret in your scrollback)")
        return EX_USAGE
    try:
        harden()
        import cryptography  # noqa: F401
    except ImportError:
        say("python3-cryptography is not installed (it is needed for secrets, not for sudo)")
        return EX_UNAVAILABLE
    except OSError as e:
        say("cannot protect this process's memory: %s" % e)
        return EX_UNAVAILABLE
    try:
        host_key = load_host_key()
    except FileNotFoundError:
        say("this computer has no host key: run 'sudo sudostamp setup' to pair it for secrets")
        return EX_UNAVAILABLE
    except (OSError, ValueError) as e:
        say(str(e))
        return EX_UNAVAILABLE
    A = _ask_module()
    pam = pam or A.PAM
    try:
        with open(pam) as f:
            settings = A.block_settings(f.read())
    except OSError:
        settings = None
    uid = os.getuid()
    user = pwd.getpwuid(uid).pw_name
    if not settings or not settings[0]:
        say("sudo here does not use the phone (no SudoStamp block in %s): run 'sudo sudostamp setup'" % pam)
        return EX_UNAVAILABLE
    phone, keydir = settings
    try:
        # The file pam_rssh reads (auth_key_file=<dir>/${user}.keys) and the probe checks.
        keys = pinned_keys(os.path.join(keydir, user + ".keys"))
    except OSError:
        keys = []
    if not keys:
        say("no phone key is pinned for %s in %s: run 'sudo sudostamp setup'" % (user, keydir))
        return EX_UNAVAILABLE
    if A.paused(uid):
        say("SudoStamp is paused on this computer: resume it to ask the phone")
        return EX_TEMPFAIL
    try:
        host, port = parse_addr(phone)
        sock = socket.create_connection((host, port), timeout=CONNECT_S)
    except (OSError, ValueError) as e:
        say("cannot reach the phone at %s: %s" % (phone, e))
        return EX_TEMPFAIL
    try:
        with sock:
            value = ask_phone(Agent(sock), keys, host_key, name.encode("ascii"), why.encode("utf-8"),
                              lambda: say("waiting for your phone (60 s)..."))
    except Stop as e:
        say(e.reason)
        return e.code
    except OSError as e:
        say("the connection to the phone failed: %s" % e)
        return EX_TEMPFAIL
    view = memoryview(value)
    while view:
        view = view[os.write(out, view):]
    say("sent")
    return EX_OK


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="sudostamp", description=(__doc__ or "").split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen", help="make this user's host key if needed; print its public point (hex)")
    i = sub.add_parser("input", help="ask the phone for a secret; it is written to stdout")
    i.add_argument("name", help="what is asked for, shown on the phone (1-64 of A-Za-z0-9._@+-)")
    i.add_argument("--why", required=True, help="one line shown on the phone under the name")
    i.add_argument("--to-tty", action="store_true", help="allow a terminal as stdout")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return EX_USAGE if e.code else EX_OK
    if a.cmd == "input":
        return run_input(a.name, a.why, a.to_tty)
    if a.cmd == "keygen":
        try:
            print(keygen().hex())
        except ImportError:
            sys.stderr.write("sudostamp: python3-cryptography is not installed\n")
            return 69
        except (OSError, ValueError) as e:
            sys.stderr.write("sudostamp: %s\n" % e)
            return 77
    return 0


if __name__ == "__main__":
    sys.exit(main())
