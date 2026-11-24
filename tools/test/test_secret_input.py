#!/usr/bin/env python3
"""`sudostamp input` end to end against a fake phone on a real socket: the exit codes of
docs/design/secrets.md §6.5, and that nothing reaches stdout unless the phone's key signed the
answer and it decrypts. The fake phone checks what the CLI sends (H's signature over T), so the
computer side is exercised exactly as the app will see it. Needs pyca `cryptography`.

    python3 -I tools/test/test_secret_input.py
"""
import base64
import os
import pty
import socket
import struct
import sys
import tempfile
import threading
import unittest
import importlib.util

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("secret", os.path.join(here, "..", "secret.py"))
assert spec is not None and spec.loader is not None
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

BEGIN, END = "# >>> SudoStamp >>>", "# <<< SudoStamp <<<"


def blob_of(pub):
    return S.s(b"ecdsa-sha2-nistp256") + S.s(b"nistp256") + S.s(S.point(pub))


def seal(pk_r, inf, pt):
    """HPKE base-mode seal (the phone's half), on the same key schedule as hpke_open."""
    eph = ec.generate_private_key(ec.SECP256R1())
    enc = S.point(eph.public_key())
    dh = eph.exchange(ec.ECDH(), S.load_point(pk_r))
    shared = S._le(S._KEM_SUITE, S._lx(S._KEM_SUITE, b"", b"eae_prk", dh), b"shared_secret", enc + pk_r, 32)
    ctx = b"\x00" + S._lx(S._HPKE_SUITE, b"", b"psk_id_hash", b"") + S._lx(S._HPKE_SUITE, b"", b"info_hash", inf)
    secret = S._lx(S._HPKE_SUITE, shared, b"secret", b"")
    key = S._le(S._HPKE_SUITE, secret, b"key", ctx, 16)
    nonce = S._le(S._HPKE_SUITE, secret, b"base_nonce", ctx, 12)
    return enc, AESGCM(key).encrypt(nonce, pt, b"")


class FakePhone(threading.Thread):
    """One connection, the app's secret path: identities, hello -> Np, verified request -> answer."""

    def __init__(self, phone_key, host_pub, value=b"hunter2", fault=None):
        super().__init__(daemon=True)
        self.k = blob_of(phone_key.public_key())
        self.phone_key, self.host_pub, self.value, self.fault = phone_key, host_pub, value, fault
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.srv.settimeout(10)
        self.port = self.srv.getsockname()[1]
        self.connected = False
        self.request = None
        self.error = None

    def frame(self, c):
        n = struct.unpack(">I", self._read(c, 4))[0]
        return self._read(c, n)

    @staticmethod
    def _read(c, n):
        b = b""
        while len(b) < n:
            x = c.recv(n - len(b))
            if not x:
                raise EOFError
            b += x
        return b

    @staticmethod
    def send(c, body):
        c.sendall(struct.pack(">I", len(body)) + body)

    def run(self):
        try:
            c, _ = self.srv.accept()
        except OSError:
            return
        self.connected = True
        try:
            with c:
                self.serve(c)
        except Exception as e:  # recorded, checked by the test
            self.error = e

    def serve(self, c):
        assert self.frame(c) == bytes([11])
        self.send(c, bytes([12]) + struct.pack(">I", 1) + S.s(self.k) + S.s(b"sudostamp"))
        f = self.frame(c)
        name, k = S.strings(f[1:], 2)
        assert f[0] == 27 and name == S.EXT_HELLO and k == self.k, "bad hello"
        if self.fault == "refuse-hello":
            return self.send(c, bytes([5]))
        np = os.urandom(32)
        self.send(c, bytes([6]) + S.s(np))
        f = self.frame(c)
        ext, kind, nm, why, pk_r, sig_h = S.strings(f[1:], 6)
        assert f[0] == 27 and ext == S.EXT_REQUEST and kind == b"input"
        t = S.transcript(self.k, np, kind, nm, why, pk_r)
        assert S.verify(self.host_pub, t, sig_h), "the CLI's request is not signed by H over T"
        self.request = (nm, why)
        if self.fault == "deny":
            return self.send(c, bytes([5]))
        enc, ct = seal(pk_r, S.info(t), self.value)
        signer = self.phone_key
        if self.fault == "other-key":
            signer = ec.generate_private_key(ec.SECP256R1())
        sig = S.sign(signer, S.answer_message(t, enc, ct))
        if self.fault == "flip-ct":           # someone in between, after the phone signed
            ct = ct[:-1] + bytes([ct[-1] ^ 1])
        if self.fault == "trailing":
            return self.send(c, bytes([6]) + S.s(enc) + S.s(ct) + S.s(sig) + b"\0")
        self.send(c, bytes([6]) + S.s(enc) + S.s(ct) + S.s(sig))


class Input(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.old_home = os.environ.get("HOME")
        os.environ["HOME"] = d
        self.host_pub = S.keygen()
        self.phone_key = ec.generate_private_key(ec.SECP256R1())
        self.keydir = os.path.join(d, "keys")
        os.mkdir(self.keydir)
        import pwd
        user = pwd.getpwuid(os.getuid()).pw_name
        # Named as install.sh writes it: auth_key_file=<keys>/${user}.keys
        with open(os.path.join(self.keydir, user + ".keys"), "w") as f:
            f.write("ecdsa-sha2-nistp256 %s phone\n" % base64.b64encode(blob_of(self.phone_key.public_key())).decode())
        self.pam = os.path.join(d, "sudo")

    def tearDown(self):
        if self.old_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self.old_home
        self.tmp.cleanup()

    def phone(self, fault=None, value=b"hunter2"):
        phone = FakePhone(self.phone_key, self.host_pub, value, fault)
        with open(self.pam, "w") as f:
            f.write("%s\nauth x pam_exec.so quiet probe phone=127.0.0.1:%d keys=%s\n%s\n" % (BEGIN, phone.port, self.keydir, END))
        phone.start()
        return phone

    def ask(self, out, to_tty=False, stderr=None):
        """run_input with [out] as stdout (and [stderr] as fd 2) against a phone that answers."""
        phone = self.phone()
        saved = os.dup(2)
        try:
            if stderr is not None:
                os.dup2(stderr, 2)
            code = S.run_input("restic", "weekly backup", to_tty=to_tty, out=out, pam=self.pam)
        finally:
            os.dup2(saved, 2)
            os.close(saved)
        connected = phone.connected
        if not connected:
            socket.create_connection(("127.0.0.1", phone.port)).close()
        phone.join(5)
        phone.srv.close()
        return code, connected

    def run_cli(self, fault=None, value=b"hunter2", name="restic", why="weekly backup \u2713", tty=False):
        phone = self.phone(fault, value)
        if tty:
            m, out = pty.openpty()
        else:
            r, out = os.pipe()
        try:
            code = S.run_input(name, why, out=out, pam=self.pam)
        finally:
            os.close(out)
        if tty:
            os.close(m)
            got = None
        else:
            with os.fdopen(r, "rb") as f:
                got = f.read()
        if not phone.connected:
            # Never asked: wake the accept() so the thread ends now, and ignore what it says.
            socket.create_connection(("127.0.0.1", phone.port)).close()
            phone.join(5)
            phone.connected = False
            phone.error = None
        phone.join(5)
        phone.srv.close()
        if phone.error:
            raise phone.error
        return code, got, phone

    def test_the_value_reaches_stdout_and_nothing_else(self):
        code, got, phone = self.run_cli(value="pässwörd ✓".encode())
        self.assertEqual(0, code)
        self.assertEqual("pässwörd ✓".encode(), got)
        self.assertEqual((b"restic", "weekly backup \u2713".encode()), phone.request)

    def test_an_answer_the_phone_key_did_not_sign_writes_nothing(self):
        for fault in ("other-key", "flip-ct", "trailing"):
            code, got, _ = self.run_cli(fault)
            self.assertEqual((S.EX_DATAERR, b""), (code, got), fault)

    def test_refusals(self):
        self.assertEqual((S.EX_NOPERM, b""), self.run_cli("deny")[:2])
        self.assertEqual((S.EX_TEMPFAIL, b""), self.run_cli("refuse-hello")[:2])

    def test_a_terminal_as_stdout_is_refused_before_anything_is_asked(self):
        code, _, phone = self.run_cli(tty=True)
        self.assertEqual(S.EX_USAGE, code)
        self.assertFalse(phone.connected)

    # Where stdout goes is checked before the phone is asked: a fingerprint is never spent on a
    # value that would land somewhere it should not.

    def test_a_file_as_stdout_is_refused_before_anything_is_asked(self):
        # A file keeps the secret on disk, readable by others under the usual umask.
        path = os.path.join(self.tmp.name, "out")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o644)
        try:
            self.assertEqual((S.EX_USAGE, False), self.ask(fd))
        finally:
            os.close(fd)
        self.assertEqual(0, os.path.getsize(path))

    def test_a_named_fifo_as_stdout_is_refused_before_anything_is_asked(self):
        # A FIFO in the file system is a pipe anyone who can open it reads (mkfifo makes it 0644
        # under the usual umask): the secret would go to whoever opens it first.
        path = os.path.join(self.tmp.name, "fifo")
        os.mkfifo(path, 0o644)
        r = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        w = os.open(path, os.O_WRONLY)
        try:
            self.assertEqual((S.EX_USAGE, False), self.ask(w))
        finally:
            os.close(w)
            os.close(r)

    def test_a_closed_stdout_is_refused_before_anything_is_asked(self):
        # With fd 1 closed, the next socket the CLI opens becomes fd 1.
        fd = 900
        with self.assertRaises(OSError):
            os.fstat(fd)
        self.assertEqual((S.EX_USAGE, False), self.ask(fd))

    def test_stderr_into_the_same_pipe_is_refused_before_anything_is_asked(self):
        # `2>&1 |` would mix "waiting for your phone" into the value the program reads.
        r, w = os.pipe()
        try:
            self.assertEqual((S.EX_USAGE, False), self.ask(w, stderr=w))
        finally:
            os.close(w)
        with os.fdopen(r, "rb") as f:
            self.assertIn(b"stderr", f.read())

    def test_to_tty_with_stderr_on_the_same_terminal_writes_the_value(self):
        m, t = pty.openpty()
        try:
            self.assertEqual((S.EX_OK, True), self.ask(t, to_tty=True, stderr=t))
            self.assertIn(b"hunter2", os.read(m, 4096))
        finally:
            os.close(t)
            os.close(m)

    def test_a_reader_that_went_away_is_an_io_error(self):
        r, w = os.pipe()
        os.close(r)
        try:
            self.assertEqual((S.EX_IOERR, True), self.ask(w))
        finally:
            os.close(w)

    def test_usage(self):
        for name, why in (("a b", "x"), ("", "x"), ("x" * 65, "x"), ("ok", ""), ("ok", "two\nlines"),
                          ("ok", "\u202eevil"), ("ok", "x" * 2049)):
            code, got, phone = self.run_cli(name=name, why=why)
            self.assertEqual(S.EX_USAGE, code, (name, why))
            self.assertFalse(phone.connected)

    def test_a_host_key_others_can_read_is_refused(self):
        os.chmod(S.key_path(), 0o644)
        code, _, phone = self.run_cli()
        self.assertEqual(S.EX_UNAVAILABLE, code)
        self.assertFalse(phone.connected)

    def test_no_pinned_key_or_no_block_is_not_paired(self):
        import pwd
        os.remove(os.path.join(self.keydir, pwd.getpwuid(os.getuid()).pw_name + ".keys"))
        self.assertEqual(S.EX_UNAVAILABLE, self.run_cli()[0])

    def test_unreachable(self):
        with open(self.pam, "w") as f:
            f.write("%s\nauth x probe phone=127.0.0.1:1 keys=%s\n%s\n" % (BEGIN, self.keydir, END))
        r, w = os.pipe()
        try:
            self.assertEqual(S.EX_TEMPFAIL, S.run_input("restic", "x", out=w, pam=self.pam))
        finally:
            os.close(r)
            os.close(w)


class Convention(unittest.TestCase):

    def test_the_key_file_is_the_one_install_sh_pins(self):
        with open(os.path.join(here, "..", "install.sh")) as f:
            self.assertIn("auth_key_file=%s/${user}.keys", f.read())
        with open(os.path.join(here, "..", "secret.py")) as f:
            self.assertIn('os.path.join(keydir, user + ".keys")', f.read())


class Parsers(unittest.TestCase):

    def test_parse_addr(self):
        self.assertEqual(("192.0.2.2", 7777), S.parse_addr("192.0.2.2:7777"))
        self.assertEqual(("fd00::1", 7777), S.parse_addr("[fd00::1]:7777"))
        for bad in ("192.0.2.2", "[fd00::1]", ":7777", "h:0", "h:65536", "h:x"):
            with self.assertRaises(ValueError):
                S.parse_addr(bad)

    def test_choose_key_takes_only_a_pinned_key_and_never_reads_past_the_frame(self):
        k = b"K" * 10
        ans = bytes([12]) + struct.pack(">I", 2) + S.s(b"other") + S.s(b"") + S.s(k) + S.s(b"c")
        self.assertEqual(k, S.choose_key(ans, [k]))
        self.assertIsNone(S.choose_key(ans, [b"nope"]))
        # A length that runs past the end, whose truncated slice would equal a pinned key.
        lying = bytes([12]) + struct.pack(">I", 1) + struct.pack(">I", 99) + k
        self.assertIsNone(S.choose_key(lying, [k]))
        self.assertIsNone(S.choose_key(bytes([5]), [k]))

    def test_strings_is_exact(self):
        self.assertEqual([b"a", b""], S.strings(S.s(b"a") + S.s(b""), 2))
        for bad in (S.s(b"a"), S.s(b"a") + S.s(b"b") + b"\0", b"\0\0\0\5ab"):
            with self.assertRaises(ValueError):
                S.strings(bad, 2)


if __name__ == "__main__":
    unittest.main(verbosity=1)
