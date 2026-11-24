#!/usr/bin/env python3
"""The probe's phone check (tools/sudostamp-probe.sh, phone_check) reads the pinned-key file the
way pam_rssh does: comment and blank lines are skipped, not fatal. A check that died on a comment
skipped the phone for every sudo, silently (exit 1 = "phone not there").

Runs the probe's own Python, cut from the script, against a fake phone on a real socket.
    python3 -I -B tools/test/test_probe_keys.py
"""
import base64
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PROBE = os.path.join(HERE, "..", "sudostamp-probe.sh")
BLOB = b"\x00\x00\x00\x13ecdsa-sha2-nistp256" + b"\x00" * 8 + b"\x04" + b"k" * 64


def phone_check_source():
    text = open(PROBE).read()
    m = re.search(r"^phone_check\(\) \{\npython3 -I - .*?<<'PY'\n(.*?)^PY$", text, re.S | re.M)
    assert m, "phone_check's Python not found in the probe"
    return m.group(1)


class FakePhone(threading.Thread):
    """Answers one REQUEST_IDENTITIES with [blob]."""

    def __init__(self, blob):
        super().__init__(daemon=True)
        self.blob = blob
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.srv.settimeout(5)
        self.port = self.srv.getsockname()[1]

    def run(self):
        try:
            c, _ = self.srv.accept()
        except OSError:
            return
        with c:
            c.recv(5)
            comment = b"phone"
            body = bytes([12]) + struct.pack(">I", 1) + struct.pack(">I", len(self.blob)) + self.blob \
                + struct.pack(">I", len(comment)) + comment
            c.sendall(struct.pack(">I", len(body)) + body)
        self.srv.close()


class ProbeKeyFile(unittest.TestCase):
    def check(self, keyfile_text):
        phone = FakePhone(BLOB)
        phone.start()
        with tempfile.TemporaryDirectory() as d:
            keys = os.path.join(d, "user.keys")
            with open(keys, "w") as f:
                f.write(keyfile_text)
            r = subprocess.run([sys.executable, "-I", "-", "127.0.0.1:%d" % phone.port, keys, ""],
                               input=phone_check_source().encode(), capture_output=True, timeout=10)
        phone.join(5)
        return r.returncode

    def line(self):
        return "ecdsa-sha2-nistp256 %s phone\n" % base64.b64encode(BLOB).decode()

    def test_the_pinned_key_is_found(self):
        self.assertEqual(0, self.check(self.line()))

    def test_a_comment_line_before_the_key_does_not_hide_it(self):
        self.assertEqual(0, self.check("# SudoStamp: pinned by setup, see sudostamp doctor\n\n" + self.line()))

    def test_a_damaged_line_before_the_key_does_not_hide_it(self):
        self.assertEqual(0, self.check("ecdsa-sha2-nistp256 not*base64 x\n" + self.line()))

    def test_a_commented_out_key_is_not_pinned(self):
        # pam_rssh would not accept it, so the probe must not send sudo to the phone for it.
        self.assertEqual(2, self.check("#" + self.line()))

    def test_a_phone_offering_another_key_is_not_the_phone(self):
        # Control: the check can say no (2), so the green cases above mean something.
        other = BLOB[:-1] + b"j"
        self.assertEqual(2, self.check("ecdsa-sha2-nistp256 %s x\n" % base64.b64encode(other).decode()))


if __name__ == "__main__":
    unittest.main()
