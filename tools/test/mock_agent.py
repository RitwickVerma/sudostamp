#!/usr/bin/env python3
"""A stand-in for the phone, for automated tests ONLY.

Speaks the same two ssh-agent messages as the app (REQUEST_IDENTITIES, SIGN_REQUEST)
and signs with a throwaway SOFTWARE key. That is exactly what the phone exists to
avoid, so this never belongs anywhere near a real host:

  - it binds loopback only and refuses anything else;
  - its key is generated fresh at start and never written anywhere but --pubkey-out;
  - it approves or denies according to a mode file, so a test can flip it mid-run.

What it buys: tools/install.sh, pam_rssh and a real `sudo` can be exercised end to end
on every supported distribution, in CI, with no phone and no finger.

    mock_agent.py --port 7777 --pubkey-out key.pub --mode-file mode   # mode: approve|deny
"""
import argparse
import base64
import os
import socket
import struct
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

REQUEST_IDENTITIES, IDENTITIES_ANSWER = 11, 12
SIGN_REQUEST, SIGN_RESPONSE, FAILURE = 13, 14, 5


def s(b):
    return struct.pack(">I", len(b)) + b


def mpint(n):
    b = n.to_bytes((n.bit_length() + 8) // 8, "big")  # leading 0x00 when the top bit is set
    return s(b)


def recv_exactly(c, n):
    buf = b""
    while len(buf) < n:
        chunk = c.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=7777)
    ap.add_argument("--pubkey-out", required=True)
    ap.add_argument("--mode-file", required=True)
    a = ap.parse_args()
    if a.host not in ("127.0.0.1", "::1", "localhost"):
        sys.exit("mock_agent binds loopback only")

    key = ec.generate_private_key(ec.SECP256R1())
    point = key.public_key().public_numbers()
    q = b"\x04" + point.x.to_bytes(32, "big") + point.y.to_bytes(32, "big")
    blob = s(b"ecdsa-sha2-nistp256") + s(b"nistp256") + s(q)
    with open(a.pubkey_out, "w") as f:
        f.write("ecdsa-sha2-nistp256 %s sudostamp-mock\n" % base64.b64encode(blob).decode())

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.host, a.port))
    srv.listen(4)
    print("mock agent on %s:%d" % (a.host, a.port), flush=True)

    while True:
        c, _ = srv.accept()
        c.settimeout(30)
        try:
            while True:
                n = struct.unpack(">I", recv_exactly(c, 4))[0]
                body = recv_exactly(c, n)
                if body[0] == REQUEST_IDENTITIES:
                    out = bytes([IDENTITIES_ANSWER]) + struct.pack(">I", 1) + s(blob) + s(b"sudostamp-mock")
                elif body[0] == SIGN_REQUEST:
                    o = 1
                    kl = struct.unpack(">I", body[o:o + 4])[0]; o += 4
                    kb = body[o:o + kl]; o += kl
                    dl = struct.unpack(">I", body[o:o + 4])[0]; o += 4
                    data = body[o:o + dl]
                    mode = open(a.mode_file).read().strip() if os.path.exists(a.mode_file) else "deny"
                    # Same policy as the app: our key, a 32-byte challenge, and approval.
                    if kb != blob or len(data) != 32 or mode != "approve":
                        out = bytes([FAILURE])
                        print("sign: refused (mode=%s, %d bytes)" % (mode, len(data)), flush=True)
                    else:
                        r, sv = utils.decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
                        sig = s(b"ecdsa-sha2-nistp256") + s(mpint(r) + mpint(sv))
                        out = bytes([SIGN_RESPONSE]) + s(sig)
                        print("sign: approved", flush=True)
                else:
                    out = bytes([FAILURE])
                c.sendall(struct.pack(">I", len(out)) + out)
        except (EOFError, OSError):
            pass
        finally:
            c.close()


if __name__ == "__main__":
    main()
