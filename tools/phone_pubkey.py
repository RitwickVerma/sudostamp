#!/usr/bin/env python3
"""Print the phone agent's live public key as an authorized_keys line.

Fetches it the same way tools/install.sh does (REQUEST_IDENTITIES over TCP), so this is
the byte-exact key a real pam_rssh sign request will be checked against. Use it to
confirm /etc/authorized_keys/<user>.keys has not drifted from the phone:

    SUDOSTAMP_PHONE=<phone-ip>:7777 python3 tools/phone_pubkey.py | diff - /etc/authorized_keys/$USER.keys
"""
import base64
import os
import socket
import struct
import sys

# The phone, as host:port -- the same SUDOSTAMP_PHONE the installer takes.
PHONE = os.environ.get("SUDOSTAMP_PHONE", "")
if PHONE.count(":") != 1:
    sys.exit("set SUDOSTAMP_PHONE=<phone-ip>:7777")
HOST, _port = PHONE.split(":")
PORT = int(_port)


def rx(sock, n):
    b = b""
    while len(b) < n:
        c = sock.recv(n - len(b))
        if not c:
            raise SystemExit("agent closed early")
        b += c
    return b


def main():
    s = socket.create_connection((HOST, PORT), timeout=10)
    try:
        s.sendall(struct.pack(">I", 1) + bytes([11]))          # REQUEST_IDENTITIES
        (ln,) = struct.unpack(">I", rx(s, 4))
        body = rx(s, ln)
        if body[0] != 12:                                     # IDENTITIES_ANSWER
            raise SystemExit("unexpected reply type %d" % body[0])
        (n,) = struct.unpack(">I", body[1:5])
        if n != 1:
            raise SystemExit("expected exactly 1 key, got %d" % n)
        o = 5
        (klen,) = struct.unpack(">I", body[o:o + 4]); o += 4
        blob = body[o:o + klen]; o += klen
        (clen,) = struct.unpack(">I", body[o:o + 4]); o += 4
        comment = body[o:o + clen].decode()
        print("ecdsa-sha2-nistp256 %s %s" % (base64.b64encode(blob).decode(), comment))
    finally:
        s.close()


if __name__ == "__main__":
    main()
