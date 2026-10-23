#!/usr/bin/env python3
"""A stand-in for the phone, for automated tests ONLY.

Speaks the same ssh-agent messages as the app (REQUEST_IDENTITIES, SIGN_REQUEST, and the
pairing extensions of protocol 2) and signs with throwaway SOFTWARE keys. That is exactly what
the phone exists to avoid, so this never belongs anywhere near a real host:

  - it binds loopback only and refuses anything else;
  - its keys are generated fresh at start (and one more per pairing, as the app does) and
    never written anywhere but --pubkey-out;
  - it behaves according to a mode file, so a test can flip it mid-run:
        approve   sign every request for one of its keys
        deny      refuse to sign
        stall     accept connections and never answer (a device squatting on the address)
        foreign   list only a key nobody pinned

What it buys: tools/install.sh, pam_rssh and a real `sudo` can be exercised end to end on every
supported distribution, in CI, with no phone and no finger.

    mock_agent.py --port 7777 --pubkey-out key.pub --mode-file mode
    mock_agent.py --port 7784 --relay-to 127.0.0.1:7783      # pass every byte through
"""
import argparse
import base64
import os
import socket
import struct
import sys
import threading
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

REQUEST_IDENTITIES, IDENTITIES_ANSWER = 11, 12
SIGN_REQUEST, SIGN_RESPONSE, FAILURE, SUCCESS = 13, 14, 5, 6


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


def new_key():
    key = ec.generate_private_key(ec.SECP256R1())
    point = key.public_key().public_numbers()
    q = b"\x04" + point.x.to_bytes(32, "big") + point.y.to_bytes(32, "big")
    return key, s(b"ecdsa-sha2-nistp256") + s(b"nistp256") + s(q)


def line(blob, comment="sudostamp-mock"):
    return "ecdsa-sha2-nistp256 %s %s\n" % (base64.b64encode(blob).decode(), comment)


def relay(listen, target):
    """A transparent relay: every byte passed through unchanged, both ways. What answering
    discovery in the phone's place, without tampering with anything, looks like."""
    def pipe(a, b):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except OSError:
            pass
        finally:
            for x in (a, b):
                try:
                    x.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
    host, port = target.rsplit(":", 1)
    while True:
        c, _ = listen.accept()
        u = socket.create_connection((host.strip("[]"), int(port)))
        threading.Thread(target=pipe, args=(c, u), daemon=True).start()
        threading.Thread(target=pipe, args=(u, c), daemon=True).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=7777)
    ap.add_argument("--pubkey-out")
    ap.add_argument("--mode-file")
    # The key comment to send. Tests use a hostile one (with a newline and a second key) to
    # prove the installer never writes the phone's comment into the pinned-keys file.
    ap.add_argument("--comment", default="sudostamp-mock")
    # Pairing, as the app does it (one exchange; see Pairing.kt). The code the phone would
    # SHOW is written to --code-file, standing in for the person reading the screen; the key
    # made for the computer replaces --pubkey-out.
    ap.add_argument("--code-file")
    # The address the computer should keep (the app's stable address); default: the one dialled.
    ap.add_argument("--stable")
    # Man in the middle: present OUR key to whoever pairs with us, while pairing with the real
    # phone at this address (with a nonce of our choosing), so the real phone shows a code.
    ap.add_argument("--mitm-to")
    # A relay that passes everything through to this address, changing nothing.
    ap.add_argument("--relay-to")
    a = ap.parse_args()
    if a.host not in ("127.0.0.1", "::1", "localhost"):
        sys.exit("mock_agent binds loopback only")

    srv = socket.socket(socket.AF_INET6 if ":" in a.host else socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.host, a.port))
    srv.listen(4)
    if a.relay_to:
        print("relay on %s:%d -> %s" % (a.host, a.port, a.relay_to), flush=True)
        relay(srv, a.relay_to)
        return

    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    import pair as P                                        # the same derivation as the host

    first, first_blob = new_key()
    keys = {first_blob: first}                              # blob -> private key
    foreign_blob = new_key()[1]
    if a.pubkey_out:
        with open(a.pubkey_out, "w") as f:
            f.write(line(first_blob))
    print("mock agent on %s:%d" % (a.host, a.port), flush=True)

    def mode():
        if a.mode_file and os.path.exists(a.mode_file):
            return open(a.mode_file).read().strip()
        return "deny"

    session = {}

    def ext(body, conn):
        name, o = P.take(body, 1)
        if name == P.EXT_COMMIT:
            if session:                                     # one exchange per arming
                session["dead"] = True
                return bytes([FAILURE])
            session["key"], session["blob"] = new_key()     # a key for this computer alone
            session["np"] = os.urandom(32)
            session["d"] = P.endpoint(conn.getsockname())
            session["st"] = P.endpoint(P.split_addr(a.stable)) if a.stable else session["d"]
            if a.mitm_to:                                   # pair with the real phone now
                ag = P.Agent(a.mitm_to)
                c = ag.ext(P.EXT_COMMIT, P.s(b"mitm"))
                r = ag.ext(P.EXT_REVEAL, P.s(os.urandom(32))) if c else None
                ag.close()
                print("mitm: real phone %s" % ("paired with us" if r else "refused"), flush=True)
            return bytes([SUCCESS]) + P.s(P.commitment(session["blob"], session["np"], session["d"], session["st"]))
        if name == P.EXT_REVEAL:
            if not session or session.get("dead") or "nh" in session:
                return bytes([FAILURE])
            nh, _ = P.take(body, o)
            session["nh"] = nh
            if a.code_file:
                with open(a.code_file, "w") as f:
                    f.write(P.code(session["blob"], session["np"], nh, session["d"], session["st"]) + "\n")
            return bytes([SUCCESS]) + P.s(session["blob"]) + P.s(session["np"]) + P.s(session["d"]) + P.s(session["st"])
        if name == P.EXT_DONE:
            nh, _ = P.take(body, o)
            if session.get("dead") or session.get("nh") != nh:
                return bytes([FAILURE])
            keys[session["blob"]] = session["key"]
            if a.pubkey_out:
                with open(a.pubkey_out, "w") as f:
                    f.write(line(session["blob"]))
            print("pairing: done", flush=True)
            return bytes([SUCCESS])
        return bytes([FAILURE])

    while True:
        c, _ = srv.accept()
        if mode() == "stall":
            # Accept, never answer: the connection is simply left hanging.
            print("stall: holding a connection", flush=True)
            threading.Thread(target=lambda x: (time.sleep(600), x.close()), args=(c,), daemon=True).start()
            continue
        c.settimeout(30)
        try:
            while True:
                n = struct.unpack(">I", recv_exactly(c, 4))[0]
                body = recv_exactly(c, n)
                if body[0] == REQUEST_IDENTITIES:
                    listed = [foreign_blob] if mode() == "foreign" else list(keys)
                    out = bytes([IDENTITIES_ANSWER]) + struct.pack(">I", len(listed)) + \
                        b"".join(s(k) + s(a.comment.encode()) for k in listed)
                    print("identities: %d" % len(listed), flush=True)
                elif body[0] == SIGN_REQUEST:
                    o = 1
                    kl = struct.unpack(">I", body[o:o + 4])[0]; o += 4
                    kb = body[o:o + kl]; o += kl
                    dl = struct.unpack(">I", body[o:o + 4])[0]; o += 4
                    data = body[o:o + dl]
                    m = mode()
                    # Same policy as the app: one of our keys, a 32-byte challenge, and approval.
                    if kb not in keys or len(data) != 32 or m != "approve":
                        out = bytes([FAILURE])
                        print("sign: refused (mode=%s, %d bytes)" % (m, len(data)), flush=True)
                    else:
                        r, sv = utils.decode_dss_signature(keys[kb].sign(data, ec.ECDSA(hashes.SHA256())))
                        sig = s(b"ecdsa-sha2-nistp256") + s(mpint(r) + mpint(sv))
                        out = bytes([SIGN_RESPONSE]) + s(sig)
                        print("sign: approved", flush=True)
                elif body[0] == 27:
                    out = ext(body, c)
                else:
                    out = bytes([FAILURE])
                c.sendall(struct.pack(">I", len(out)) + out)
        except (EOFError, OSError):
            pass
        finally:
            c.close()


if __name__ == "__main__":
    main()
