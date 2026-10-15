#!/usr/bin/env python3
"""Pair with a SudoStamp phone, or find one on the LAN. Run by tools/install.sh.

    pair.py discover                       print "address:port<TAB>name" for each phone found
    pair.py pair --phone ADDR [--label L]  pair; print the phone's verified key line on stdout

Pairing is numeric comparison with a commitment (the protocol is written up in
app/src/main/java/com/ritwick/sudostamp/Pairing.kt). The phone commits to its key before it
sees our random nonce; once both are revealed, phone and computer each derive a 6-digit code.
The person types the code the PHONE shows; only an exact match pins the key. Someone between
the two cannot make the codes agree except by a one-in-a-million guess per attempt, and every
attempt costs the person a tap on the phone and a typed code here.

Prompts go to stderr and the typed code is read from stdin, so `install.sh` can capture the
key line from stdout. Python standard library only: this runs as root (with -I).
"""
import argparse
import base64
import hashlib
import hmac
import os
import socket
import struct
import sys
import time

AGENTC_EXTENSION = 27
AGENT_SUCCESS, AGENT_FAILURE = 6, 5
EXT_COMMIT = b"pair-commit@sudostamp"
EXT_REVEAL = b"pair-reveal@sudostamp"
EXT_DONE = b"pair-done@sudostamp"
COMMIT_TAG = b"sudostamp-pair-commit-v1\x00"
CODE_TAG = b"sudostamp-pair-code-v1\x00"
NONCE = 32
SERVICE = "_sudostamp._tcp.local."


def say(msg=""):
    print(msg, file=sys.stderr, flush=True)


def s(b):
    return struct.pack(">I", len(b)) + b


def take(buf, o):
    if o + 4 > len(buf):
        raise ValueError("truncated")
    n = struct.unpack(">I", buf[o:o + 4])[0]
    if o + 4 + n > len(buf):
        raise ValueError("truncated")
    return buf[o + 4:o + 4 + n], o + 4 + n


def commitment(key, np_):
    return hashlib.sha256(COMMIT_TAG + key + np_).digest()


def code(key, np_, nh):
    v = int.from_bytes(hashlib.sha256(CODE_TAG + key + np_ + nh).digest()[:8], "big")
    return "%06d" % (v % 1000000)


def valid_key(blob):
    """Exactly what the app makes: one ecdsa-sha2-nistp256 key, an uncompressed point."""
    try:
        t, o = take(blob, 0)
        c, o = take(blob, o)
        q, o = take(blob, o)
    except ValueError:
        return False
    return (t, c) == (b"ecdsa-sha2-nistp256", b"nistp256") and len(q) == 65 and q[0] == 4 and o == len(blob)


class Agent:
    def __init__(self, addr):
        host, port = addr.rsplit(":", 1)
        self.sock = socket.create_connection((host, int(port)), timeout=10)
        self.sock.settimeout(10)

    def rx(self, n):
        b = b""
        while len(b) < n:
            c = self.sock.recv(n - len(b))
            if not c:
                raise ConnectionError("the phone closed the connection")
            b += c
        return b

    def ext(self, name, payload):
        msg = bytes([AGENTC_EXTENSION]) + s(name) + payload
        self.sock.sendall(struct.pack(">I", len(msg)) + msg)
        n = struct.unpack(">I", self.rx(4))[0]
        if not 1 <= n <= 4096:
            raise ConnectionError("implausible answer from the phone")
        body = self.rx(n)
        if body[0] != AGENT_SUCCESS:
            return None
        return body[1:]

    def close(self):
        self.sock.close()


def read_line():
    """One line from fd 0, byte by byte. sys.stdin would buffer ahead and swallow the answers
    install.sh reads next (e.g. a scripted "yes"), so read only up to the newline."""
    out = b""
    while True:
        c = os.read(0, 1)
        if not c or c == b"\n":
            return out.decode("ascii", "replace")
        out += c


def cmd_pair(a):
    label = (a.label or socket.gethostname()).encode("ascii", "replace")[:64]
    try:
        ag = Agent(a.phone)
    except OSError as e:
        sys.exit("cannot reach the phone at %s: %s" % (a.phone, e))
    try:
        c = ag.ext(EXT_COMMIT, s(label))
        if c is None:
            sys.exit("the phone refused to pair. On the phone: tap 'Pair a computer', then run this again.")
        c, _ = take(c, 0)
        nh = os.urandom(NONCE)
        r = ag.ext(EXT_REVEAL, s(nh))
        if r is None:
            sys.exit("the phone stopped the pairing. Check the phone's screen, then start again.")
        key, o = take(r, 0)
        np_, o = take(r, o)
    except (OSError, ValueError, ConnectionError) as e:
        sys.exit("pairing failed: %s" % e)
    finally:
        ag.close()

    # The phone must have committed to exactly this key and nonce BEFORE it saw ours.
    if len(np_) != NONCE or not hmac.compare_digest(commitment(key, np_), c):
        sys.exit("the phone's answer does not match its commitment -- NOT pinned. "
                 "Something between this computer and the phone is interfering.")
    if not valid_key(key):
        sys.exit("the phone did not send a SudoStamp key -- NOT pinned.")

    expected = code(key, np_, nh)
    say("")
    say("  Your phone now shows a 6-digit code.")
    say("  Type it here. (Check the phone says '%s'.)" % label.decode("ascii", "replace"))
    say("")
    sys.stderr.write("  Code on the phone: ")
    sys.stderr.flush()
    typed = "".join(ch for ch in read_line() if ch.isdigit())
    # One attempt. A wrong code is not a typo to retry quietly: it can mean the codes really
    # differ, i.e. this computer is not talking to your phone.
    if len(typed) != 6 or not hmac.compare_digest(typed.encode(), expected.encode()):
        say("")
        say("  That is not the code this computer expected. NOTHING was pinned.")
        say("  If you typed it correctly, this computer may not be talking to your phone directly.")
        say("  Start again from the phone ('Pair a computer').")
        sys.exit(1)

    # Display-only acknowledgement for the phone; failure here changes nothing.
    try:
        ag = Agent(a.phone)
        ag.ext(EXT_DONE, s(nh))
        ag.close()
    except (OSError, ConnectionError):
        pass
    say("  Codes match: paired.")
    print("ecdsa-sha2-nistp256 %s sudostamp" % base64.b64encode(key).decode())


# ------------------------------------------------------------------ discovery
# A minimal mDNS browser: one PTR question for _sudostamp._tcp.local, asked from an ordinary
# UDP port, which makes responders answer straight back to us by unicast (RFC 6762 section
# 6.7, "legacy unicast"). Nothing found here is trusted: an address only ever leads to the
# pairing above, which the person verifies with the code.

def qname(name):
    out = b""
    for part in name.rstrip(".").split("."):
        out += bytes([len(part)]) + part.encode()
    return out + b"\x00"


def read_name(msg, o, depth=0):
    labels = []
    while True:
        if o >= len(msg) or depth > 10:
            raise ValueError("bad name")
        n = msg[o]
        if n == 0:
            return ".".join(labels) + ".", o + 1
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", msg[o:o + 2])[0] & 0x3FFF
            rest, _ = read_name(msg, ptr, depth + 1)
            return ".".join(labels + [rest.rstrip(".")]) + ".", o + 2
        labels.append(msg[o + 1:o + 1 + n].decode("utf-8", "replace"))
        o += 1 + n


def parse(msg, ptrs, srvs, addrs):
    qd, an, ns, ar = struct.unpack(">HHHH", msg[4:12])
    o = 12
    for _ in range(qd):
        _, o = read_name(msg, o)
        o += 4
    for _ in range(an + ns + ar):
        name, o = read_name(msg, o)
        rtype, _, _, rdlen = struct.unpack(">HHIH", msg[o:o + 10])
        o += 10
        rd = msg[o:o + rdlen]
        if rtype == 12:                                   # PTR
            target, _ = read_name(msg, o)
            if name.lower() == SERVICE:
                ptrs.add(target)
        elif rtype == 33 and rdlen >= 7:                  # SRV
            port = struct.unpack(">H", rd[4:6])[0]
            host, _ = read_name(msg, o + 6)
            srvs[name] = (host, port)
        elif rtype == 1 and rdlen == 4:                   # A
            addrs.setdefault(name.lower(), socket.inet_ntoa(rd))
        o += rdlen


def cmd_discover(a):
    query = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + qname(SERVICE) + struct.pack(">HH", 12, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    sock.bind(("", 0))
    ptrs, srvs, addrs = set(), {}, {}
    end = time.time() + a.timeout
    for _ in range(2):
        sock.sendto(query, ("224.0.0.251", 5353))
        time.sleep(0.05)
    while time.time() < end:
        sock.settimeout(max(0.05, end - time.time()))
        try:
            msg, src = sock.recvfrom(9000)
        except socket.timeout:
            break
        try:
            parse(msg, ptrs, srvs, addrs)
        except (ValueError, struct.error, IndexError):
            continue
    found = []
    for inst in sorted(ptrs):
        if inst not in srvs:
            continue
        host, port = srvs[inst]
        ip = addrs.get(host.lower())
        if ip:
            name = inst[:-len(SERVICE)].rstrip(".").replace("\\032", " ")
            found.append("%s:%d\t%s" % (ip, port, name))
    for line in dict.fromkeys(found):
        print(line)
    return 0 if found else 1


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pair")
    p.add_argument("--phone", required=True)
    p.add_argument("--label")
    d = sub.add_parser("discover")
    d.add_argument("--timeout", type=float, default=3.0)
    a = ap.parse_args()
    if a.cmd == "pair":
        cmd_pair(a)
    else:
        sys.exit(cmd_discover(a))


if __name__ == "__main__":
    main()
