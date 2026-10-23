#!/usr/bin/env python3
"""Pair with a SudoStamp phone, or find one on the LAN. Run by tools/install.sh.

    pair.py discover                       print "address:port<TAB>name" for each phone found
    pair.py pair --phone ADDR [--label L] [--addr-out FILE]
                                           pair; print the verified key line on stdout, and
                                           write the address to keep for the phone to FILE

Pairing is numeric comparison with a commitment (protocol version 2, written up in
app/src/main/java/com/ritwick/sudostamp/Pairing.kt). The phone makes a key for this computer and
commits to it, to its nonce, to the address we reached it at and to the address we should keep,
before it sees our random nonce; once both are revealed, phone and computer each derive a
6-digit code. The person types the code the PHONE shows; only an exact match pins the key.
Someone between the two cannot make the codes agree except by a one-in-a-million guess per
attempt, and every attempt costs the person a tap on the phone and a typed code here. And
because the phone states the address it was reached at, a relay that answered in the phone's
place -- even one passing every byte through unchanged -- is refused: its address is not the
phone's.

Prompts go to stderr and the typed code is read from stdin, so `install.sh` can capture the
key line from stdout. Python standard library only: this runs as root (with -I).
"""
import argparse
import base64
import hashlib
import hmac
import ipaddress
import os
import re
import socket
import struct
import sys
import time

AGENTC_EXTENSION = 27
AGENT_SUCCESS, AGENT_FAILURE = 6, 5
EXT_COMMIT = b"pair-commit-v2@sudostamp"
EXT_REVEAL = b"pair-reveal-v2@sudostamp"
EXT_DONE = b"pair-done-v2@sudostamp"
COMMIT_TAG = b"sudostamp-pair-commit-v2\x00"
CODE_TAG = b"sudostamp-pair-code-v2\x00"
NONCE = 32
ENDPOINT = 18                     # 16 address bytes (IPv4 as ::ffff:a.b.c.d) + 2 port bytes
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


def commitment(key, np_, dialled, stable):
    return hashlib.sha256(COMMIT_TAG + s(key) + s(np_) + s(dialled) + s(stable)).digest()


def code(key, np_, nh, dialled, stable):
    v = int.from_bytes(hashlib.sha256(CODE_TAG + s(key) + s(np_) + s(nh) + s(dialled) + s(stable)).digest()[:8], "big")
    return "%06d" % (v % 1000000)


def endpoint(sockaddr):
    """A socket address as the phone encodes it (Net.endpoint): bytes, so the IPv6 spellings
    of Java and Python never have to agree."""
    host, port = sockaddr[0], sockaddr[1]
    a = ipaddress.ip_address(host.split("%")[0])
    if a.version == 4:
        packed = b"\x00" * 10 + b"\xff\xff" + a.packed
    else:
        packed = a.packed
    return packed + struct.pack(">H", port)


def endpoint_text(ep):
    """'1.2.3.4:7777' or '[fd00::1]:7777' for an encoded endpoint."""
    a = ipaddress.IPv6Address(ep[:16])
    port = struct.unpack(">H", ep[16:])[0]
    if a.ipv4_mapped:
        return "%s:%d" % (a.ipv4_mapped, port)
    return "[%s]:%d" % (a, port)


def keepable(ep):
    """Whether an encoded endpoint may go into sudo's configuration: a LAN literal that
    pam_rssh can dial without help -- RFC 1918 IPv4, a unique-local IPv6 address, or loopback
    (tests). Not link-local: it would need an interface name, which a phone cannot know."""
    a = ipaddress.IPv6Address(ep[:16])
    if struct.unpack(">H", ep[16:])[0] == 0:
        return False
    if a.ipv4_mapped:
        v4 = a.ipv4_mapped
        return any(v4 in ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"))
    return a in ipaddress.ip_network("fc00::/7") or a == ipaddress.IPv6Address("::1")


def valid_key(blob):
    """Exactly what the app makes: one ecdsa-sha2-nistp256 key, an uncompressed point."""
    try:
        t, o = take(blob, 0)
        c, o = take(blob, o)
        q, o = take(blob, o)
    except ValueError:
        return False
    return (t, c) == (b"ecdsa-sha2-nistp256", b"nistp256") and len(q) == 65 and q[0] == 4 and o == len(blob)


def split_addr(addr):
    """'1.2.3.4:7777' or '[fd00::1]:7777' -> (host, port)."""
    host, port = addr.rsplit(":", 1)
    return host.strip("[]"), int(port)


class Agent:
    def __init__(self, addr, timeout=10):
        host, port = split_addr(addr)
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)

    def identities(self):
        """The key blobs the agent lists (REQUEST_IDENTITIES)."""
        self.sock.sendall(struct.pack(">IB", 1, 11))
        n = struct.unpack(">I", self.rx(4))[0]
        if not 5 <= n <= 65536:
            raise ConnectionError("implausible answer")
        body = self.rx(n)
        if body[0] != 12:
            raise ConnectionError("not an identities answer")
        count, o, keys = struct.unpack(">I", body[1:5])[0], 5, []
        for _ in range(min(count, 64)):
            k, o = take(body, o)
            _, o = take(body, o)
            keys.append(k)
        return keys

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
        # Where WE reached the phone, as the network shows it: what the phone must report.
        reached = endpoint(ag.sock.getpeername())
        c = ag.ext(EXT_COMMIT, s(label))
        if c is None:
            sys.exit("the phone refused to pair. On the phone: tap 'Pair a computer', then run this again.\n"
                     "(A phone app older than 1.4 cannot pair with this installer: update the app.)")
        c, _ = take(c, 0)
        nh = os.urandom(NONCE)
        r = ag.ext(EXT_REVEAL, s(nh))
        if r is None:
            sys.exit("the phone stopped the pairing. Check the phone's screen, then start again.")
        key, o = take(r, 0)
        np_, o = take(r, o)
        dialled, o = take(r, o)
        stable, o = take(r, o)
    except (OSError, ValueError, ConnectionError) as e:
        sys.exit("pairing failed: %s" % e)
    finally:
        ag.close()

    # The phone must have committed to exactly these values BEFORE it saw ours.
    if len(np_) != NONCE or len(dialled) != ENDPOINT or len(stable) != ENDPOINT or \
            not hmac.compare_digest(commitment(key, np_, dialled, stable), c):
        sys.exit("the phone's answer does not match its commitment -- NOT pinned. "
                 "Something between this computer and the phone is interfering.")
    if not valid_key(key):
        sys.exit("the phone did not send a SudoStamp key -- NOT pinned.")
    # The phone was dialled at `dialled`; we dialled `reached`. If they differ, what answered us
    # is not the phone but something passing our messages on to it -- which would end up as the
    # address sudo dials for ever.
    if dialled != reached:
        sys.exit("the phone says it was reached at %s, but this computer is talking to %s -- NOT pinned.\n"
                 "Something on this network answered in the phone's place. Pair again, typing the address "
                 "the phone shows." % (endpoint_text(dialled), endpoint_text(reached)))

    expected = code(key, np_, nh, dialled, stable)
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

    # Tells the phone to keep the key (as a new computer, until its first approval).
    try:
        ag = Agent(a.phone)
        ok = ag.ext(EXT_DONE, s(nh)) is not None
        ag.close()
    except (OSError, ConnectionError):
        ok = False
    if not ok:
        sys.exit("the phone did not confirm the pairing (it may have been cancelled on the phone) -- NOT pinned.")

    # The address to keep: the phone's stable one (it survives DHCP changes), if it is a LAN
    # address this computer can actually reach and the phone answers there with this key.
    keep = endpoint_text(dialled)
    if stable != dialled and keepable(stable):
        try:
            probe = Agent(endpoint_text(stable), timeout=3)
            if key in probe.identities():
                keep = endpoint_text(stable)
            probe.close()
        except (OSError, ValueError, ConnectionError):
            pass
    if a.addr_out:
        with open(a.addr_out, "w") as f:
            f.write(keep + "\n")
    say("  Codes match: paired.")
    print("ecdsa-sha2-nistp256 %s sudostamp" % base64.b64encode(key).decode())


# ------------------------------------------------------------------ discovery
# Finding _sudostamp._tcp on the LAN. Shaped by how Android's own mDNS responder behaves
# (AOSP MdnsRecordRepository, and a capture against a real phone):
#   - it never answers "legacy unicast" queries from an ordinary port (RFC 6762 6.7);
#   - it answers ordinary (QM) queries by multicast, but skips any record it multicast in the
#     last second -- e.g. its own announcement, or another host's query just before ours;
#   - it announces the service three times, ~0.4 s apart, the moment it starts advertising.
# So: ask avahi if it runs (it owns 5353 and caches everything); otherwise listen on 5353
# for the whole window, which catches the announcements, and repeat the query every 1.5 s,
# alternating QM and QU (unicast-reply requested), so no attempt lands inside that second.
# Nothing found here is trusted: an address only ever leads to the pairing above, which the
# person verifies with the code.

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


def stable_address(v4, v6, port):
    """Which address to keep for the phone: "host:port" ("[fd..]:7777" for IPv6).

    The same rule as Net.stableHostPort in the app: a unique-local IPv6 address whose 64-bit
    interface identifier equals the link-local address's is the phone's stable one (built from
    its Wi-Fi hardware address; Android's temporary addresses are random). It survives the
    router handing out a new IPv4 lease, which sudo's config cannot follow: pam_rssh takes a
    literal address. Otherwise the IPv4 address."""
    try:
        addrs = [ipaddress.IPv6Address(a) for a in v6]
    except ValueError:
        addrs = []
    ll = next((a for a in addrs if a.is_link_local), None)
    if ll:
        iid = ll.packed[8:]
        ula = ipaddress.ip_network("fc00::/7")
        for a in addrs:
            if a in ula and a.packed[8:] == iid:
                return "[%s]:%d" % (a, port)
    return "%s:%d" % (v4, port)


def parse(msg, ptrs, srvs, addrs, addrs6=None):
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
        elif rtype == 28 and rdlen == 16 and addrs6 is not None:   # AAAA
            addrs6.setdefault(name.lower(), set()).add(socket.inet_ntop(socket.AF_INET6, rd))
        o += rdlen


def via_avahi(timeout):
    """[(address:port, name)] from avahi-browse; [] if avahi is missing or finds nothing."""
    import shutil
    import subprocess
    exe = shutil.which("avahi-browse")
    if not exe:
        return []
    try:
        out = subprocess.run([exe, "-rtp", "-k", "_sudostamp._tcp"], capture_output=True,
                             text=True, timeout=timeout + 2).stdout
    except (subprocess.TimeoutExpired, OSError):
        return []
    v4, v6 = {}, {}
    for line in out.splitlines():
        # =;iface;proto;name;type;domain;host;address;port;txt
        f = line.split(";")
        if len(f) < 9 or f[0] != "=":
            continue
        name = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))), f[3])
        if f[2] == "IPv4":
            v4[name] = (f[7], int(f[8]))
        elif f[2] == "IPv6":
            v6.setdefault(name, set()).add(f[7].split("%")[0])
    return [(stable_address(a, v6.get(n, ()), port), n) for n, (a, port) in v4.items()]


def mdns_socket():
    """Port 5353, sharing it with avahi, browsers and the like, in the mDNS group."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    sock.bind(("", 5353))
    mreq = socket.inet_aton("224.0.0.251") + socket.inet_aton("0.0.0.0")
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    return sock


def resolved(ptrs, srvs, addrs, addrs6):
    found = []
    for inst in sorted(ptrs):
        if inst in srvs:
            host, port = srvs[inst]
            ip = addrs.get(host.lower())
            if ip:
                found.append((stable_address(ip, addrs6.get(host.lower(), ()), port),
                              inst[:-len(SERVICE)].rstrip(".").replace("\\032", " ")))
    return found


def via_mdns(timeout, on_tick=None):
    """Listen on 5353 for up to `timeout` s, querying every 1.5 s; return as soon as found."""
    try:
        sock = mdns_socket()
    except OSError:
        return []
    q = qname(SERVICE)
    queries = [struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + q + struct.pack(">HH", 12, cls)
               for cls in (1, 0x8001)]                       # QM, then QU
    ptrs, srvs, addrs, addrs6 = set(), {}, {}, {}
    end = time.time() + timeout
    next_query, n = 0.0, 0
    try:
        while time.time() < end:
            now = time.time()
            if now >= next_query:
                sock.sendto(queries[n % 2], ("224.0.0.251", 5353))
                n += 1
                next_query = now + 1.5
                if on_tick:
                    on_tick()
            sock.settimeout(max(0.05, min(next_query, end) - time.time()))
            try:
                msg, _ = sock.recvfrom(9000)
            except socket.timeout:
                continue
            try:
                parse(msg, ptrs, srvs, addrs, addrs6)
            except (ValueError, struct.error, IndexError):
                continue
            # Implausible answers are dropped HERE, so a bogus early answer cannot end the wait
            # before the real phone is heard.
            found = [f for f in resolved(ptrs, srvs, addrs, addrs6) if plausible(f[0])]
            if found:
                return found
    finally:
        sock.close()
    return []


def own_addresses():
    """This computer's own addresses, best effort (a phone cannot share one of them)."""
    out = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            out.add(info[4][0].split("%")[0])
    except OSError:
        pass
    return out


def plausible(addr):
    """Discovery answers are unauthenticated: anything on the network can send them. Pairing
    catches a wrong one, but there is no reason to dial what cannot be a phone on this LAN."""
    try:
        host, port = split_addr(addr)
        ep = endpoint((host, port))
    except (ValueError, OSError):
        return False
    a = ipaddress.ip_address(host)
    return keepable(ep) and not a.is_loopback and host not in own_addresses()


def display_name(name):
    """A discovered name is network text: printable ASCII, one line, bounded."""
    return "".join(ch for ch in name if " " <= ch <= "~")[:64] or "a phone"


def cmd_discover(a):
    found, method = via_avahi(min(a.timeout, 3)), "avahi"
    if not found:
        found, method = via_mdns(a.timeout), "mdns"
    found = [(addr, display_name(name)) for addr, name in found if plausible(addr)]
    for addr, name in dict.fromkeys(found):
        print("%s\t%s" % (addr, name))
    if found and a.verbose:
        print("found via %s" % method, file=sys.stderr)
    return 0 if found else 1


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pair")
    p.add_argument("--phone", required=True)
    p.add_argument("--label")
    p.add_argument("--addr-out")
    d = sub.add_parser("discover")
    d.add_argument("--timeout", type=float, default=3.0)
    d.add_argument("--verbose", action="store_true")
    a = ap.parse_args()
    if a.cmd == "pair":
        cmd_pair(a)
    else:
        sys.exit(cmd_discover(a))


if __name__ == "__main__":
    main()
