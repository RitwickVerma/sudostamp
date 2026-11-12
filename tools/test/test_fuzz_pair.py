#!/usr/bin/env python3
"""Fuzz and property tests for tools/pair.py and the --phone check of tools/install.sh.

    python3 -I tools/test/test_fuzz_pair.py

Standard library only. Everything that reads bytes a neighbour on the LAN (or the phone, or an
impostor in its place) can choose is fed seeded random input and valid input damaged the way a
hostile peer would: compression-pointer loops, depth-limit chains, truncated records, count and
length lies, one-byte socket reads, bit flips in every field of an honest pairing.

Properties, per call and under a hard time limit (a hang is a failure, not a slow test):

  * read_name / parse / the Agent frame readers raise only what their callers catch
    (ValueError, struct.error, IndexError for mDNS; OSError incl. ConnectionError, ValueError
    for the agent) -- nothing else escapes, and nothing reads more than the length it validated;
  * cmd_pair never prints a key line (nothing is pinned) unless the phone's answer is exactly the
    honest one: every single-field corruption, wrong address, wrong code or refused step fails closed;
  * discovery answers that reach the screen or `install.sh` are display text: printable ASCII,
    one line, bounded, and only plausible LAN addresses;
  * need_phone, the --phone check in install.sh (run in a subshell, no root needed), accepts
    exactly "IPv4:port" and "[IPv6]:port" with a canonical port 1-65535 and nothing else.

Size: SUDOSTAMP_FUZZ_ITERATIONS (default 20000) cases per property; SUDOSTAMP_FUZZ_SEED replays.
The bash-driven property runs iterations/100 cases (min 200): each is a process.
"""
import contextlib
import importlib.util
import io
import ipaddress
import os
import random
import re
import signal
import socket
import struct
import subprocess
import sys
import time
import unittest

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("pair", os.path.join(here, "..", "pair.py"))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
INSTALL = os.path.join(here, "..", "install.sh")

ITER = int(os.environ.get("SUDOSTAMP_FUZZ_ITERATIONS") or 20000)
SEED = int(os.environ.get("SUDOSTAMP_FUZZ_SEED") or 0x5D057A)
# What pair.parse's callers (via_mdns) tolerate: anything else escaping would end discovery.
MDNS_OK = (ValueError, struct.error, IndexError)
# What cmd_pair and the stable-address probe catch.
AGENT_OK = (OSError, ValueError)          # ConnectionError is an OSError


class Hang(Exception):
    pass


@contextlib.contextmanager
def deadline(seconds=2.0):
    """A call that does not return in `seconds` fails with Hang (no infinite loop gets through)."""
    def fire(signum, frame):
        raise Hang("no result in %.1f s" % seconds)
    old = signal.signal(signal.SIGALRM, fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def rng(salt):
    return random.Random(SEED * 1000003 + salt)


def cases(name, salt, n, body):
    """Runs body(i, r) n times; a failure names the seed and iteration to replay."""
    r = rng(salt)
    t0 = time.time()
    for i in range(n):
        try:
            body(i, r)
        except Exception as e:                                    # noqa: BLE001 (report anything)
            raise AssertionError("%s: seed=%d iteration=%d of %d: %r (replay: SUDOSTAMP_FUZZ_SEED=%d)"
                                 % (name, SEED, i, n, e, SEED)) from e
    print("fuzz %s: %d cases, seed %d, %.1fs" % (name, n, SEED, time.time() - t0), file=sys.stderr)


def rbytes(r, n):
    return bytes(r.getrandbits(8) for _ in range(n))


def flip(b, r):
    if not b:
        return b
    i = r.randrange(len(b))
    return b[:i] + bytes([b[i] ^ (1 << r.randrange(8))]) + b[i + 1:]


# ------------------------------------------------------------------ mDNS messages

def header(an=0, ns=0, ar=0, qd=0):
    return struct.pack(">HHHHHH", 0, 0x8400, qd, an, ns, ar)


def rr(name, rtype, rdata, cls=1, ttl=120):
    return name + struct.pack(">HHIH", rtype, cls, ttl, len(rdata)) + rdata


def valid_response(r):
    """What a phone announces: PTR (service -> instance), SRV, A and AAAA, with the instance
    name once as a pointer."""
    inst_label = bytes(r.choice(b"Pixel 9 ab-_") for _ in range(r.randrange(1, 20)))
    inst = bytes([len(inst_label)]) + inst_label + P.qname(P.SERVICE)
    host = P.qname("phone-%d.local." % r.randrange(100))
    ptr = rr(P.qname(P.SERVICE), 12, inst)
    inst_at = 12 + len(P.qname(P.SERVICE)) + 10
    srv_name = struct.pack(">H", 0xC000 | inst_at) if r.random() < 0.5 else inst
    srv = rr(srv_name, 33, struct.pack(">HHH", 0, 0, r.choice([7777, 7781, 1, 65535])) + host)
    a = rr(host, 1, bytes([192, 168, r.randrange(256), r.randrange(1, 255)]))
    aaaa = rr(host, 28, bytes([0xFD]) + rbytes(r, 15))
    return header(an=2, ar=2) + ptr + srv + a + aaaa


LIES16 = (0, 1, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF)


def damage(r, msg):
    k = r.randrange(9)
    if k == 0:
        return msg[:r.randrange(len(msg) + 1)]                              # truncated record
    if k == 1:
        return flip(flip(msg, r), r)
    if k == 2 and len(msg) >= 12:                                           # count lies
        o = 4 + 2 * r.randrange(4)
        return msg[:o] + struct.pack(">H", r.choice(LIES16)) + msg[o + 2:]
    if k == 3 and len(msg) > 14:                                            # a length or pointer lie
        o = r.randrange(12, len(msg) - 1)
        return msg[:o] + struct.pack(">H", r.choice(LIES16) | (0xC000 if r.random() < 0.6 else 0)) + msg[o + 2:]
    if k == 4:
        return msg + rbytes(r, r.randrange(1, 40))
    if k == 5 and len(msg) > 13:                                            # self / backward pointer at a name
        o = r.randrange(12, len(msg) - 1)
        return msg[:o] + struct.pack(">H", 0xC000 | r.randrange(0, o + 2)) + msg[o + 2:]
    if k == 6:
        return rbytes(r, r.randrange(0, 120))
    if k == 7:
        return header(an=r.choice(LIES16), ns=r.choice(LIES16), ar=r.choice(LIES16), qd=r.choice(LIES16)) + msg[12:]
    return msg[:12] + rbytes(r, r.randrange(1, 60))


class Fuzz(unittest.TestCase):

    def setUp(self):
        # plausible() asks the resolver for this host's own addresses; tests must not.
        self._own = P.own_addresses
        P.own_addresses = lambda: set()

    def tearDown(self):
        P.own_addresses = self._own

    # -------------------------------------------------------------- read_name

    def test_read_name_loops_and_depth_limit(self):
        self_loop = header() + b"\xc0\x0c"
        with deadline():
            self.assertRaises(ValueError, P.read_name, self_loop, 12)
        two = header() + b"\xc0\x0e\xc0\x0c"                                # 12 -> 14 -> 12
        with deadline():
            self.assertRaises(ValueError, P.read_name, two, 12)
        # A chain of k pointers ending in a name resolves up to the depth limit and no further.
        for k in range(0, 16):
            msg = header()
            for j in range(k):
                msg += struct.pack(">H", 0xC000 | (12 + 2 * (j + 1)))
            msg += P.qname("ok.local.")
            with deadline():
                if k <= 10:
                    self.assertEqual(P.read_name(msg, 12)[0], "ok.local.", k)
                else:
                    self.assertRaises(ValueError, P.read_name, msg, 12)

    def test_read_name_random_and_mutated(self):
        def body(i, r):
            msg = rbytes(r, r.randrange(0, 80)) if r.random() < 0.5 else damage(r, valid_response(r))
            o = r.randrange(0, len(msg) + 2)
            try:
                with deadline():
                    name, end = P.read_name(msg, o)
            except (ValueError, struct.error):
                return
            self.assertTrue(name.endswith("."), name)
            self.assertTrue(o < end <= len(msg), (o, end, len(msg)))
            # Bounded amplification: at most 11 segments (the depth limit), each within the message.
            self.assertLessEqual(len(name), 12 * len(msg) + 2)
        cases("pair/read_name", 1, ITER, body)

    def test_qname_roundtrip(self):
        def body(i, r):
            labels = ["".join(r.choice("abcdefghijklmnopqrstuvwxyz0123456789-_ ") for _ in range(r.randrange(1, 30)))
                      for _ in range(r.randrange(1, 5))]
            name = ".".join(labels) + "."
            raw = P.qname(name)
            self.assertEqual(P.read_name(raw, 0), (name, len(raw)))
        cases("pair/qname", 2, ITER // 4, body)

    # -------------------------------------------------------------- parse

    def test_parse_valid_then_damaged(self):
        r0 = rng(3)
        ptrs, srvs, addrs, addrs6 = set(), {}, {}, {}
        P.parse(valid_response(r0), ptrs, srvs, addrs, addrs6)
        self.assertTrue(ptrs and srvs and addrs and addrs6, "the valid response must parse")
        self.assertTrue(P.resolved(ptrs, srvs, addrs, addrs6))

        def body(i, r):
            msg = valid_response(r)
            for _ in range(r.randrange(0, 4)):
                msg = damage(r, msg)
            ptrs, srvs, addrs, addrs6 = set(), {}, {}, {}
            try:
                with deadline():
                    P.parse(msg, ptrs, srvs, addrs, addrs6)
            except MDNS_OK:
                pass
            # Whatever was learnt, turning it into answers must not raise, and what reaches the
            # user is display text at a plausible address.
            with deadline():
                for addr, name in P.resolved(ptrs, srvs, addrs, addrs6):
                    self.assertIsInstance(P.plausible(addr), bool)
                    shown = P.display_name(name)
                    self.assertTrue(1 <= len(shown) <= 64 and all(" " <= c <= "~" for c in shown), repr(shown))
        cases("pair/parse", 4, ITER, body)

    def test_parse_random_bytes(self):
        def body(i, r):
            try:
                with deadline():
                    P.parse(rbytes(r, r.randrange(0, 200)), set(), {}, {}, {})
            except MDNS_OK:
                pass
        cases("pair/parse-noise", 5, ITER // 2, body)

    # -------------------------------------------------------------- discovery loop

    class FakeTime:
        """The discovery loop's clock, ticking 50 ms per call so a 'wait' costs no real time."""
        def __init__(self):
            self.t = 1000.0

        def time(self):
            self.t += 0.05
            return self.t

    class FakeMdnsSocket:
        def __init__(self, datagrams):
            self.q = list(datagrams)

        def sendto(self, *a):
            return 0

        def settimeout(self, t):
            pass

        def recvfrom(self, n):
            if not self.q:
                raise socket.timeout()
            return self.q.pop(0), ("192.168.1.9", 5353)

        def close(self):
            pass

    def _run_discovery(self, datagrams):
        real_time, real_sock = P.time, P.mdns_socket
        P.time = Fuzz.FakeTime()
        P.mdns_socket = lambda: Fuzz.FakeMdnsSocket(datagrams)
        try:
            with deadline(5):
                return P.via_mdns(3)
        finally:
            P.time, P.mdns_socket = real_time, real_sock

    def test_discovery_survives_hostile_datagrams_and_still_finds_the_phone(self):
        def good(r):
            ptr = rr(P.qname(P.SERVICE), 12, P.qname("Pixel." + P.SERVICE))
            srv = rr(P.qname("Pixel." + P.SERVICE), 33, struct.pack(">HHH", 0, 0, 7777) + P.qname("p.local."))
            return header(an=1, ar=2) + ptr + srv + rr(P.qname("p.local."), 1, bytes([192, 168, 1, 50]))

        def hostile_answer(r, addr_bytes):
            """A well-formed answer advertising an address no phone on this LAN can have."""
            ptr = rr(P.qname(P.SERVICE), 12, P.qname("Evil." + P.SERVICE))
            srv = rr(P.qname("Evil." + P.SERVICE), 33, struct.pack(">HHH", 0, 0, 7777) + P.qname("e.local."))
            return header(an=1, ar=2) + ptr + srv + rr(P.qname("e.local."), 1, addr_bytes)

        def body(i, r):
            # Every damaged datagram goes in: none may end discovery any more.
            noise = [damage(r, valid_response(r)) for _ in range(r.randrange(0, 6))]
            bait = [hostile_answer(r, bytes(a)) for a in ([8, 8, 8, 8], [127, 0, 0, 1], [100, 64, 0, 1], [169, 254, 1, 1], [0, 0, 0, 0])]
            stream = noise + r.sample(bait, r.randrange(0, 3))
            got = self._run_discovery(stream)
            # A damaged copy of a real announcement can still be a plausible phone; a bait address never is.
            for addr, name in got:
                self.assertTrue(P.plausible(addr), got)
                self.assertTrue(all(" " <= c <= "~" for c in P.display_name(name)))
            self.assertFalse([a for a, _ in got if a.split(":")[0] in ("8.8.8.8", "127.0.0.1", "100.64.0.1", "169.254.1.1", "0.0.0.0")], got)
            with_phone = self._run_discovery(stream + [good(r)])
            # With the junk in front, discovery still ends with plausible answers (records of damaged
            # datagrams stay in the tables and can resolve later, and the first plausible answer
            # ends the wait, so which one comes first is not fixed)...
            mixed = self._run_discovery(stream + [good(r)])
            self.assertTrue(mixed and all(P.plausible(a) for a, _ in mixed), mixed)
            # ...and bait aimed at the wait (well-formed, implausible) cannot hide the real phone.
            baited = self._run_discovery(r.sample(bait, r.randrange(0, 5)) + [good(r)])
            self.assertEqual([a for a, _ in baited], ["192.168.1.50:7777"], baited)
        cases("pair/discovery", 6, max(50, ITER // 40), body)

    def test_truncated_a_record_is_dropped_not_fatal(self):
        """One datagram on 5353 with an A record that claims 4 address bytes and ends early used to
        make socket.inet_ntoa raise OSError, which via_mdns does not catch: any host on the LAN
        could end `pair.py discover` with a traceback. parse() now checks the bytes that arrived,
        not the length the sender claimed. The phone answering after it must still be found."""
        name = P.qname("p.local.")
        bad = header(an=1) + name + struct.pack(">HHIH", 1, 1, 120, 4) + b"\x01\x02"
        ptr = rr(P.qname(P.SERVICE), 12, P.qname("Pixel." + P.SERVICE))
        srv = rr(P.qname("Pixel." + P.SERVICE), 33, struct.pack(">HHH", 0, 0, 7777) + P.qname("p.local."))
        good = header(an=1, ar=2) + ptr + srv + rr(P.qname("p.local."), 1, bytes([192, 168, 1, 50]))
        self.assertEqual([a for a, _ in self._run_discovery([bad, good])], ["192.168.1.50:7777"])

    def test_truncated_aaaa_record_is_dropped_not_fatal(self):
        """The same lie in an AAAA record (claims 16, carries 5) must not end discovery either."""
        bad = header(an=1) + P.qname("p.local.") + struct.pack(">HHIH", 28, 1, 120, 16) + b"\xfd\x00\x00\x00\x01"
        addrs6 = {}
        P.parse(bad, set(), {}, {}, addrs6)    # raises nothing
        self.assertEqual(addrs6, {})

    def test_cmd_discover_prints_only_plausible_addresses_with_display_names(self):
        def body(i, r):
            hostile_names = ["Pixel\n1) 10.0.0.66:7777", "\x1b[2J\x1b[Hroot", "a" * 5000, "\u202eevil", "\x00\x00", "\n\n", "x\ry"]
            found = [(r.choice(["192.168.1.2:7777", "8.8.8.8:7777", "[fd00::1]:7777", "127.0.0.1:7777", "junk", "1.2.3.4:65535", ":7777", "[::1", "1.2.3.4:0"]),
                      r.choice(hostile_names) + "".join(chr(r.randrange(0x20, 0x2FFF)) for _ in range(r.randrange(0, 5))))
                     for _ in range(r.randrange(0, 5))]
            real = (P.via_avahi, P.via_mdns)
            P.via_avahi, P.via_mdns = (lambda t: found), (lambda t, on_tick=None: [])
            out = io.StringIO()
            try:
                with contextlib.redirect_stdout(out), deadline():
                    P.cmd_discover(type("A", (), {"timeout": 1.0, "verbose": False})())
            except MDNS_OK:
                self.fail("cmd_discover let a malformed answer escape: %r" % (found,))
            finally:
                P.via_avahi, P.via_mdns = real
            for line in out.getvalue().splitlines():
                addr, name = line.split("\t")          # exactly two fields per line
                self.assertTrue(P.plausible(addr), line)
                self.assertTrue(all(" " <= c <= "~" for c in name) and len(name) <= 64, repr(line))
            self.assertEqual(out.getvalue().count("\n"), len(out.getvalue().splitlines()))
        cases("pair/cmd_discover", 7, max(100, ITER // 20), body)

    # -------------------------------------------------------------- the agent's frames

    class FakeSock:
        """A socket that hands out `chunk` bytes at most per recv, then EOF (or an error)."""
        def __init__(self, data, chunk, end="eof"):
            self.data, self.chunk, self.end, self.asked, self.taken, self.sent = data, chunk, end, 0, 0, b""

        def recv(self, n):
            self.asked = max(self.asked, n)
            if not self.data:
                if self.end == "reset":
                    raise ConnectionResetError()
                if self.end == "timeout":
                    raise socket.timeout()
                return b""
            out, self.data = self.data[:min(n, self.chunk)], self.data[min(n, self.chunk):]
            self.taken += len(out)
            return out

        def sendall(self, b):
            self.sent += b

        def getpeername(self):
            return ("192.168.1.50", 7777)

        def settimeout(self, t):
            pass

        def close(self):
            pass

    def agent(self, data, chunk=10 ** 9, end="eof"):
        a = P.Agent.__new__(P.Agent)
        a.sock = Fuzz.FakeSock(data, chunk, end)
        return a

    @staticmethod
    def answer(body):
        return struct.pack(">I", len(body)) + body

    def run_agent(self, op, data, chunk):
        a = self.agent(data, chunk, end=random.Random(len(data)).choice(["eof", "reset", "timeout"]))
        try:
            with deadline():
                res = op(a)
            return ("ok", res), a
        except AGENT_OK as e:
            return ("err", type(e).__name__), a

    def hostile_answer(self, r):
        k = r.randrange(7)
        if k == 0:
            return rbytes(r, r.randrange(0, 60))
        n = r.choice([0, 1, 4, 5, 6, 64, 4096, 4097, 65536, 65537, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF])
        if k == 1:
            return struct.pack(">I", n) + rbytes(r, r.randrange(0, 40))
        keys = [P_KEY, rbytes(r, r.randrange(0, 50))]
        if k == 2:                                                          # a real identities answer, lying about the count
            body = bytes([12]) + struct.pack(">I", r.choice([0, 1, 2, 3, 64, 65, 0xFFFFFFFF])) + b"".join(P.s(x) + P.s(b"c") for x in keys)
            return self.answer(body)
        if k == 3:                                                          # an answer of the wrong type
            return self.answer(bytes([r.randrange(256)]) + rbytes(r, r.randrange(0, 30)))
        if k == 4:                                                          # blobs inside the answer that lie
            body = bytes([12]) + struct.pack(">I", 1) + struct.pack(">I", r.choice([0, 3, 0xFFFFFFFF, 0x7FFFFFFF, 500])) + rbytes(r, r.randrange(0, 40))
            return self.answer(body)
        if k == 5:
            return flip(self.answer(bytes([12]) + struct.pack(">I", 1) + P.s(P_KEY) + P.s(b"comment")), r)
        return self.answer(bytes([6]) + b"".join(P.s(rbytes(r, r.randrange(0, 40))) for _ in range(r.randrange(0, 4))))

    def test_agent_frames_fail_closed_and_chunking_changes_nothing(self):
        def body(i, r):
            data = self.hostile_answer(r)
            for op, bound in ((lambda a: a.identities(), 65536), (lambda a: a.ext(b"x", b""), 4096)):
                whole, aw = self.run_agent(op, data, 10 ** 9)
                drip, ad = self.run_agent(op, data, 1)                     # one byte per recv
                self.assertEqual(whole, drip, "short reads must not change the outcome")
                self.assertLessEqual(aw.sock.asked, bound, "asked the socket for more than the cap")
                self.assertLessEqual(aw.sock.taken, 4 + bound)
                if whole[0] == "ok" and bound == 65536:                    # identities: a list of byte strings, at most 64
                    self.assertTrue(isinstance(whole[1], list) and len(whole[1]) <= 64 and all(isinstance(k, bytes) for k in whole[1]))
        cases("pair/agent-frames", 8, ITER // 2, body)

    def test_agent_valid_answers_parse(self):
        keys = [P_KEY, P_KEY[:-1] + b"\x00"]
        body = bytes([12]) + struct.pack(">I", 2) + b"".join(P.s(k) + P.s(b"sudostamp") for k in keys)
        for chunk in (1, 3, 10 ** 9):
            self.assertEqual(self.agent(self.answer(body), chunk).identities(), keys)
            self.assertEqual(self.agent(self.answer(bytes([6]) + P.s(b"abc")), chunk).ext(b"x", b""), P.s(b"abc"))
            self.assertIsNone(self.agent(self.answer(bytes([5])), chunk).ext(b"x", b""))

    def test_take_and_helpers_raise_only_valueerror(self):
        def body(i, r):
            b = rbytes(r, r.randrange(0, 60))
            if r.random() < 0.5:
                b = struct.pack(">I", r.choice([0, 1, 5, 0x7FFFFFFF, 0xFFFFFFFF, len(b)])) + b
            o = r.randrange(0, len(b) + 6)
            try:
                v, end = P.take(b, o)
                self.assertTrue(o + 4 <= end <= len(b) and len(v) == end - o - 4)
            except ValueError:
                pass
            self.assertIsInstance(P.valid_key(b), bool)
            ep = rbytes(r, 18)
            self.assertIsInstance(P.keepable(ep), bool)
            self.assertRegex(P.endpoint_text(ep), r"^(\[[0-9a-f:]+\]|[0-9.]+):[0-9]+$")
            txt = "".join(chr(r.choice([r.randrange(32, 127), r.randrange(0, 0x3000)])) for _ in range(r.randrange(0, 400)))
            shown = P.display_name(txt)
            self.assertTrue(1 <= len(shown) <= 64 and all(" " <= c <= "~" for c in shown), repr(shown))
            try:
                host, port = P.split_addr(txt)
            except ValueError:
                pass
        cases("pair/helpers", 9, ITER // 4, body)

    # -------------------------------------------------------------- cmd_pair against a phone that is not honest

    class Phone:
        """The phone as pair.py meets it: answers pair-commit, pair-reveal, pair-done. `fault`
        corrupts one thing; None is the honest phone."""
        def __init__(self, fault=None, rnd=None):
            self.fault, self.r = fault, rnd or random.Random(0)
            self.np = bytes(range(100, 132))
            self.dialled = P.endpoint(("192.168.1.50", 7777))
            if fault == "relay":                       # it committed to where IT was reached: not where we dialled
                self.dialled = P.endpoint(("192.168.1.66", 7777))
            self.stable = self.dialled
            self.nh = None
            self.stage = 0

        def commitment(self):
            return P.commitment(P_KEY, self.np, self.dialled, self.stable)

        # the Agent interface cmd_pair uses
        def __call__(self, addr, timeout=30):
            self.sock = Fuzz.FakeSock(b"", 1)
            return self

        def close(self):
            pass

        def ext(self, name, payload, limit=4096):
            f = self.fault
            if name == getattr(P, "EXT_ATTEST", None):
                return None   # a phone without attest-v1: pairing must still go through, unattested
            if name == P.EXT_COMMIT:
                if f == "refuse-commit":
                    return None
                c = self.commitment()
                if f == "bad-commitment":
                    c = flip(c, self.r)
                if f == "short-commit":
                    return P.s(c)[:-1]
                return P.s(c)
            if name == P.EXT_REVEAL:
                self.nh, _ = P.take(payload, 0)
                if f == "refuse-reveal":
                    return None
                key, np_, d, st = P_KEY, self.np, self.dialled, self.stable
                if f == "flip-key":
                    key = flip(key, self.r)
                if f == "flip-np":
                    np_ = flip(np_, self.r)
                if f == "flip-dialled":
                    d = flip(d, self.r)
                if f == "flip-stable":
                    st = flip(st, self.r)
                if f == "short-nonce":
                    np_ = np_[:-1]
                if f == "truncated-reveal":
                    return (P.s(key) + P.s(np_) + P.s(d) + P.s(st))[:-3]
                return P.s(key) + P.s(np_) + P.s(d) + P.s(st)
            if name == P.EXT_DONE:
                return None if f == "refuse-done" else b""
            raise AssertionError(name)

        def typed_code(self):
            return P.code(P_KEY, self.np, self.nh, self.dialled, self.stable)

    def pair_once(self, phone, typed=None, addr_out=None):
        real_agent, real_read = P.Agent, P.read_line
        P.Agent = phone
        P.read_line = lambda: typed if typed is not None else phone.typed_code()
        out, err = io.StringIO(), io.StringIO()
        # Every pair.py option at its default, as argparse would give it; attestation is not required.
        args = type("A", (), {"phone": "192.168.1.50:7777", "label": "host", "addr_out": addr_out,
                              "attest_out": None, "require_attestation": False, "check_revocation": False})()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), deadline(5):
                P.cmd_pair(args)
            code = None
        except SystemExit as e:
            code = e.code
        finally:
            P.Agent, P.read_line = real_agent, real_read
        return code, out.getvalue(), err.getvalue()

    def test_cmd_pair_pins_only_the_honest_phone(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "addr")
            code, out, err = self.pair_once(Fuzz.Phone(), addr_out=f)
            self.assertIsNone(code, err)
            self.assertEqual(out.count("\n"), 1)
            self.assertTrue(out.startswith("ecdsa-sha2-nistp256 "), out)
            with open(f) as fh:
                self.assertEqual(fh.read(), "192.168.1.50:7777\n")

        faults = ["refuse-commit", "bad-commitment", "short-commit", "refuse-reveal", "flip-key", "flip-np", "flip-dialled",
                  "flip-stable", "short-nonce", "relay", "truncated-reveal", "refuse-done"]
        for fault in faults:
            for n in range(8):
                code, out, err = self.pair_once(Fuzz.Phone(fault, random.Random(n)))
                self.assertEqual(out, "", "%s: a key line was printed (pinned): %r / %s" % (fault, out, err))
                self.assertIsNotNone(code, "%s: cmd_pair returned as if it succeeded" % fault)

        # A wrong, short, long or non-numeric code: nothing is pinned, and the person is told.
        for typed in ["", "000000", "12345", "1234567", "abcdef", " ", "1 2 3 4 5 6", "\x00" * 6]:
            ph = Fuzz.Phone()
            code, out, err = self.pair_once(ph, typed=typed)
            if "".join(c for c in typed if c.isdigit()) == ph.typed_code():
                continue                                                    # a spaced correct code is fine
            self.assertEqual(out, "", typed)
            self.assertEqual(code, 1, typed)

    def test_cmd_pair_random_phone_answers_never_pin(self):
        class Noise(Fuzz.Phone):
            def ext(self, name, payload, limit=4096):
                r = self.r
                k = r.randrange(5)
                if k == 0:
                    return None
                if k == 1:
                    return rbytes(r, r.randrange(0, 200))
                if k == 2:
                    return b"".join(P.s(rbytes(r, r.choice([0, 32, 18, 104, 65]))) for _ in range(r.randrange(0, 5)))
                if k == 3:
                    return P.s(P_KEY) + P.s(rbytes(r, 32)) + P.s(P.endpoint(("192.168.1.50", 7777))) * 2
                return struct.pack(">I", r.choice([0xFFFFFFFF, 0x7FFFFFFF])) + rbytes(r, 10)

        def body(i, r):
            ph = Noise(rnd=r)
            ph.nh = rbytes(r, 32)
            code, out, err = self.pair_once(ph, typed="%06d" % r.randrange(10 ** 6))
            self.assertEqual(out, "", "pinned a key on garbage: %r" % out)
            self.assertIsNotNone(code)
        cases("pair/cmd_pair-noise", 10, max(200, ITER // 20), body)

    # -------------------------------------------------------------- install.sh --phone

    def need_phone_codes(self, values):
        """need_phone's exit status for each value: the function is cut out of install.sh and run in
        a subshell (no root, no side effect), exactly as the installer calls it."""
        with open(INSTALL) as f:
            src = f.read()
        m = re.search(r"^need_phone\(\) \{\n.*?^\}\n", src, re.S | re.M)
        self.assertIsNotNone(m, "need_phone() not found in install.sh")
        # With the helpers it calls: the check itself lives in phone_valid (doctor uses it too).
        helpers = "".join(h.group(0) for h in re.finditer(r"^phone_valid\(\) \{\n.*?^\}\n", src, re.S | re.M))
        script = helpers + m.group(0) + (
            'while IFS= read -r -d "" v; do PHONE_ADDR=$v; ( need_phone ) >/dev/null 2>&1; echo "$?"; done\n')
        data = b"".join(v.encode("utf-8", "surrogateescape") + b"\0" for v in values)
        p = subprocess.run(["bash", "-c", script], input=data, capture_output=True, timeout=600,
                           env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"})
        self.assertEqual(p.returncode, 0, p.stderr)
        codes = [int(x) for x in p.stdout.split()]
        self.assertEqual(len(codes), len(values))
        return codes

    @staticmethod
    def oracle_phone(v):
        """Independent statement of what --phone may be: IPv4:port or [IPv6]:port, canonical port."""
        host, sep, port = v.rpartition(":")
        if not sep or not re.fullmatch(r"[1-9][0-9]{0,4}", port) or int(port) > 65535:
            return False
        if re.fullmatch(r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])", host):
            return True
        m = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\]", host)
        if not m:
            return False
        try:
            ipaddress.IPv6Address(m.group(1))
            return True
        except ValueError:
            return False

    def test_phone_argument_accepts_only_address_and_port(self):
        good = ["192.168.1.50:7777", "10.0.0.1:1", "255.255.255.255:65535", "[fd00::1]:7777", "[::1]:7777",
                "[FD6C:5C93:23:1F7E:445B:9BFF:FE36:628A]:7777", "[::ffff:192.168.1.2]:7777", "0.0.0.0:80"]
        bad = ["", ":", ":7777", "192.168.1.50", "192.168.1.50:", "192.168.1.50:0", "192.168.1.50:65536", "192.168.1.50:07777",
               "192.168.1.50:+7777", "192.168.1.50:-1", "192.168.1.50:7777 ", " 192.168.1.50:7777", "192.168.1.50:7777\n",
               "192.168.1.50:7777\nauth sufficient pam_permit.so", "192.168.1.50:7777;id", "192.168.1.50:77 77",
               "phone.local:7777", "localhost:7777", "[192.168.1.50]:7777", "[fd00::1]", "[fd00::1:7777", "fd00::1:7777",
               "[fd00::1%eth0]:7777", "[fe80::1%1]:7777", "256.1.1.1:7777", "01.2.3.4:7777", "1.2.3:7777", "1.2.3.4.5:7777",
               "192.168.1.50:7777:7777", "192.168.1.50:77777", "192.168.1.50:\uff17\uff17\uff17\uff17", "\u0661.2.3.4:7777",
               "$(id):7777", "`id`:7777", "1.2.3.4:7777#", "1.2.3.4:7777\\", "[::1]:7777]", "[[::1]]:7777", "*:7777", "?.?.?.?:7777"]
        values = good + bad
        codes = self.need_phone_codes(values)
        for v, c in zip(values, codes):
            self.assertEqual(c, 0 if v in good else 2, repr(v))

    def test_phone_argument_fuzz_agrees_with_the_oracle_and_never_lets_text_through(self):
        n = max(200, ITER // 100)
        r = rng(11)
        alphabet = "0123456789abcdefABCDEF.:[]  \n\t;#%/-+xzg\\\"'$`"

        def one():
            k = r.randrange(5)
            if k == 0:
                return "".join(r.choice(alphabet) for _ in range(r.randrange(0, 30)))
            if k == 1:
                return "%d.%d.%d.%d:%d" % (r.randrange(300), r.randrange(300), r.randrange(300), r.randrange(300), r.randrange(70000))
            if k == 2:
                return "[%s]:%d" % (":".join("%x" % r.randrange(0x10000) for _ in range(r.randrange(1, 9))), r.randrange(70000))
            base = r.choice(["192.168.1.50:7777", "[fd00::1]:7777", "10.1.2.3:65535"])
            i = r.randrange(len(base) + 1)
            return base[:i] + r.choice(["", "\n", " ", ";", "\x00".replace("\x00", "0"), ":", "[", "]", "%", "\t", "a", "\r"]) + base[i + r.randrange(0, 2):]
        values = [one() for _ in range(n)]
        t0 = time.time()
        codes = self.need_phone_codes(values)
        accepted = 0
        for v, c in zip(values, codes):
            self.assertIn(c, (0, 2), repr(v))
            self.assertEqual(c == 0, self.oracle_phone(v), "need_phone disagrees with the oracle on %r" % v)
            if c == 0:
                accepted += 1
                # Whatever is accepted is safe to write into a PAM line: one line, no spaces, no quoting.
                self.assertRegex(v, r"^[0-9A-Fa-f.:\[\]]+$")
        print("fuzz install.sh need_phone: %d cases (%d accepted), seed %d, %.1fs" % (n, accepted, SEED, time.time() - t0), file=sys.stderr)


# The key blob every honest pairing uses: what the app makes (ecdsa-sha2-nistp256, uncompressed point).
P_KEY = P.s(b"ecdsa-sha2-nistp256") + P.s(b"nistp256") + P.s(b"\x04" + bytes(range(1, 65)))

if __name__ == "__main__":
    unittest.main(verbosity=1)
