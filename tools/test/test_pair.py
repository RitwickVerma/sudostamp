#!/usr/bin/env python3
"""Unit tests for tools/pair.py that need no network. Same addresses as NetTest.kt: the
app and the installer must choose the same address for a phone.

    python3 -I tools/test/test_pair.py
"""
import importlib.util
import os
import sys
import unittest

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("pair", os.path.join(here, "..", "pair.py"))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)

LL = "fe80::445b:9bff:fe36:628a"
STABLE = "fd6c:5c93:23:1f7e:445b:9bff:fe36:628a"       # shares the link-local interface id
TEMP_A = "fd6c:5c93:23:1f7e:71dd:8575:3a54:10d4"       # random (privacy)
TEMP_B = "fd6c:5c93:23:1f7e:ffc0:a838:3bd4:f22"


class StableAddress(unittest.TestCase):
    def test_stable_ula_is_chosen(self):
        self.assertEqual(P.stable_address("192.168.86.14", [TEMP_A, TEMP_B, LL, STABLE], 7777),
                         "[%s]:7777" % STABLE)

    def test_order_does_not_matter(self):
        self.assertEqual(P.stable_address("192.168.86.14", [STABLE, LL, TEMP_B, TEMP_A], 7777),
                         "[%s]:7777" % STABLE)

    def test_no_match_means_ipv4_never_a_temporary(self):
        for v6 in ([LL, TEMP_A, TEMP_B], [], [TEMP_A], [LL]):
            self.assertEqual(P.stable_address("192.168.86.14", v6, 7777), "192.168.86.14:7777")

    def test_global_address_is_never_offered(self):
        # The app serves only LAN peers; a global address would be refused as "internet".
        self.assertEqual(P.stable_address("192.168.86.14", [LL, "2001:db8:1:2:445b:9bff:fe36:628a"], 7777),
                         "192.168.86.14:7777")

    def test_garbage_is_ignored(self):
        self.assertEqual(P.stable_address("10.0.0.2", ["not-an-address", LL], 7777), "10.0.0.2:7777")

    def test_split_addr(self):
        self.assertEqual(P.split_addr("1.2.3.4:7777"), ("1.2.3.4", 7777))
        self.assertEqual(P.split_addr("[fd00::1]:7777"), ("fd00::1", 7777))


class ProtocolV2(unittest.TestCase):
    """The same vectors as PairingTest.kt: the phone and this computer must agree byte for byte."""
    key = bytes.fromhex("0000001365636473612d736861322d6e69737470323536000000086e6973747032353600000041"
                        "040102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                        "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40")
    np_, nh = bytes(range(32)), bytes(range(32, 64))
    d = bytes.fromhex("00000000000000000000ffffc0a801141e61")
    st = bytes.fromhex("fd6c5c9300231f7e445b9bfffe36628a1e61")

    def test_vectors(self):
        self.assertEqual(P.commitment(self.key, self.np_, self.d, self.st).hex(),
                         "c37c3aedabc70facaf31d565dcc8c9748644785dd89bec2d40c61b35cddd492c")
        self.assertEqual(P.code(self.key, self.np_, self.nh, self.d, self.st), "397004")
        self.assertEqual(P.code(self.key, self.np_, bytes(32), self.d, self.st), "303376")
        self.assertEqual(P.code(self.key, self.np_, self.nh, self.d, self.d), "238409")

    def test_endpoints(self):
        self.assertEqual(P.endpoint(("192.168.1.20", 7777)), self.d)
        self.assertEqual(P.endpoint(("::ffff:192.168.1.20", 7777)), self.d)   # dual-stack spelling
        self.assertEqual(P.endpoint((STABLE, 7777, 0, 0)), self.st)
        self.assertEqual(P.endpoint(("fe80::1%eth0", 7777, 0, 2)), P.endpoint(("fe80::1", 7777)))
        self.assertEqual(P.endpoint_text(self.d), "192.168.1.20:7777")
        self.assertEqual(P.endpoint_text(self.st), "[%s]:7777" % STABLE)

    def test_only_lan_literals_are_kept(self):
        ok = [("192.168.1.2", 7777), ("10.1.2.3", 7777), ("172.16.0.1", 7777), (STABLE, 7777), ("127.0.0.1", 7781), ("::1", 7791)]
        bad = [("8.8.8.8", 7777), ("100.64.0.1", 7777), ("169.254.1.1", 7777), (LL, 7777),
               ("2001:db8::1", 7777), ("192.168.1.2", 0)]
        for a in ok:
            self.assertTrue(P.keepable(P.endpoint(a)), a)
        for a in bad:
            self.assertFalse(P.keepable(P.endpoint(a)), a)

    def test_discovery_answers_are_display_text(self):
        self.assertEqual(P.display_name("Pixel\n1) 10.0.0.66:7777\x1b[2J"), "Pixel1) 10.0.0.66:7777[2J")
        self.assertFalse(P.plausible("127.0.0.1:7777"))
        self.assertFalse(P.plausible("8.8.8.8:7777"))
        self.assertTrue(P.plausible("192.168.1.250:7777"))


if __name__ == "__main__":
    unittest.main()
