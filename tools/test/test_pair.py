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


if __name__ == "__main__":
    unittest.main()
