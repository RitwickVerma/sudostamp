#!/usr/bin/env python3
"""Tests for tools/attest.py (hardware key attestation) and its use in tools/pair.py.

    python3 -I tools/test/test_attest.py

The chains in tools/test/attest/ are REAL: produced by the secure hardware of real phones and
published by Google (see the README there). The verified-but-software, second-extension and
other-key cases need a chain no honest phone makes, so those use a throwaway root from
attest_fixture.py, which the check trusts only because the test says so. Needs the system
`openssl`, like the code under test (a missing one fails the tests rather than skipping them).
"""
import base64
import glob
import hashlib
import importlib.util
import os
import re
import struct
import sys
import unittest

here = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path.insert(0, here)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, os.path.join(here, "..", path))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


A = load("attest", "attest.py")
P = load("pair", "pair.py")
import attest_fixture as F                                      # noqa: E402
from cryptography.hazmat.primitives import serialization       # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec        # noqa: E402


def S(b):
    return struct.pack(">I", len(b)) + b


def ssh_blob(point):
    return S(b"ecdsa-sha2-nistp256") + S(b"nistp256") + S(point)


def pem_chain(path):
    t = open(path).read()
    return [base64.b64decode("".join(m.split())) for m in
            re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", t, re.S)]


# The challenge each real chain's phone was given: attestationChallenge from Google's metadata
# for the same chain (base64 of the bytes), as published next to it.
CHALLENGES = {
    "akita-tee-root2019": "Y2hhbGxlbmdl",
    "blueline-tee-root2016": "Y2hhbGxlbmdl",
    "caiman-strongbox-rkp": "N2NjYWMxZWEtNDg0NS00ODJlLTg1OGQtZjZmYTlhYThjMjk1",
    "tegu-strongbox-ec-root2026": "OTA1NzhlMWQtZjViZi00Y2NmLWEyN2YtYTRmNGQ4OWVlMjFm",
    "walleye-tee-ca-false": "OTEyODk1ZTAtM2UxOS00MzI3LWEwZmItOTFlMmYzZjQ2Y2Ri",
}


class Real:
    """One real chain, the challenge its phone was given, and the SSH blob of its leaf key."""

    def __init__(self, name, level):
        self.name, self.level = name, level
        self.chain = pem_chain(os.path.join(here, "attest", name + ".chain"))
        self.challenge = base64.b64decode(CHALLENGES[name])
        self.blob = ssh_blob(A.Cert(self.chain[0]).ec_point())


REAL = [Real("tegu-strongbox-ec-root2026", "StrongBox"), Real("caiman-strongbox-rkp", "StrongBox"),
        Real("akita-tee-root2019", "TEE"), Real("blueline-tee-root2016", "TEE"),
        Real("walleye-tee-ca-false", "TEE")]


def flip(der, at):
    b = bytearray(der)
    b[at] ^= 0x01
    return bytes(b)


class Asn1(unittest.TestCase):
    def test_lengths_and_oids(self):
        short = bytes([0x30, 0x03, 0x02, 0x01, 0x05])
        t = A.tlv(short, 0)
        self.assertEqual((t[0], t[2], t[3]), (0x30, 2, 5))
        longform = bytes([0x04, 0x81, 0x80]) + b"x" * 128
        self.assertEqual(A.tlv(longform, 0)[3] - A.tlv(longform, 0)[2], 128)
        self.assertEqual(A.oid(bytes.fromhex("06092a864886f70d01010b"), (0x06, 0, 2, 11)), "1.2.840.113549.1.1.11")
        self.assertEqual(A.oid(bytes.fromhex("060a2b06010401d679020111"), (0x06, 0, 2, 12)), A.KEY_DESCRIPTION_OID)

    def test_lies_and_garbage_raise(self):
        for bad in (b"", b"\x30", b"\x30\x05\x02\x01", b"\x30\x84\xff\xff\xff\xff", b"\x04\x80", b"\x1f\x01\x00"):
            with self.assertRaises(A.Asn1Error, msg=bad.hex()):
                A.tlv(bad, 0)
        with self.assertRaises(A.Asn1Error):
            A.Cert(b"\x30\x00")
        with self.assertRaises(A.Asn1Error):
            A.Cert(REAL[0].chain[0] + b"\x00")           # trailing bytes after the certificate

    def test_a_real_certificate_is_read(self):
        c = A.Cert(REAL[0].chain[0])
        self.assertEqual(len(c.ec_point()), 65)
        self.assertEqual(c.ec_point()[0], 4)
        self.assertIn(A.KEY_DESCRIPTION_OID, c.exts)
        self.assertEqual(A.Cert(REAL[0].chain[-1]).self_signed(), True)
        self.assertEqual(A.Cert(REAL[0].chain[0]).self_signed(), False)

    def test_key_description_of_a_real_chain(self):
        r = REAL[0]
        kd = A.key_description(A.Cert(r.chain[0]).exts[A.KEY_DESCRIPTION_OID][0])
        self.assertEqual((kd["attestation_level"], kd["keymaster_level"], kd["version"]), (2, 2, 300))
        self.assertEqual(kd["challenge"], r.challenge)
        self.assertEqual(kd["challenge"], b"90578e1d-f5bf-4ccf-a27f-a4f4d89ee21f")
        kd = A.key_description(A.Cert(REAL[2].chain[0]).exts[A.KEY_DESCRIPTION_OID][0])
        self.assertEqual((kd["attestation_level"], kd["keymaster_level"], kd["challenge"]), (1, 1, b"challenge"))

    def test_a_malformed_key_description_raises(self):
        for bad in (b"", b"\x30\x00", b"\x04\x01\x00", F.der(0x30, F.integer(1))):
            with self.assertRaises(A.Asn1Error):
                A.key_description(bad)


class Roots(unittest.TestCase):
    def test_pins(self):
        # Google's two current roots, fingerprints as Google publishes them.
        self.assertIn("cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc", A.ROOTS)
        self.assertIn("6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0", A.ROOTS)
        self.assertEqual(len(A.ROOTS), 5)
        for pin, (name, der) in A.ROOTS.items():
            self.assertEqual(hashlib.sha256(der).hexdigest(), pin, name)
            c = A.Cert(der)
            self.assertTrue(c.self_signed(), name)

    def test_a_corrupted_root_is_refused_at_load(self):
        saved = A._ROOTS_SRC
        try:
            n, pin, b64 = saved[0]
            A._ROOTS_SRC = [(n, pin, b64.replace("MIIF", "MIIG", 1))] + saved[1:]
            with self.assertRaises(ImportError):
                A._load_roots()
        finally:
            A._ROOTS_SRC = saved


class RealChains(unittest.TestCase):
    def test_every_real_hardware_chain_is_attested(self):
        for r in REAL:
            with self.subTest(r.name):
                res = A.check(r.chain, r.challenge, r.blob)
                self.assertEqual((res.verdict, res.level), ("attested", r.level), res)
                self.assertEqual(res.line(), "Key attested: " + r.level)

    def test_wrong_challenge_is_refused(self):
        for r in REAL:
            with self.subTest(r.name):
                res = A.check(r.chain, A.hashlib.sha256(b"another pairing").digest(), r.blob)
                self.assertEqual(res.verdict, "refused")
                self.assertIn("wrong challenge", res.reason)
                self.assertTrue(res.line().startswith("Key NOT hardware-attested ("))

    def test_a_different_key_is_refused(self):
        r = REAL[0]
        other = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        res = A.check(r.chain, r.challenge, ssh_blob(other))
        self.assertEqual(res.verdict, "refused")
        self.assertIn("not the key", res.reason)

    def test_a_tampered_signature_fails_verification(self):
        r = REAL[0]
        for i in range(len(r.chain) - 1):                 # every link below the root
            with self.subTest(link=i):
                bad = list(r.chain)
                bad[i] = flip(bad[i], len(bad[i]) - 5)   # inside the signature value
                res = A.check(bad, r.challenge, r.blob)
                self.assertEqual(res.verdict, "unverified")
                self.assertIn("signatures do not verify", res.reason)

    def test_tampered_contents_fail_verification(self):
        r = REAL[2]
        c = A.Cert(r.chain[0])
        at = r.chain[0].index(c.spki_der) + 30              # inside the leaf's public key
        bad = [flip(r.chain[0], at)] + r.chain[1:]
        res = A.check(bad, r.challenge, r.blob)
        self.assertEqual(res.verdict, "unverified")
        self.assertIn("signatures do not verify", res.reason)

    def test_a_tampered_root_is_not_a_google_root(self):
        r = REAL[0]
        bad = r.chain[:-1] + [flip(r.chain[-1], 200)]
        res = A.check(bad, r.challenge, r.blob)
        self.assertEqual(res.verdict, "unverified")
        self.assertIn("Google hardware attestation root", res.reason)

    def test_a_chain_without_its_root_proves_nothing(self):
        r = REAL[0]
        self.assertEqual(A.check(r.chain[:-1], r.challenge, r.blob).verdict, "unverified")

    def test_a_chain_out_of_order_proves_nothing(self):
        r = REAL[0]
        bad = [r.chain[0], r.chain[2], r.chain[1]] + r.chain[3:]
        self.assertEqual(A.check(bad, r.challenge, r.blob).verdict, "unverified")

    def test_nothing_or_garbage_proves_nothing(self):
        r = REAL[0]
        for chain in ([], [b"garbage"], [b""], r.chain * 3):
            res = A.check(chain, r.challenge, r.blob)
            self.assertEqual(res.verdict, "unverified", chain[:1])

    def test_openssl_missing_is_a_warning_not_a_failure(self):
        r = REAL[0]
        res = A.check(r.chain, r.challenge, r.blob, openssl=None)
        self.assertEqual(res.verdict, "unverified")
        self.assertEqual(res.line(), "Key NOT hardware-attested (attestation not checked: openssl missing)")

    def test_a_broken_openssl_is_a_warning_not_a_failure(self):
        r = REAL[0]
        res = A.check(r.chain, r.challenge, r.blob, openssl="/bin/false")
        self.assertEqual(res.verdict, "unverified")

    def test_the_hash_must_match_the_signed_algorithm(self):
        # The outer algorithm identifier is unsigned; a chain that disagrees with the signed one is refused.
        r = REAL[0]
        mid = r.chain[1]
        c = A.Cert(mid)
        self.assertEqual(c.sig_alg, c.tbs_sig_alg)
        self.assertTrue(c.sig_alg.startswith("1.2.840.10045.4.3."), c.sig_alg)
        last = int(c.sig_alg.rsplit(".", 1)[1])
        enc = bytes.fromhex("2a8648ce3d0403") + bytes([last])
        i = mid.rindex(enc)                                      # the outer copy, after the signed one
        swapped = bytes.fromhex("2a8648ce3d0403") + bytes([5 - last])   # SHA256 <-> SHA384
        bad = [r.chain[0], mid[:i] + swapped + mid[i + 8:]] + r.chain[2:]
        res = A.check(bad, r.challenge, r.blob)
        self.assertEqual(res.verdict, "unverified")
        self.assertIn("signature algorithm", res.reason)


class SyntheticChains(unittest.TestCase):
    """Chains of a throwaway root that the test chooses to trust."""

    def setUp(self):
        self.root = F.new_root()
        self.roots = F.roots_for(self.root)
        self.key = ec.generate_private_key(ec.SECP256R1()).public_key()
        self.point = self.key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.blob = ssh_blob(self.point)
        self.challenge = hashlib.sha256(b"this pairing").digest()

    def chain(self, att=1, km=1, **kw):
        return F.build_chain(self.key, self.challenge, att, km, root=self.root, **kw)

    def check(self, chain, **kw):
        return A.check(chain, kw.pop("challenge", self.challenge), kw.pop("blob", self.blob), roots=self.roots, **kw)

    def test_hardware_levels(self):
        self.assertEqual(self.check(self.chain(1, 1)).line(), "Key attested: TEE")
        self.assertEqual(self.check(self.chain(2, 2)).line(), "Key attested: StrongBox")
        self.assertEqual(self.check(self.chain(2, 1)).level, "TEE", "the lower of the two")

    def test_a_genuine_chain_that_says_software_is_refused(self):
        for att, km in ((0, 0), (1, 0), (0, 2)):
            res = self.check(self.chain(att, km))
            self.assertEqual(res.verdict, "refused", (att, km))
            self.assertIn("software", res.reason)

    def test_the_same_chain_without_the_root_is_only_unverified(self):
        # The emulator: the chain is internally fine, but its root is nobody's.
        res = A.check(self.chain(0, 0), self.challenge, self.blob)
        self.assertEqual(res.verdict, "unverified")
        self.assertEqual(res.line(),
                         "Key NOT hardware-attested (the chain does not end at a Google hardware attestation root: "
                         "an emulator, or a phone without hardware attestation)")

    def test_wrong_challenge_and_other_key_are_refused(self):
        self.assertEqual(self.check(self.chain(), challenge=b"\x00" * 32).verdict, "refused")
        other = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.assertEqual(self.check(self.chain(), blob=ssh_blob(other)).verdict, "refused")

    def test_a_second_key_description_is_refused(self):
        res = self.check(self.chain(kd_in_intermediate=True))
        self.assertEqual(res.verdict, "refused")
        self.assertIn("leaf only", res.reason)

    def test_a_chain_with_no_key_description_is_refused(self):
        chain = F.build_chain(self.key, self.challenge, 1, 1, root=self.root)
        # Swap the leaf for a certificate of the same name signed by the same chain but without it.
        self.assertEqual(self.check(chain[1:]).verdict, "refused")   # the intermediate alone is the "leaf"

    def test_the_same_chain_passes_exactly_once_the_inputs_fit(self):
        # Negative controls above must be able to pass: this is the one that does.
        self.assertEqual(self.check(self.chain()).verdict, "attested")


class Revocation(unittest.TestCase):
    r = REAL[0]

    def run_check(self, status):
        return A.check(self.r.chain, self.r.challenge, self.r.blob, check_revocation=True, status=status)

    def test_not_asked_means_no_network(self):
        def boom():
            raise AssertionError("fetched without --check-revocation")
        self.assertEqual(A.check(self.r.chain, self.r.challenge, self.r.blob, status=boom).verdict, "attested")

    def test_clean_list(self):
        self.assertEqual(self.run_check(lambda: {"deadbeef": {"status": "REVOKED"}}).verdict, "attested")

    def test_a_revoked_certificate_is_refused(self):
        serial = A.Cert(self.r.chain[1]).serial
        res = self.run_check(lambda: {"%x" % serial: {"status": "REVOKED", "reason": "KEY_COMPROMISE"}})
        self.assertEqual(res.verdict, "refused")
        self.assertIn("revoked", res.reason)
        res = self.run_check(lambda: {"%x" % serial: {"status": "SUSPENDED"}})
        self.assertIn("suspended", res.reason)

    def test_unknown_status_is_not_attested_but_not_refused(self):
        def offline():
            raise OSError("no route")
        res = self.run_check(offline)
        self.assertEqual(res.verdict, "unverified")
        self.assertIn("revocation status unknown", res.reason)


class PairSide(unittest.TestCase):
    def test_challenge_vector_matches_the_phone(self):
        # The same vector as PairingTest.kt.
        np_, nh = bytes(range(32)), bytes(range(32, 64))
        d = bytes.fromhex("00000000000000000000ffffc0a801141e61")
        st = bytes.fromhex("fd6c5c9300231f7e445b9bfffe36628a1e61")
        self.assertEqual(P.attest_challenge(np_, d, st).hex(),
                         "6fcc2b4f7f2fa5c62a1c185cdf13b5509237eb71ff8fb9952e3c61a8a06d56eb")
        self.assertNotEqual(P.attest_challenge(nh, d, st), P.attest_challenge(np_, d, st))

    def test_fingerprint_is_ssh_keygens(self):
        self.assertEqual(P.fingerprint(b"abc"), "SHA256:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0")

    def test_request_chain_parses_the_answer(self):
        class Ag:
            def __init__(self, answer):
                self.answer = answer

            def ext(self, name, payload, limit=0):
                assert name == P.EXT_ATTEST and limit >= 16 * 1024
                return self.answer

        exp = b"c" * 32
        self.assertEqual(P.request_chain(Ag(S(exp) + S(b"leaf") + S(b"root")), exp), [b"leaf", b"root"])
        self.assertIn("older than 1.5", P.request_chain(Ag(None), exp))
        self.assertIn("malformed", P.request_chain(Ag(S(exp) + b"\x00\x00\x00\x09ab"), exp))
        self.assertIn("another pairing", P.request_chain(Ag(S(b"x" * 32) + S(b"leaf")), exp))

        def dead(*_a, **_k):
            raise ConnectionError("closed")
        ag = Ag(None)
        ag.ext = dead
        self.assertIn("did not answer", P.request_chain(ag, exp))

    def test_attest_is_loaded_next_to_pair_py(self):
        self.assertIsNotNone(P.load_attest())


if __name__ == "__main__":
    unittest.main(verbosity=1)
