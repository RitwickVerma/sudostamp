#!/usr/bin/env python3
"""Unit tests for tools/secret.py: the same vectors as SecretProtocolTest.kt and HpkeTest.kt, and
its HPKE against messages sealed by pyca's own HPKE (an implementation that is not ours; frozen
here, because the distributions' pyca is older than its HPKE). Needs pyca `cryptography`. The
phone's half is checked the other way round by tools/verify_secret_seal.py.

    python3 -I tools/test/test_secret.py
"""
import hashlib
import importlib.util
import os
import unittest

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("secret", os.path.join(here, "..", "secret.py"))
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

h = bytes.fromhex
K = h("0000001365636473612d736861322d6e69737470323536000000086e6973747032353600000041"
      "040102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
      "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40")
NP = bytes(range(32))
WHY = "weekly backup ✓".encode()
# RFC 9180 A.3.1
INFO = h("4f6465206f6e2061204772656369616e2055726e")
SK_R = h("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2")
PK_R = h("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0")
ENC = h("04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4")
CT0 = h("5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434")
PT = h("4265617574792069732074727574682c20747275746820626561757479")
HOST = ec.derive_private_key(int.from_bytes(hashlib.sha256(b"sudostamp test host key").digest(), "big"), ec.SECP256R1())
SIG_H = h("3046022100c53aa0d0e54ea877e1c98bb46a9ce771a773aea980e3f06e5c1e911371f017ce022100a945dd83efc145975732b72c0af9adef935e1a4e2805fec0b985e742ad028d82")


def priv(scalar_bytes):
    return ec.derive_private_key(int.from_bytes(scalar_bytes, "big"), ec.SECP256R1())


class Vectors(unittest.TestCase):
    """The numbers in SecretProtocolTest.kt."""

    def t(self):
        return S.transcript(K, NP, b"input", b"restic", WHY, PK_R)

    def test_transcript_info_answer(self):
        t = self.t()
        self.assertEqual(len(t), 281)
        self.assertEqual(hashlib.sha256(t).hexdigest(), "b37db54d5eb1d176c20a60d4b7a01353791898f179ea42052c1f7be560a2980b")
        self.assertEqual(S.info(t).hex(), "7375646f7374616d702d7365637265742d763100"
                         "b37db54d5eb1d176c20a60d4b7a01353791898f179ea42052c1f7be560a2980b")
        self.assertEqual(hashlib.sha256(S.answer_message(t, ENC, CT0)).hexdigest(),
                         "153be01b755c4b0bc268c3854dac367bf80bbbcf9f6ed9ec44ea080901dee2aa")

    def test_host_key_and_signature(self):
        self.assertEqual(S.point(HOST.public_key()).hex(),
                         "04b80a6328f448a8796d12339d9c16f4f7c057ba2c7684b396f55b7b95ae6d933c"
                         "4e308f4b1237f4d7d3798f8c1a834debefacfb70c020e5b2c970916b667e85a8")
        self.assertTrue(S.verify(S.point(HOST.public_key()), self.t(), SIG_H))
        self.assertFalse(S.verify(S.point(HOST.public_key()), self.t() + b"\0", SIG_H))
        self.assertFalse(S.verify(PK_R, self.t(), SIG_H))

    def test_answer_longer_than_a_challenge(self):
        self.assertGreater(len(S.answer_message(b"", b"", b"")), 32)


class Hpke(unittest.TestCase):
    def test_rfc9180_a31_sequence_0(self):
        self.assertEqual(S.hpke_open(priv(SK_R), ENC, CT0, INFO, b"Count-0"), PT)

    # Sealed by pyca 50.0.2's hpke.Suite(P256, HKDF_SHA256, AES_128_GCM).encrypt(pt, pk, info) to
    # the key derive_private_key(SHA-256(b"pyca vector %d" % i)); output is enc || ct.
    PYCA = (
        (0, "7375646f7374616d702d7365637265742d7631000000000000000000000000000000000000000000000000000000000000000000", "",
         "04c7faafe4917373fdfbbe1c4b62e13c7f991445b7271d572f030498f281dbf1a0e33d767085949012218f399f3a1f95e28c5c0e5331"
         "1c8c110cdc3708f8cfe9e3b8c3c8f5137678c7062e93646eadb460"),
        (1, "69", "70c3a4737377c3b6726420e29c93",
         "04179660e20bd0e01f03872e5c672921a656416dcf5e1bd36329c896eb4f5fdd48c51da30a4529f88e8379756a9476276b0c508035"
         "6bd05a11a9366ffc1fa429714b78b9ba8bd3d3cc119248b318e46667e9be055e6246340ae96809c5c650"),
    )

    def test_opens_what_pyca_hpke_sealed(self):
        for i, inf, pt, blob in self.PYCA:
            sk = priv(hashlib.sha256(b"pyca vector %d" % i).digest())
            blob = h(blob)
            self.assertEqual(S.hpke_open(sk, blob[:65], blob[65:], h(inf)), h(pt))

    def test_tampering_is_refused(self):
        sk = priv(SK_R)
        for enc, ct, inf, aad in ((ENC, CT0[:-1] + bytes([CT0[-1] ^ 1]), INFO, b"Count-0"),
                                  (ENC, CT0, INFO + b"\0", b"Count-0"),
                                  (ENC, CT0, INFO, b"Count-1")):
            with self.assertRaises(Exception):
                S.hpke_open(sk, enc, ct, inf, aad)
        with self.assertRaises(ValueError):
            S.hpke_open(sk, ENC[:64], CT0, INFO, b"Count-0")
        with self.assertRaises(ValueError):            # off the curve
            S.hpke_open(sk, ENC[:-1] + bytes([ENC[-1] ^ 1]), CT0, INFO, b"Count-0")


class HostKey(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.d = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.d.name, "cfg", "sudostamp", "host-key.pem")

    def tearDown(self):
        self.d.cleanup()

    def test_made_private_and_kept(self):
        pub = S.keygen(self.path)
        self.assertEqual(len(pub), 65)
        self.assertEqual(pub[0], 4)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(os.path.dirname(self.path)).st_mode & 0o777, 0o700)
        self.assertEqual(S.keygen(self.path), pub, "pairing again must not change who this computer is")

    def test_a_key_others_can_read_is_refused(self):
        S.keygen(self.path)
        for mode in (0o640, 0o604, 0o620, 0o602):
            os.chmod(self.path, mode)
            with self.assertRaises(ValueError):
                S.load_host_key(self.path)
        os.chmod(self.path, 0o600)
        S.load_host_key(self.path)

    def test_a_symlink_is_refused(self):
        S.keygen(self.path)
        link = self.path + ".link"
        os.symlink(self.path, link)
        with self.assertRaises(OSError):
            S.load_host_key(link)
        with self.assertRaises(OSError):            # and keygen does not follow one to write
            os.remove(self.path)
            S.keygen(link)

    def test_another_curve_is_refused(self):
        from cryptography.hazmat.primitives import serialization
        os.makedirs(os.path.dirname(self.path), mode=0o700)
        k = ec.generate_private_key(ec.SECP384R1())
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
        with self.assertRaises(ValueError):
            S.load_host_key(self.path)


class PhonePoint(unittest.TestCase):
    def test_parses_the_pairing_vector(self):
        self.assertEqual(S.phone_point(K), K[-65:])

    def test_refuses_anything_else(self):
        for bad in (b"", K + b"\0", K[:-1], K.replace(b"nistp256", b"nistp384", 1),
                    K[:-65] + b"\x03" + K[-64:]):
            with self.assertRaises(ValueError):
                S.phone_point(bad)


if __name__ == "__main__":
    unittest.main()
