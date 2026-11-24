#!/usr/bin/env python3
"""Ask the paired phone for a secret the person types or fills there: `sudostamp input`.

Protocol (secret-hello-v1 / secret-request-v1) and the reasons for it: docs/design/secrets.md and
app/src/main/java/com/ritwick/sudostamp/SecretProtocol.kt, which shares this file's test vectors
(tools/test/test_secret.py, SecretProtocolTest.kt).

Needs pyca `cryptography` (ECDSA, ECDH, AES-GCM): the standard library has no elliptic curves.
Only this command needs it; sudo and pairing do not.
"""
import hashlib
import hmac
import struct

REQUEST_TAG = b"sudostamp-secret-request-v1\0"
ANSWER_TAG = b"sudostamp-secret-answer-v1\0"
INFO_TAG = b"sudostamp-secret-v1\0"
EXT_HELLO = b"secret-hello-v1@sudostamp"
EXT_REQUEST = b"secret-request-v1@sudostamp"
KIND_INPUT = b"input"
NONCE_BYTES = 32
POINT_BYTES = 65
MAX_SECRET_BYTES = 1024


def s(b):
    """An SSH string."""
    return struct.pack(">I", len(b)) + b


def framed(tag, *parts):
    return tag + b"".join(s(p) for p in parts)


def transcript(phone_key, nonce, kind, name, why, pk_r):
    """T: what this computer's host key signs; the answer is bound to it."""
    return framed(REQUEST_TAG, phone_key, nonce, kind, name, why, pk_r)


def info(t):
    return INFO_TAG + hashlib.sha256(t).digest()


def answer_message(t, enc, ct):
    """What the phone's key K signs for an answer (always longer than a 32-byte sudo challenge)."""
    return framed(ANSWER_TAG, t, enc, ct)


def phone_point(key_blob):
    """The 65-byte P-256 point inside an ecdsa-sha2-nistp256 SSH key blob, or ValueError."""
    def take(b, i):
        if i + 4 > len(b):
            raise ValueError("truncated key blob")
        n = struct.unpack(">I", b[i:i + 4])[0]
        if n > len(b) - i - 4:
            raise ValueError("truncated key blob")
        return b[i + 4:i + 4 + n], i + 4 + n
    kt, i = take(key_blob, 0)
    curve, i = take(key_blob, i)
    q, i = take(key_blob, i)
    if kt != b"ecdsa-sha2-nistp256" or curve != b"nistp256" or i != len(key_blob) \
            or len(q) != POINT_BYTES or q[0] != 4:
        raise ValueError("not an ecdsa-sha2-nistp256 key blob")
    return q


# ---------------------------------------------------------------- crypto (pyca)
# Imported here, not at the top, so `doctor` can say "pyca missing" instead of a traceback.

def _ec():
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec


def point(public_key):
    from cryptography.hazmat.primitives import serialization
    return public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def load_point(b):
    """A P-256 public key from 65 uncompressed bytes; pyca checks the point is on the curve."""
    ec = _ec()
    if len(b) != POINT_BYTES or b[0] != 4:
        raise ValueError("not an uncompressed P-256 point")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b)


def sign(private_key, msg):
    from cryptography.hazmat.primitives import hashes
    ec = _ec()
    return private_key.sign(msg, ec.ECDSA(hashes.SHA256()))


def verify(point_bytes, msg, sig_der):
    """True only for a valid DER ECDSA-P256-SHA256 signature by that point."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    ec = _ec()
    try:
        load_point(point_bytes).verify(sig_der, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


# HPKE (RFC 9180) base mode, single shot, DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM:
# the recipient's half of Hpke.kt. Composed from primitives every packaged pyca has (its own HPKE
# is 47+); tests check it against the RFC vectors and against that HPKE.
_KEM_SUITE = b"KEM" + struct.pack(">H", 0x10)
_HPKE_SUITE = b"HPKE" + struct.pack(">HHH", 0x10, 1, 1)


def _extract(salt, ikm):
    return hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()


def _expand(prk, inf, n):
    assert 1 <= n <= 32
    return hmac.new(prk, inf + b"\x01", hashlib.sha256).digest()[:n]


def _lx(suite, salt, label, ikm):
    return _extract(salt, b"HPKE-v1" + suite + label + ikm)


def _le(suite, prk, label, inf, n):
    return _expand(prk, struct.pack(">H", n) + b"HPKE-v1" + suite + label + inf, n)


def hpke_open(sk_r, enc, ct, inf, aad=b""):
    """Plaintext, or raises (InvalidTag, ValueError). sk_r: a pyca P-256 private key."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ec = _ec()
    dh = sk_r.exchange(ec.ECDH(), load_point(enc))
    shared = _le(_KEM_SUITE, _lx(_KEM_SUITE, b"", b"eae_prk", dh), b"shared_secret",
                 enc + point(sk_r.public_key()), 32)
    ctx = b"\x00" + _lx(_HPKE_SUITE, b"", b"psk_id_hash", b"") + _lx(_HPKE_SUITE, b"", b"info_hash", inf)
    secret = _lx(_HPKE_SUITE, shared, b"secret", b"")
    key = _le(_HPKE_SUITE, secret, b"key", ctx, 16)
    nonce = _le(_HPKE_SUITE, secret, b"base_nonce", ctx, 12)
    return AESGCM(key).decrypt(nonce, ct, aad)
