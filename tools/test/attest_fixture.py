#!/usr/bin/env python3
"""Synthetic attestation chains, for tests ONLY (test_attest.py and mock_agent.py).

They have the shape of a phone's -- root, intermediate, leaf carrying a KeyDescription -- but the
root is a throwaway, so tools/attest.py never trusts one unless a test hands it that root. They
exist to reach the paths real chains cannot: a genuine-looking chain that says Software, a chain
with a second KeyDescription, a chain for another key. Real hardware chains are in tools/test/attest/.
"""
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

KEY_DESCRIPTION_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")


def der(tag, body):
    n = len(body)
    if n < 0x80:
        head = bytes([tag, n])
    else:
        lb = n.to_bytes((n.bit_length() + 7) // 8, "big")
        head = bytes([tag, 0x80 | len(lb)]) + lb
    return head + body


def integer(v):
    b = v.to_bytes((v.bit_length() + 8) // 8, "big")
    return der(0x02, b)


def key_description(challenge, attestation_level, keymaster_level):
    """KeyDescription, attestation version 300, empty authorization lists."""
    return der(0x30, integer(300) + der(0x0A, bytes([attestation_level])) + integer(300) +
               der(0x0A, bytes([keymaster_level])) + der(0x04, challenge) + der(0x04, b"") +
               der(0x30, b"") + der(0x30, b""))


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, key, issuer, issuer_key, ca, serial, ext=None):
    now = datetime.datetime(2026, 1, 1)
    b = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer))
         .public_key(key).serial_number(serial).not_valid_before(now)
         .not_valid_after(now + datetime.timedelta(days=3650))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ext is not None:
        b = b.add_extension(x509.UnrecognizedExtension(KEY_DESCRIPTION_OID, ext), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def new_root():
    """(private key, certificate DER) of a throwaway root, also usable as `roots` for attest.check."""
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _cert("test root", key.public_key(), "test root", key, True, 1)
    return key, cert.public_bytes(serialization.Encoding.DER)


def build_chain(leaf_public_key, challenge, attestation_level=0, keymaster_level=0, root=None,
                kd_in_intermediate=False):
    """[leaf, intermediate, root] as DER, leaf first. `root` is new_root()'s pair."""
    root_key, root_der = root or new_root()
    mid_key = ec.generate_private_key(ec.SECP256R1())
    root_cert = x509.load_der_x509_certificate(root_der)
    kd = key_description(challenge, attestation_level, keymaster_level)
    mid = _cert("test intermediate", mid_key.public_key(), "test root", root_key, True, 2,
                kd if kd_in_intermediate else None)
    leaf = _cert("Android Keystore Key", leaf_public_key, "test intermediate", mid_key, False, 3, kd)
    enc = serialization.Encoding.DER
    return [leaf.public_bytes(enc), mid.public_bytes(enc), root_cert.public_bytes(enc)]


def roots_for(root):
    """The `roots` argument of attest.check that trusts exactly this throwaway root."""
    import hashlib
    return {hashlib.sha256(root[1]).hexdigest(): ("test root", root[1])}
