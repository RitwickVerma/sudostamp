#!/usr/bin/env python3
"""Bitwarden V1 client crypto, written from the published format with pyca, WITHOUT reading
app/.../vault/VaultCrypto.kt: the independent half of the vault crypto vectors.

    python3 -I tools/test/vault_vectors.py            # rewrite the fixture (fresh random keys)
    python3 -I tools/test/vault_vectors.py --check    # recompute what is derivable, compare

The fixture is app/src/test/resources/vault/vectors-v1.json. VaultCryptoTest decrypts it;
tools/verify_vault_crypto.py imports this module to open what the Kotlin side encrypted.

The account is fake: test@example.invalid, 'correct horse battery staple', PBKDF2 at 600 000.

What this is NOT: the design (docs/design/vault-grant.md section 7) wants vectors from the
official `bw` CLI against a throwaway server. Those are owed by phase 2. Until then this file
is a second implementation of the same published format, by a different library, plus
Bitwarden's own published master-password-hash vector (below), which both sides reproduce.

Needs python3-cryptography (pyca). Every value in the fixture is a string with no quote or
backslash, so the Kotlin test can read it without a JSON library (the app has none on the JVM).
"""
import base64
import hashlib
import hmac
import json
import os
import sys

from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as apad
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "..", "..", "app", "src", "test", "resources", "vault", "vectors-v1.json")

EMAIL = "  Test@Example.INVALID "   # trimmed and lowercased before use, as every Bitwarden client does
PASSWORD = "correct horse battery staple"
ITERATIONS = 600000

# Bitwarden's own published vector (sdk-internal, bitwarden-crypto master_key.rs,
# test_password_hash_pbkdf2): password "asdfasdf", email "test@bitwarden.com", PBKDF2 100 000.
# Cited from memory, without network access; that pyca reproduces it exactly is what confirms it.
PUBLISHED = ("asdfasdf", "test@bitwarden.com", 100000, "wmyadRMyBZOH7P/a/ucTCbSghKgdzDpPqUnu/DAVtSw=")


def b64(b):
    return base64.b64encode(b).decode("ascii")


def unb64(s):
    return base64.b64decode(s, validate=True)


def master_key(password, email, iterations):
    salt = email.strip().lower().encode("utf-8")
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, iterations).derive(password.encode("utf-8"))


def password_hash(mk, password):
    return b64(PBKDF2HMAC(hashes.SHA256(), 32, password.encode("utf-8"), 1).derive(mk))


def stretch(mk):
    enc = HKDFExpand(hashes.SHA256(), 32, b"enc").derive(mk)
    mac = HKDFExpand(hashes.SHA256(), 32, b"mac").derive(mk)
    return enc + mac


def enc2(pt, key, iv=None):
    """EncString type 2: AES-256-CBC (PKCS#7) then HMAC-SHA256 over iv || ct."""
    assert len(key) == 64
    iv = iv or os.urandom(16)
    p = padding.PKCS7(128).padder()
    data = p.update(pt) + p.finalize()
    e = Cipher(algorithms.AES(key[:32]), modes.CBC(iv)).encryptor()
    ct = e.update(data) + e.finalize()
    mac = hmac.new(key[32:], iv + ct, hashlib.sha256).digest()
    return "2.%s|%s|%s" % (b64(iv), b64(ct), b64(mac))


def dec2(s, key):
    """The opener for verify_vault_crypto.py: refuses anything but a well-formed, authentic type 2."""
    assert len(key) == 64
    if not s.startswith("2."):
        raise ValueError("not type 2")
    parts = s[2:].split("|")
    if len(parts) != 3:
        raise ValueError("parts")
    iv, ct, mac = (unb64(x) for x in parts)
    if len(iv) != 16 or len(mac) != 32 or not ct or len(ct) % 16:
        raise ValueError("lengths")
    if not hmac.compare_digest(hmac.new(key[32:], iv + ct, hashlib.sha256).digest(), mac):
        raise ValueError("mac")
    d = Cipher(algorithms.AES(key[:32]), modes.CBC(iv)).decryptor()
    u = padding.PKCS7(128).unpadder()
    return u.update(d.update(ct) + d.finalize()) + u.finalize()


def enc4(pt, public_key, digest: "type[hashes.HashAlgorithm]" = hashes.SHA1):
    """EncString type 4: RSA-OAEP with SHA-1 (and MGF1-SHA-1), as Bitwarden wraps org keys."""
    ct = public_key.encrypt(pt, apad.OAEP(apad.MGF1(digest()), digest(), None))
    return "4." + b64(ct)


def generate():
    mk = master_key(PASSWORD, EMAIL, ITERATIONS)
    stretched = stretch(mk)
    user_key = os.urandom(64)
    rsa_key = rsa.generate_private_key(65537, 2048)
    der = rsa_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    small = rsa.generate_private_key(65537, 1024).private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    org_key = os.urandom(64)
    item_key = os.urandom(64)
    name, pw, notes, org_text = "Example login", "hunter2 \u00e9\u00e8 \U0001f511", "a note under the user key", "an org string"
    v = {
        "email": EMAIL,
        "password": PASSWORD,
        "kdfType": "0",
        "iterations": str(ITERATIONS),
        "masterKey": mk.hex(),
        "masterPasswordHash": password_hash(mk, PASSWORD),
        "stretchedKey": stretched.hex(),
        "userKey": user_key.hex(),
        "encUserKey": enc2(user_key, stretched),
        "encUserKeyShort": enc2(user_key[:32], stretched),           # a 32-byte "user key": refused
        "privateKeyDer": b64(der),
        "publicKeySpki": b64(rsa_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
        "encPrivateKey": enc2(der, user_key),
        "encPrivateKey1024": enc2(small, user_key),                   # RSA-1024: refused
        "orgKey": org_key.hex(),
        "encOrgKey": enc4(org_key, rsa_key.public_key()),
        "encOrgKeyOaepSha256": enc4(org_key, rsa_key.public_key(), hashes.SHA256),  # wrong OAEP: refused
        "encOrgKeyShort": enc4(org_key[:32], rsa_key.public_key()),   # 32 bytes: refused
        "itemKey": item_key.hex(),
        "encItemKey": enc2(item_key, user_key),
        "itemName": name,
        "encItemName": enc2(name.encode("utf-8"), item_key),
        "itemPassword": pw.encode("utf-8").hex(),                      # hex: non-ASCII stays out of the JSON
        "encItemPassword": enc2(pw.encode("utf-8"), item_key),
        "userNotes": notes,
        "encUserNotes": enc2(notes.encode("utf-8"), user_key),
        "orgText": org_text,
        "encOrgText": enc2(org_text.encode("utf-8"), org_key),
        "encEmpty": enc2(b"", user_key),                                # one block of padding
    }
    for k, s in v.items():
        assert '"' not in s and "\\" not in s and all(32 <= ord(c) < 127 for c in s), k
    return v


def check(v):
    """Everything in the fixture that can be recomputed or opened, recomputed or opened."""
    mk = master_key(v["password"], v["email"], int(v["iterations"]))
    assert mk.hex() == v["masterKey"]
    assert password_hash(mk, v["password"]) == v["masterPasswordHash"]
    st = stretch(mk)
    assert st.hex() == v["stretchedKey"]
    uk = dec2(v["encUserKey"], st)
    assert uk.hex() == v["userKey"]
    der = dec2(v["encPrivateKey"], uk)
    assert b64(der) == v["privateKeyDer"]
    pk = serialization.load_der_private_key(der, None)
    assert isinstance(pk, rsa.RSAPrivateKey) and pk.key_size == 2048
    ok = pk.decrypt(unb64(v["encOrgKey"][2:]), apad.OAEP(apad.MGF1(hashes.SHA1()), hashes.SHA1(), None))
    assert ok.hex() == v["orgKey"]
    ik = dec2(v["encItemKey"], uk)
    assert ik.hex() == v["itemKey"]
    assert dec2(v["encItemName"], ik).decode() == v["itemName"]
    assert dec2(v["encItemPassword"], ik).hex() == v["itemPassword"]
    assert dec2(v["encUserNotes"], uk).decode() == v["userNotes"]
    assert dec2(v["encOrgText"], ok).decode() == v["orgText"]
    pw, email, it, want = PUBLISHED
    assert password_hash(master_key(pw, email, it), pw) == want, "published vector"


def load():
    with open(FIXTURE, encoding="ascii") as f:
        return json.load(f)


def main(argv):
    if argv == ["--check"]:
        check(load())
        print("vault vectors: fixture recomputed and opened by pyca: OK")
        return 0
    if argv:
        sys.exit(__doc__)
    v = generate()
    check(v)
    os.makedirs(os.path.dirname(FIXTURE), exist_ok=True)
    with open(FIXTURE, "w", encoding="ascii") as f:
        json.dump(v, f, indent=2, sort_keys=True)
        f.write("\n")
    print("wrote", os.path.relpath(FIXTURE))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
