#!/usr/bin/env python3
"""Checks what the phone's vault crypto (app/.../vault/VaultCrypto.kt) produced in a unit test with
an implementation that shares no code with it (tools/test/vault_vectors.py, pyca primitives): the
two halves must agree on real output, not only on the fixture. Plus negative controls: one
flipped bit must NOT open, and a wrong key must NOT open.

    python3 -I tools/verify_vault_crypto.py app/build/vaultcheck

VaultCryptoTest `emit Kotlin-made vault crypto for external verification` writes the directory,
from the fake account in app/src/test/resources/vault/vectors-v1.json.
"""
import importlib.util
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("vault_vectors", os.path.join(here, "test", "vault_vectors.py"))
assert spec is not None and spec.loader is not None
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)


def flip(s):
    """The same EncString with one bit of its MAC flipped."""
    head, mac = s.rsplit("|", 1)
    m = bytearray(V.unb64(mac))
    m[0] ^= 1
    return head + "|" + V.b64(bytes(m))


def refuses(s, key):
    try:
        V.dec2(s, key)
        return False
    except ValueError:
        return True


def main(d):
    v = V.load()

    def read(n):
        with open(os.path.join(d, n), "rb") as f:
            return f.read()

    def text(n):
        return read(n).decode("ascii")

    results = []

    def check(label, ok):
        results.append(ok)
        print("%-58s %s" % (label, "OK" if ok else "MISMATCH"))

    # Recomputed from the account's inputs, not copied from the fixture.
    mk = V.master_key(v["password"], v["email"], int(v["iterations"]))
    st = V.stretch(mk)
    check("master key (PBKDF2-SHA256, 600000) equals pyca's", read("masterkey.bin") == mk)
    check("login hash equals pyca's", text("hash.txt") == V.password_hash(mk, v["password"]))
    check("stretched key (HKDF-Expand enc||mac) equals pyca's", read("stretched.bin") == st)

    user_key, org_key, item_key = bytes.fromhex(v["userKey"]), bytes.fromhex(v["orgKey"]), bytes.fromhex(v["itemKey"])
    org_text = text("org-text.enc")
    check("Kotlin type 2 under the org key opened by pyca", V.dec2(org_text, org_key) == read("org-text.bin"))
    rewrapped = text("item-key-rewrapped.enc")
    check("re-wrapped item key opens under the org key, = item key", V.dec2(rewrapped, org_key) == item_key)
    check("re-wrapped item key still opens the item's name", V.dec2(v["encItemName"], V.dec2(rewrapped, org_key)).decode() == v["itemName"])
    user_wrap = text("user-key.enc")
    check("Kotlin user-key wrap opened with pyca's stretched key", V.dec2(user_wrap, st) == user_key)

    check("negative control: one MAC bit flipped is refused", refuses(flip(org_text), org_key))
    check("negative control: re-wrapped key refused under the user key", refuses(rewrapped, user_key))
    check("negative control: user-key wrap refused under the user key", refuses(user_wrap, user_key))
    print("vault crypto, Kotlin output checked by pyca:", "PASS" if all(results) else "FAIL")
    return 0 if all(results) else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
