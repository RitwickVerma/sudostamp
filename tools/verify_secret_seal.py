#!/usr/bin/env python3
"""Opens the message the phone's HPKE (Hpke.kt) sealed in a unit test, with the computer's
opener (tools/secret.py, pyca primitives): the two halves must agree on real output, not only on
the RFC's vectors. Plus a negative control: one flipped ciphertext bit must NOT open.

    python3 tools/verify_secret_seal.py app/build/secretcheck

HpkeTest `emit a sealed message for external verification` writes the directory; the recipient
is RFC 9180 A.3.1's skRm.
"""
import importlib.util
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("secret", os.path.join(here, "secret.py"))
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)

SK_R = bytes.fromhex("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2")


def main(d):
    from cryptography.hazmat.primitives.asymmetric import ec
    sk = ec.derive_private_key(int.from_bytes(SK_R, "big"), ec.SECP256R1())

    def read(n):
        with open(os.path.join(d, n), "rb") as f:
            return f.read()
    pt, inf, enc, ct = read("pt.bin"), read("info.bin"), read("enc.bin"), read("ct.bin")
    ok = S.hpke_open(sk, enc, ct, inf) == pt
    print("phone seal opened by the computer:", "OK" if ok else "MISMATCH", "(%d bytes)" % len(pt))
    try:
        S.hpke_open(sk, enc, ct[:-1] + bytes([ct[-1] ^ 1]), inf)
        refused = False
    except Exception:
        refused = True
    print("negative control (one bit flipped):", "refused" if refused else "OPENED -- broken")
    return 0 if ok and refused else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
