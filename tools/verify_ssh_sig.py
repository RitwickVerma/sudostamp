#!/usr/bin/env python3
"""Verify SshSig's output with tools that are NOT our own code.

WHY: a unit test can assert the structure of a blob and still be satisfied by bytes no
real SSH implementation accepts. This script closes that gap using two independent
verifiers:

  1. `ssh-keygen -l` on the emitted public key. OpenSSH refuses a malformed
     ecdsa-sha2-nistp256 blob, so a successful fingerprint proves the key encoding
     (curve name + uncompressed point) is right.
  2. `cryptography` parses the signature blob per the SSH wire format and verifies the
     ECDSA signature over the message. That proves the DER -> (r,s) mpint conversion.

The artifacts come from the unit test `emit artifacts for external verification`:
    ./gradlew test          # writes app/build/sshcheck/{test.pub,msg.bin,sig.bin}
    python3 tools/verify_ssh_sig.py app/build/sshcheck

Usage: python3 tools/verify_ssh_sig.py [dir]
"""
import base64
import os
import struct
import subprocess
import sys


def ssh_string(buf, off):
    (n,) = struct.unpack_from(">I", buf, off)
    off += 4
    return buf[off:off + n], off + n


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else "app/build/sshcheck"
    pub_path = os.path.join(d, "test.pub")
    msg_path = os.path.join(d, "msg.bin")
    sig_path = os.path.join(d, "sig.bin")

    for p in (pub_path, msg_path, sig_path):
        if not os.path.exists(p):
            print("MISSING: %s\n(run ./gradlew test first)" % p)
            return 1

    failures = []

    # ---------------------------------------------------------------- 1. pubkey
    print("=== 1. key blob vs real ssh-keygen ===")
    line = open(pub_path).read().strip()
    parts = line.split()
    print("   line: %s...%s" % (line[:34], line[-14:]))
    if parts[0] != "ecdsa-sha2-nistp256":
        failures.append("key type is not ecdsa-sha2-nistp256")

    blob = base64.b64decode(parts[1])
    keytype, off = ssh_string(blob, 0)
    curve, off = ssh_string(blob, off)
    point, off = ssh_string(blob, off)
    print("   keytype=%r curve=%r point_len=%d first=0x%02x"
          % (keytype.decode(), curve.decode(), len(point), point[0]))
    if keytype != b"ecdsa-sha2-nistp256":
        failures.append("inner keytype wrong")
    if curve != b"nistp256":
        failures.append("curve name wrong: %r" % curve)
    if len(point) != 65 or point[0] != 0x04:
        failures.append("point is not a 65-byte uncompressed point")
    if off != len(blob):
        failures.append("trailing bytes in key blob")

    r = subprocess.run(["ssh-keygen", "-l", "-f", pub_path], capture_output=True, text=True)
    print("   ssh-keygen -l -> rc=%d  %s" % (r.returncode, (r.stdout or r.stderr).strip()))
    if r.returncode != 0:
        failures.append("ssh-keygen REFUSED the public key line")
    else:
        print("   [PASS] OpenSSH parsed our key blob")

    # --------------------------------------------------------------- 2. sig blob
    print("\n=== 2. signature blob vs cryptography ===")
    sigblob = open(sig_path, "rb").read()
    stype, off = ssh_string(sigblob, 0)
    inner, off = ssh_string(sigblob, off)
    print("   sig type=%r  inner=%d bytes" % (stype.decode(), len(inner)))
    if stype != b"ecdsa-sha2-nistp256":
        failures.append("signature type wrong")
    if off != len(sigblob):
        failures.append("trailing bytes in signature blob")

    r_bytes, off2 = ssh_string(inner, 0)
    s_bytes, off3 = ssh_string(inner, off2)
    print("   r=%d bytes (lead 0x%02x)  s=%d bytes (lead 0x%02x)"
          % (len(r_bytes), r_bytes[0], len(s_bytes), s_bytes[0]))
    if off3 != len(inner):
        failures.append("trailing bytes in r/s container")
    for name, b in (("r", r_bytes), ("s", s_bytes)):
        if len(b) > 1 and b[0] == 0x00 and not (b[1] & 0x80):
            failures.append("%s has a non-minimal leading zero" % name)

    try:
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        from cryptography.hazmat.primitives import hashes
        pubkey = ec.EllipticCurvePublicNumbers(
            int.from_bytes(point[1:33], "big"),
            int.from_bytes(point[33:65], "big"),
            ec.SECP256R1(),
        ).public_key()
        der = utils.encode_dss_signature(
            int.from_bytes(r_bytes, "big"), int.from_bytes(s_bytes, "big")
        )
        msg = open(msg_path, "rb").read()
        pubkey.verify(der, msg, ec.ECDSA(hashes.SHA256()))
        print("   [PASS] ECDSA signature VERIFIED over the message")
    except ImportError:
        print("   (cryptography not installed; structural checks only)")
        msg = None
    except Exception as e:
        failures.append("signature did NOT verify: %s" % e)
        print("   [FAIL] %s" % e)

    # ------------------------------------------------------- 3. tamper detection
    print("\n=== 3. tamper detection (must fail) ===")
    try:
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        from cryptography.hazmat.primitives import hashes
        pubkey = ec.EllipticCurvePublicNumbers(
            int.from_bytes(point[1:33], "big"),
            int.from_bytes(point[33:65], "big"),
            ec.SECP256R1(),
        ).public_key()
        r_int = int.from_bytes(r_bytes, "big")
        s_int = int.from_bytes(s_bytes, "big")
        try:
            pubkey.verify(utils.encode_dss_signature(r_int, s_int ^ 1),
                          open(msg_path, "rb").read(), ec.ECDSA(hashes.SHA256()))
            failures.append("tampered signature VERIFIED -- catastrophic")
        except Exception:
            print("   [PASS] tampered signature rejected")
        try:
            pubkey.verify(utils.encode_dss_signature(r_int, s_int),
                          b"a different message", ec.ECDSA(hashes.SHA256()))
            failures.append("signature verified over the WRONG message -- catastrophic")
        except Exception:
            print("   [PASS] wrong-message rejected")
    except ImportError:
        print("   (skipped)")

    print("\n" + "=" * 60)
    if failures:
        print("FAILED (%d):" % len(failures))
        for f in failures:
            print("   - %s" % f)
    else:
        print("ALL FORMAT CHECKS PASSED")
    print("=" * 60)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
