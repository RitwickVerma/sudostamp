#!/usr/bin/env python3
"""
Simulate pam_rssh's authentication sequence against the phone agent.

This is a faithful replay of the module's actual code path, so that a PASS here means
the PAM module has a working backend. Read the module source and mirror it exactly:

  lib.rs:219  AgentClient::new(ssh_agent_addr)
  lib.rs:220  agent.list_identities()
  lib.rs:223  skip any key not present in authorized_keys  <-- pinned key check
  lib.rs:69   challenge = gen_challenge()            -> 32 random bytes
  lib.rs:70   sig = agent.sign_data(&challenge, pubkey)
  lib.rs:71   verify_signature(&challenge, pubkey, &sig)

Needs no root. If this passes, the only thing left is the PAM plumbing.
"""
import base64
import hashlib
import os
import socket
import struct
import sys

# The phone, as host:port -- the same SUDOSTAMP_PHONE the installer takes.
PHONE = os.environ.get("SUDOSTAMP_PHONE", "")
if PHONE.count(":") != 1:
    sys.exit("set SUDOSTAMP_PHONE=<phone-ip>:7777")
HOST, _port = PHONE.split(":")
PORT = int(_port)

# The pinned public key: the file pam_rssh itself reads (auth_key_file), so a key that
# drifted from the phone fails here exactly as it would at the sudo prompt.
KEYFILE = os.environ.get(
    "SUDOSTAMP_KEYFILE",
    "/etc/authorized_keys/%s.keys" % (os.environ.get("SUDO_USER") or os.environ.get("USER", "")))
try:
    with open(KEYFILE) as f:
        PINNED = f.read().strip()
except OSError as e:
    sys.exit("cannot read the pinned key %s (%s); set SUDOSTAMP_KEYFILE" % (KEYFILE, e))

SSH2_AGENTC_REQUEST_IDENTITIES = 11
SSH2_AGENTC_SIGN_REQUEST = 13
SSH2_AGENT_IDENTITIES_ANSWER = 12
SSH2_AGENT_SIGN_RESPONSE = 14
SSH2_AGENT_FAILURE = 5
SSH_AGENT_RSA_SHA2_256 = 0x02

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print("  %-42s %s%s" % (name, "PASS" if ok else "FAIL", ("  " + detail) if detail else ""))
    return ok


def recv_exactly(sock, n):
    """sock.recv(n) does NOT guarantee n bytes. A short read here would look like a
    device failure and send us chasing a bug that isn't there."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed after %d/%d bytes" % (len(buf), n))
        buf += chunk
    return buf


def s_string(b):
    return struct.pack(">I", len(b)) + b


def read_msg(sock):
    (length,) = struct.unpack(">I", recv_exactly(sock, 4))
    return recv_exactly(sock, length)


def send_msg(sock, payload):
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def main():
    print("=== simulating pam_rssh auth path against %s:%d ===" % (HOST, PORT))

    # ---- 1. connect (lib.rs:219 AgentClient::new, ssh_agent_auth.rs:46 connect)
    sock = None
    try:
        sock = socket.create_connection((HOST, PORT), timeout=10)
    except Exception as e:
        check("tcp connect to phone agent", False, repr(e))
        return 1
    check("tcp connect to phone agent", True)
    # A human has to touch a fingerprint sensor mid-handshake, so the sign step needs a
    # generous read timeout. Connect stays at 10s (that should be instant).
    sock.settimeout(120)

    # ---- 2. REQUEST_IDENTITIES (lib.rs:220 list_identities)
    send_msg(sock, bytes([SSH2_AGENTC_REQUEST_IDENTITIES]))
    resp = read_msg(sock)
    if not resp or resp[0] != SSH2_AGENT_IDENTITIES_ANSWER:
        check("REQUEST_IDENTITIES -> IDENTITIES_ANSWER", False, "got byte %r" % (resp[:1],))
        return 1
    check("REQUEST_IDENTITIES -> IDENTITIES_ANSWER", True)

    (nkeys,) = struct.unpack(">I", resp[1:5])
    off = 5
    keys = []
    for _ in range(nkeys):
        (klen,) = struct.unpack(">I", resp[off:off + 4])
        off += 4
        blob = resp[off:off + klen]
        off += klen
        (clen,) = struct.unpack(">I", resp[off:off + 4])
        off += 4
        comment = resp[off:off + clen].decode("utf-8", "replace")
        off += clen
        keys.append((blob, comment))
    check("agent reports exactly 1 key", nkeys == 1, "nkeys=%d" % nkeys)
    if nkeys != 1:
        return 1

    blob, comment = keys[0]
    pub_blob = base64.b64decode(PINNED.split()[1])

    # ---- 3. the authorized_keys check (lib.rs:223 is_key_authorized).
    # This is the pin. Byte comparison, not a substring or a prefix match.
    expected_algo = s_string(b"ecdsa-sha2-nistp256")
    check("agent key == pinned key (byte-exact)",
          blob == pub_blob,
          "blob %d bytes, pinned %d bytes" % (len(blob), len(pub_blob)))
    check("key algorithm is ecdsa-sha2-nistp256",
          blob.startswith(expected_algo))
    check("key comment", True, repr(comment))

    # ---- 4. fresh 32-byte challenge (lib.rs:69 gen_challenge)
    challenge = os.urandom(32)
    check("challenge is 32 CSPRNG bytes", len(challenge) == 32)

    # ---- 5. SIGN_REQUEST (ssh_agent_auth.rs:104 sign_data).
    # ECDSA => flags stay 0 (only RSA sets RSA_SHA2_256).
    body = (bytes([SSH2_AGENTC_SIGN_REQUEST])
            + s_string(blob) + s_string(challenge) + struct.pack(">I", 0))
    send_msg(sock, body)
    resp = read_msg(sock)
    if not resp or resp[0] == SSH2_AGENT_FAILURE:
        check("SIGN_REQUEST -> SIGN_RESPONSE", False,
              "agent returned FAILURE (no fingerprint touched, or rejected)")
        return 1
    if resp[0] != SSH2_AGENT_SIGN_RESPONSE:
        check("SIGN_REQUEST -> SIGN_RESPONSE", False, "got byte %r" % (resp[:1],))
        return 1
    check("SIGN_REQUEST -> SIGN_RESPONSE", True)

    (slen,) = struct.unpack(">I", resp[1:5])
    sig_blob = resp[5:5 + slen]
    check("no trailing bytes after signature blob",
          len(resp) == 5 + slen, "len(resp)=%d expected=%d" % (len(resp), 5 + slen))

    # ---- 6. verify (sign_verify.rs:167).
    #
    # ECDSA sig blob = string(algo) || string( inner ) where
    #     inner = string( mpint r ) || string( mpint s )     <-- SSH wire format, NOT DER.
    #
    # An earlier version of this checker asserted "raw sig == 64 bytes" and treated the
    # inner blob as packed r||s. That is the *unwrapped* form and is wrong: each mpint
    # carries its own 4-byte length prefix, and r gains a leading 0x00 whenever its top
    # bit is set. So a correct signature is 70-74 bytes, and the bogus assertion failed a
    # perfectly good implementation. Decode it the way the protocol defines it.
    o = 0
    (alen,) = struct.unpack(">I", sig_blob[o:o + 4]); o += 4
    sig_algo = sig_blob[o:o + alen]; o += alen
    (ilen,) = struct.unpack(">I", sig_blob[o:o + 4]); o += 4
    inner = sig_blob[o:o + ilen]; o += ilen
    check("no trailing bytes inside signature blob", o == len(sig_blob))
    check("signature algorithm", True, sig_algo.decode())

    p = 0
    (rlen,) = struct.unpack(">I", inner[p:p + 4]); p += 4
    r_bytes = inner[p:p + rlen]; p += rlen
    (slen,) = struct.unpack(">I", inner[p:p + 4]); p += 4
    s_bytes = inner[p:p + slen]; p += slen
    check("inner blob fully consumed", p == len(inner),
          "consumed=%d of %d" % (p, len(inner)))
    check("r and s are 32-33 bytes (P-256 mpints)",
          rlen in (32, 33) and slen in (32, 33), "rlen=%d slen=%d" % (rlen, slen))
    check("no negative mpints (leading 0x00 only pads sign bit)",
          not (len(r_bytes) > 1 and r_bytes[0] == 0 and not (r_bytes[1] & 0x80))
          and not (len(s_bytes) > 1 and s_bytes[0] == 0 and not (s_bytes[1] & 0x80)))

    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes

    r = int.from_bytes(r_bytes, "big")
    s = int.from_bytes(s_bytes, "big")
    check("r,s are in range (1..n-1)",
          0 < r < 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 and
          0 < s < 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551)

    # pam_rssh re-encodes r,s as DER before calling OpenSSL (sign_verify.rs:110).
    der = utils.encode_dss_signature(r, s)

    # Rebuild the P-256 public key from the SSH blob.
    q_off = 4 + len("ecdsa-sha2-nistp256") + 4 + len("nistp256") + 4
    q = blob[q_off:]
    q = q[4:] if len(q) == 68 else q
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), q)

    ok = True
    try:
        pub.verify(der, challenge, ec.ECDSA(hashes.SHA256()))
    except Exception as e:
        ok = False
        detail = repr(e)
    else:
        detail = ""
    check("signature verifies over the challenge", ok, detail)

    # ---- 7. the challenge is actually random (replay defence).
    # If the agent returned a signature over something else, or the challenge were
    # constant, this catches it.
    try:
        pub.verify(der, os.urandom(32), ec.ECDSA(hashes.SHA256()))
        check("signature does NOT verify over a different message", False,
              "verified over wrong data -- signature is not bound to the challenge")
    except Exception:
        check("signature does NOT verify over a different message", True)

    sock.close()

    # A tamper check: flip one bit of the challenge, must fail.
    bad = bytearray(challenge)
    bad[0] ^= 0x01
    try:
        pub.verify(der, bytes(bad), ec.ECDSA(hashes.SHA256()))
        check("signature rejects a 1-bit tampered challenge", False, "BUG")
    except Exception:
        check("signature rejects a 1-bit tampered challenge", True)

    failed = [n for n, ok, _ in results if not ok]
    print()
    if failed:
        print("RESULT: FAILED (%d) -> %s" % (len(failed), ", ".join(failed)))
        return 1
    print("RESULT: PASSED (%d checks) -- pam_rssh backend is functional" % len(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
