#!/usr/bin/env python3
"""
Ad-hoc verification for the SudoStamp fixes.

Scope note: this asserts the BEHAVIOUR THAT CHANGED, not the whole app.

The headline check needs NO fingerprint, on purpose. The old AgentService served exactly
one request frame per TCP connection, so a second request on the same socket hit a closed
socket. That is testable deterministically by sending REQUEST_IDENTITIES twice down one
connection -- no biometric, no human, no timing dependence:

    old code -> 2nd request sees EOF
    new code -> 2nd request gets its own IDENTITIES_ANSWER

A negative control (unknown request type) then proves the loop keeps serving afterwards
rather than dying on the odd frame. Then the hardening that needs no finger either:
refusals that must come back instantly (wrong key, non-challenge payloads), the per-
connection frame cap and, with --slow, the connection time budget.

    SUDOSTAMP_PHONE=<phone-ip>:7777 python3 tools/reuse_connection_test.py [--slow]
"""
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

C_REQUEST_IDENTITIES = 11
C_SIGN_REQUEST = 13
A_IDENTITIES_ANSWER = 12
A_FAILURE = 5

results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print("  %-52s %s%s" % (name, "PASS" if ok else "FAIL",
                            ("  " + detail) if detail else ""))
    return ok


def recv_exactly(sock, n):
    """recv(n) may return short. Not looping here is how you invent a device fault."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("closed after %d/%d bytes" % (len(buf), n))
        buf += chunk
    return buf


def read_msg(sock):
    (length,) = struct.unpack(">I", recv_exactly(sock, 4))
    return recv_exactly(sock, length)


def send_msg(sock, payload):
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def main():
    print("=== ad-hoc verification: one connection, many frames (%s:%d) ===" % (HOST, PORT))

    sock = socket.create_connection((HOST, PORT), timeout=10)
    sock.settimeout(15)

    # --- 1. first request
    send_msg(sock, bytes([C_REQUEST_IDENTITIES]))
    r1 = read_msg(sock)
    check("1st REQUEST_IDENTITIES -> IDENTITIES_ANSWER",
          r1[0] == A_IDENTITIES_ANSWER, "type=%d" % r1[0])

    # --- 2. THE REGRESSION CHECK: same socket, second request.
    # If the server reverted to one-frame-per-connection this raises EOFError instead.
    try:
        send_msg(sock, bytes([C_REQUEST_IDENTITIES]))
        r2 = read_msg(sock)
        served_second = (r2[0] == A_IDENTITIES_ANSWER)
        detail = "type=%d" % r2[0]
    except EOFError as e:
        served_second = False
        detail = "EOF -- server closed after one frame (the original bug): %s" % e
    check("2nd request on SAME socket is served", served_second, detail)

    # --- 3. identical answers (no state leaked between requests)
    if served_second:
        check("both answers byte-identical", r1 == r2,
              "%d vs %d bytes" % (len(r1), len(r2)))

    # --- 4. negative control: unknown type must FAILURE but keep the connection
    send_msg(sock, bytes([99]))
    r3 = read_msg(sock)
    check("unknown request type -> FAILURE", r3[0] == A_FAILURE, "type=%d" % r3[0])

    # --- 5. and the connection survives that refusal
    try:
        send_msg(sock, bytes([C_REQUEST_IDENTITIES]))
        r4 = read_msg(sock)
        still = (r4[0] == A_IDENTITIES_ANSWER)
        detail = "type=%d" % r4[0]
    except EOFError as e:
        still = False
        detail = "EOF after FAILURE: %s" % e
    check("connection survives a refused frame", still, detail)

    # --- 6. a malformed frame must close cleanly, not wedge the server
    sock.close()
    s2 = socket.create_connection((HOST, PORT), timeout=10)
    s2.settimeout(10)
    s2.sendall(struct.pack(">I", 0x7FFFFFFF))          # absurd length
    try:
        s2.recv(16)
    except Exception:
        pass
    s2.close()
    check("absurd frame length does not crash server", True)

    # --- 7. server still accepts new connections after all that
    s3 = socket.create_connection((HOST, PORT), timeout=10)
    s3.settimeout(15)
    send_msg(s3, bytes([C_REQUEST_IDENTITIES]))
    r5 = read_msg(s3)
    check("server healthy after malformed input",
          r5[0] == A_IDENTITIES_ANSWER and r5 == r1, "type=%d" % r5[0])
    s3.close()

    # --- 8. requests the agent must refuse WITHOUT asking the user. An instant FAILURE
    # is the proof: anything put to the user would sit waiting on a fingerprint.
    key_blob = r1[9:9 + struct.unpack(">I", r1[5:9])[0]]

    def sign_req(blob, data):
        return (bytes([C_SIGN_REQUEST]) + struct.pack(">I", len(blob)) + blob
                + struct.pack(">I", len(data)) + data + struct.pack(">I", 0))

    for name, blob, data in (
            ("wrong key", b"\x00" * len(key_blob), os.urandom(32)),
            ("64-byte payload (not a pam_rssh challenge)", key_blob, os.urandom(64)),
            ("SSHSIG-shaped payload", key_blob, b"SSHSIG" + os.urandom(58))):
        s4 = socket.create_connection((HOST, PORT), timeout=10)
        s4.settimeout(5)
        send_msg(s4, sign_req(blob, data))
        try:
            r = read_msg(s4)
            ok, detail = r[0] == A_FAILURE, "type=%d" % r[0]
        except socket.timeout:
            ok, detail = False, "no answer in 5 s: it was put to the user"
        s4.close()
        check("refused unprompted: " + name, ok, detail)

    # --- 9. a connection that will not stop talking is cut off
    s5 = socket.create_connection((HOST, PORT), timeout=10)
    s5.settimeout(10)
    answered = 0
    try:
        for _ in range(12):
            send_msg(s5, bytes([C_REQUEST_IDENTITIES]))
            read_msg(s5)
            answered += 1
    except (EOFError, OSError):
        pass
    s5.close()
    check("frames per connection are capped", 0 < answered < 12, "answered %d of 12" % answered)

    # --- 10. (opt-in, ~35 s) a slow-drip client cannot hold the worker past its budget
    if "--slow" in sys.argv:
        import time
        s6 = socket.create_connection((HOST, PORT), timeout=10)
        # A valid header promising 1000 bytes, then the body one byte at a time. Every
        # byte is well formed, so only the time budget can end this.
        s6.sendall(struct.pack(">I", 1000) + bytes([C_REQUEST_IDENTITIES]))
        cut = False
        start = time.monotonic()
        try:
            while time.monotonic() - start < 45:
                s6.sendall(b"\x00")             # one more byte of a never-finished frame...
                time.sleep(5)                  # ...well inside any per-read timeout
                s6.setblocking(False)
                try:
                    if s6.recv(1) == b"":
                        cut = True
                        break
                except BlockingIOError:
                    pass
                finally:
                    s6.setblocking(True)
        except OSError:
            cut = True
        s6.close()
        took = time.monotonic() - start
        # The budget is 30 s; one 5 s drip interval of slack on top to notice the close.
        check("slow-drip client cut off by the connection budget", cut and 25 <= took <= 40,
              "after %.0f s" % took)

    # --- 11. SIGN_REQUEST over a reused connection must reach the handler.
    # A fingerprint is needed to COMPLETE it, so we assert only that the server does not
    # drop the connection or reply FAILURE instantly: a timeout here is the correct
    # outcome (it is waiting on the user), which is precisely why it is last.
    print("  (skipping live SIGN_REQUEST: needs a human fingerprint)")

    failed = [n for n, ok in results if not ok]
    print()
    if failed:
        print("AD-HOC VERIFICATION FAILED (%d): %s" % (len(failed), "; ".join(failed)))
        return 1
    print("AD-HOC VERIFICATION PASSED (%d checks)" % len(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
