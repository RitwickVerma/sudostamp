#!/usr/bin/env python3
"""A SOCK_DGRAM Unix socket for the e2e test of the desktop events, tests ONLY.

    event_sink.py log  SOCKET LOGFILE [MODE]   append every datagram to LOGFILE, one per line
    event_sink.py full SOCKET                  never read; its queue is filled first, so the
                                               next sender would block (a stuck desktop app)

SOCKET is created with MODE (octal, default 600). Prints "ready" once it can be written to.
Run as the test user it stands in for the desktop app; run as root with MODE 600 it stands in
for a root daemon's socket (journald's native one), which a root-sent datagram could reach and
a user-sent one cannot.
"""
import os
import socket
import sys
import time


def main():
    mode, path = sys.argv[1], sys.argv[2]
    if os.path.lexists(path):
        os.unlink(path)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    if mode == "full":
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
    s.bind(path)
    os.chmod(path, int(sys.argv[4], 8) if len(sys.argv) > 4 else 0o600)
    if mode == "full":
        c = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        c.setblocking(False)
        sent = 0
        try:
            while True:
                c.sendto(b"x" * 900, path)
                sent += 1
        except BlockingIOError:
            pass
        print("ready (%d datagrams queued)" % sent, flush=True)
        while True:
            time.sleep(60)
    log = open(sys.argv[3], "ab", buffering=0)
    print("ready", flush=True)
    while True:
        data = s.recv(65536)
        log.write(data + b"\n")


if __name__ == "__main__":
    main()
