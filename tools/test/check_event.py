#!/usr/bin/env python3
"""Check the datagrams the probe sent (tools/test/event_sink.py wrote one per line), e2e only.

    check_event.py LOG --events asking[,not-approved...] [--pid P] [--command FRAG]
                       [--phone ADDR] [--reason R] [--command-len LO-HI]

Fails (exit 1, with the reason) unless LOG holds exactly the named events, in order, and each one
is what docs/DESKTOP.md specifies: UTF-8 JSON of at most 2048 bytes with exactly the fields
v event sudo_pid tty command [reason] phone ts, of the right types, `reason` only on `skipped`,
`command` without control characters and within 512 characters.
"""
import argparse
import json
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--events", default="")
    ap.add_argument("--pid", type=int)
    ap.add_argument("--command")
    ap.add_argument("--phone")
    ap.add_argument("--reason")
    ap.add_argument("--command-len", help="LO-HI characters, e.g. 512-512")
    a = ap.parse_args()
    try:
        raw = open(a.log, "rb").read()
    except OSError:
        raw = b""
    lines = [l for l in raw.split(b"\n") if l]
    want = [e for e in a.events.split(",") if e]
    bad = []
    got = []
    for l in lines:
        if len(l) > 2048:
            bad.append("datagram of %d bytes" % len(l))
        try:
            ev = json.loads(l.decode("utf-8"))
        except ValueError:
            bad.append("not UTF-8 JSON: %r" % l[:80])
            continue
        got.append(ev.get("event"))
        fields = {"v", "event", "sudo_pid", "tty", "command", "phone", "ts"}
        if ev.get("event") == "skipped":
            fields.add("reason")
        if set(ev) != fields:
            bad.append("fields %s, want %s" % (sorted(ev), sorted(fields)))
            continue
        if ev["v"] != 1 or ev["event"] not in ("asking", "skipped", "not-approved"):
            bad.append("v/event: %r" % ev)
        if not isinstance(ev["sudo_pid"], int) or isinstance(ev["sudo_pid"], bool):
            bad.append("sudo_pid type")
        if not isinstance(ev["ts"], int) or abs(ev["ts"] - time.time()) > 300:
            bad.append("ts: %r" % ev["ts"])
        for k in ("tty", "command", "phone"):
            if not isinstance(ev[k], str):
                bad.append("%s type" % k)
        if isinstance(ev["command"], str):
            lo, hi = (int(x) for x in (a.command_len or "0-512").split("-"))
            if not lo <= len(ev["command"]) <= hi:
                bad.append("command of %d chars, want %d-%d" % (len(ev["command"]), lo, hi))
            if any(ord(c) < 32 or ord(c) == 127 for c in ev["command"]):
                bad.append("control character in command")
            if a.command is not None and a.command not in ev["command"]:
                bad.append("command %r lacks %r" % (ev["command"], a.command))
        if a.pid is not None and ev["sudo_pid"] != a.pid:
            bad.append("sudo_pid %r, want %d" % (ev["sudo_pid"], a.pid))
        if a.phone is not None and ev["phone"] != a.phone:
            bad.append("phone %r, want %r" % (ev["phone"], a.phone))
        if a.reason is not None and ev.get("reason") != a.reason and ev["event"] == "skipped":
            bad.append("reason %r, want %r" % (ev.get("reason"), a.reason))
    if got != want:
        bad.append("events %s, want %s" % (got, want))
    if bad:
        print("; ".join(bad))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
