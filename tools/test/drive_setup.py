#!/usr/bin/env python3
"""Drive `install.sh setup --phone ADDR --json` the way the desktop app does, for the e2e test.

    drive_setup.py INSTALL_SH ADDR CODEFILE TRANSCRIPT [--wrong-code]

Reads stdout line by line, answers `ask` events (the code from CODEFILE, which the mock phone
writes in place of the person reading its screen; `yes` to confirmations) and checks the protocol
of docs/DESKTOP.md as it goes: every line one JSON object with "v": 1, a known shape, exactly one
final "done" and nothing after it. Prints `RESULT done=<true|false> attestation=<line>` (or
`PROTOCOL <what is wrong>`); exit 0 when the protocol held, whatever the outcome of the setup.
The raw stdout lines go to TRANSCRIPT.
"""
import json
import os
import subprocess
import sys
import time

STATUS = {"start", "ok", "fail"}


def main():
    install, addr, codefile, transcript = sys.argv[1:5]
    wrong = "--wrong-code" in sys.argv[5:]
    p = subprocess.Popen([install, "setup", "--phone", addr, "--json"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=open(transcript + ".stderr", "wb"))
    done = None
    asked = []
    steps = []
    problem = None
    deadline = time.time() + 900
    with open(transcript, "w") as log:
        for raw in p.stdout:
            log.write(raw.decode("utf-8", "replace"))
            log.flush()
            try:
                ev = json.loads(raw.decode("utf-8"))
            except ValueError:
                problem = "not JSON: %r" % raw
                break
            if not isinstance(ev, dict) or ev.get("v") != 1:
                problem = "no v:1: %r" % raw
                break
            if done is not None:
                problem = "output after done: %r" % raw
                break
            if "step" in ev:
                if ev.get("status") not in STATUS or not isinstance(ev.get("step"), str) \
                        or not isinstance(ev.get("text"), str):
                    problem = "bad step event: %r" % raw
                    break
                steps.append((ev["step"], ev["status"]))
            elif "ask" in ev:
                if ev["ask"] not in ("code", "confirm") or not isinstance(ev.get("text"), str):
                    problem = "bad ask event: %r" % raw
                    break
                asked.append(ev["ask"])
                if ev["ask"] == "code":
                    while not (os.path.exists(codefile) and os.path.getsize(codefile)) and time.time() < deadline:
                        time.sleep(0.1)
                    code = open(codefile).read().strip()
                    answer = ("000000" if code != "000000" else "111111") if wrong else code
                else:
                    answer = "yes"
                p.stdin.write((answer + "\n").encode())
                p.stdin.flush()
            elif "done" in ev:
                if not isinstance(ev["done"], bool) or not isinstance(ev.get("attestation"), str) \
                        or not isinstance(ev.get("phone"), str) or not isinstance(ev.get("text"), str):
                    problem = "bad done event: %r" % raw
                    break
                done = ev
            else:
                problem = "unknown event: %r" % raw
                break
            if time.time() > deadline:
                problem = "timed out"
                break
    if problem is None and done is None:
        problem = "no final done event"
    if problem:
        p.kill()
        print("PROTOCOL", problem)
        return 1
    p.stdin.close()
    rc = p.wait()
    print("RESULT done=%s attestation=%s exit=%d asked=%s steps=%s" % (
        "true" if done["done"] else "false", done["attestation"], rc, ",".join(asked),
        ",".join("%s:%s" % s for s in steps)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
