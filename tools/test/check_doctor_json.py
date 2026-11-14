#!/usr/bin/env python3
"""Check one `install.sh doctor --json` run against docs/DESKTOP.md, e2e only.

    check_doctor_json.py JSON_FILE --exit N [--plain PLAIN_LOG] [--needs-root]

JSON_FILE: exactly {"v":1,"checks":[...],"exit":N}; each check exactly id/status/text/fix
(strings; status ok|warn|fail; a fix on every check that is not ok); ids from the stable set;
"exit" equal to --exit and to what the statuses say (a fail: 1, else a warn: 2, else 0). With
--plain: the same number of OK/WARN/FAIL lines as the plain doctor printed. With --needs-root:
a warn whose text says "needs root", and no fail.
"""
import argparse
import json
import re
import sys

IDS = {"platform", "user", "pam-block", "pam-foreign", "pam-rssh", "helper-probe", "helper-is-local",
       "local-reader", "pinned-key", "phone", "sudoers", "scratch-pam"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--exit", type=int, required=True)
    ap.add_argument("--plain")
    ap.add_argument("--needs-root", action="store_true")
    a = ap.parse_args()
    bad = []
    try:
        doc = json.loads(open(a.file, "rb").read().decode("utf-8"))
    except ValueError as e:
        print("not UTF-8 JSON:", e)
        return 1
    if not isinstance(doc, dict) or set(doc) != {"v", "checks", "exit"} or doc["v"] != 1:
        print("top level: %r" % (doc if not isinstance(doc, dict) else sorted(doc)))
        return 1
    seen = []
    for c in doc["checks"]:
        if not isinstance(c, dict) or set(c) != {"id", "status", "text", "fix"}:
            bad.append("check fields: %r" % c)
            continue
        if not all(isinstance(c[k], str) for k in c) or c["status"] not in ("ok", "warn", "fail") \
                or c["id"] not in IDS or not c["text"]:
            bad.append("check values: %r" % c)
        if c["status"] != "ok" and not c["fix"]:
            bad.append("no fix: %r" % c)
        seen.append(c["status"])
    want = 1 if "fail" in seen else 2 if "warn" in seen else 0
    if doc["exit"] != want or doc["exit"] != a.exit:
        bad.append("exit %r, statuses say %d, process said %d" % (doc["exit"], want, a.exit))
    for need in ("platform", "pam-block", "pam-rssh", "helper-probe", "pinned-key", "phone"):
        if need not in [c["id"] for c in doc["checks"] if isinstance(c, dict)]:
            bad.append("no check with id %s" % need)
    if a.plain:
        text = re.sub(r"\x1b\[[0-9;]*m", "", open(a.plain, errors="replace").read())
        for st, word in (("ok", "OK"), ("warn", "WARN"), ("fail", "FAIL")):
            n = len(re.findall(r"^\s+%s\s" % word, text, re.M))
            if n != seen.count(st):
                bad.append("plain doctor printed %d %s, JSON has %d" % (n, word, seen.count(st)))
    if a.needs_root:
        if "fail" in seen:
            bad.append("a fail without root")
        if not any(c["status"] == "warn" and "needs root" in c["text"] for c in doc["checks"]):
            bad.append("no 'needs root' warning")
    if bad:
        print("; ".join(bad))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
