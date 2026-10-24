#!/usr/bin/env python3
"""Fail a commit (or a CI run) that carries a credential.

Two modes:

  as a pre-commit hook   python3 tools/check-secrets.py --staged
  over a whole tree      python3 tools/check-secrets.py --all

Exit code 0 = clean, 1 = findings (each printed with file, line and a redacted
match). Designed for GitLab's free tier, where server-side secret push
protection is not available.

Scope note: this is a seatbelt, not a guarantee. It catches known shapes and
any `key = "long-literal"` assignment. It cannot catch a novel format, and it
deliberately does not flag short or high-entropy-free strings.
"""
import argparse
import os
import re
import subprocess
import sys

PATTERNS = [
    ("gitlab token", re.compile(rb"glpat-[A-Za-z0-9_\-]{20}")),
    ("gitlab runner token", re.compile(rb"glrt-[A-Za-z0-9_\-]{20}")),
    ("github token", re.compile(rb"gh[pousr]_[A-Za-z0-9]{36}")),
    ("aws access key", re.compile(rb"(AKIA|ASIA)[0-9A-Z]{16}")),
    ("private key block", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("openai-style key", re.compile(rb"sk-[A-Za-z0-9]{20,}")),
    ("slack/discord webhook", re.compile(rb"https://(hooks\.slack\.com|discord(app)?\.com/api/webhooks)/\S+")),
    ("google api key", re.compile(rb"AIza[0-9A-Za-z_\-]{35}")),
    ("jwt", re.compile(rb"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    # This project's own secrets: the age key that opens the signing vault, and the vault's
    # decrypted form (dotenv, unquoted) -- the shapes a slip during a release would produce.
    ("age secret key", re.compile(rb"AGE-SECRET-KEY-1[0-9A-Z]{50,}")),
    ("signing vault entry", re.compile(
        rb"(?m)^\s*(KEYSTORE_JKS_B64|STORE_PASSWORD|KEY_PASSWORD|INSTALLER_KEY_B64)\s*=\s*[^\s\"'$]{6,}")),
    # Quoted literals; also camelCase names (storePassword, keyPassword), which a leading \b
    # before "pass" never matched.
    ("assignment with literal", re.compile(
        rb"(?i)(\b|_|(?<=[a-z]))(pass(word|wd|phrase)?|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)"
        rb"\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']")),
    # Unquoted: KEY_PASSWORD=hunter22, password: hunter22 (dotenv, YAML, properties).
    ("unquoted credential assignment", re.compile(
        rb"(?im)^\s*[A-Z0-9_.-]*(password|passwd|secret|api_?key|token)\s*[:=][ \t]*"
        rb"(?![A-Za-z_][A-Za-z0-9_.]*\()[^\s\"'$({<][^\s]{7,}$")),   # not a call: getenv(...)
]

# Never committed, whatever they contain: a keystore is binary, so no pattern sees inside it.
FORBIDDEN_EXT = (".jks", ".keystore", ".p12", ".pfx", ".pem", ".key", ".age")

# Paths that are allowed to contain pattern text (this scanner's own pattern list,
# test fixtures that assert a scanner rejects something, etc).
ALLOWLIST_PATHS = (
    "tools/check-secrets.py",
)
ALLOWLIST_MARKERS = (b"allowlist-secret", b"EXAMPLE_NOT_A_SECRET", b"placeholder")

# Not scanned as text. (.pem and .p12 are not here: they are refused outright, above.)
BINARY_EXT = (".png", ".jpg", ".jpeg", ".webp", ".bin", ".jar", ".apk", ".zip", ".pdf")


def scan_bytes(data, label, out):
    for name, rx in PATTERNS:
        for m in rx.finditer(data):
            hit = m.group(0)
            if any(marker in hit for marker in ALLOWLIST_MARKERS):
                continue
            line = data[:m.start()].count(b"\n") + 1
            safe = hit[:24].decode("utf-8", "replace")
            out.append(f"{label}:{line}: {name}: {safe}…")


def forbidden(all_files, out):
    for p in all_files:
        if p.lower().endswith(FORBIDDEN_EXT):
            out.append(f"{p}: key or keystore file -- never committed")


def scanned_paths(all_files):
    for p in all_files:
        if p.endswith(BINARY_EXT) or "/.git/" in f"/{p}":
            continue
        if any(p.startswith(a) for a in ALLOWLIST_PATHS):
            continue
        yield p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="scan every tracked file")
    ap.add_argument("--staged", action="store_true", help="scan staged content (pre-commit)")
    args = ap.parse_args()
    if not (args.all or args.staged):
        args.staged = True

    findings = []

    if args.all:
        files = [f.decode() for f in subprocess.run(["git", "ls-files", "-z"], capture_output=True).stdout.split(b"\0") if f]
        forbidden(files, findings)
        for p in scanned_paths(files):
            try:
                with open(p, "rb") as f:
                    scan_bytes(f.read(), p, findings)
            except OSError:
                pass
        print(f"scanned {len(files)} tracked files")

    if args.staged:
        files = subprocess.run(["git", "diff", "--cached", "--name-only", "-z"],
                               capture_output=True).stdout.split(b"\0")
        files = [f.decode() for f in files if f]
        forbidden(files, findings)
        for p in scanned_paths(files):
            blob = subprocess.run(["git", "show", f":{p}"], capture_output=True).stdout
            scan_bytes(blob, p, findings)
        print(f"scanned {len(files)} staged paths")

    if findings:
        print("\nBLOCKED — credential-shaped content found:")
        for f in sorted(set(findings)):
            print("  " + f)
        print("\nIf this is a false positive, add an `allowlist-secret` marker on that line,")
        print("or add the path to ALLOWLIST_PATHS in tools/check-secrets.py.")
        return 1

    print("clean — no credential-shaped content")
    return 0


if __name__ == "__main__":
    sys.exit(main())
