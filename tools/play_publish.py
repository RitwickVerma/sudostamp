#!/usr/bin/env python3
"""Publish a signed app bundle and the store listing to Google Play (Android Publisher API v3).

    play_publish.py --credentials SA.json --bundle app.aab --version 1.4.1 [--track production]
                    [--listing fastlane/metadata/android/en-US] [--dry-run]

Run by `scripts/release.sh ship` on the maintainer's machine, never in CI. In one edit, it uploads
the bundle, sets the track's release (with the store notes for its versionCode), and replaces the
en-US listing -- title, descriptions, icon, feature graphic, phone screenshots -- with the files in
the repository, so Play shows exactly what the repository holds. Then it commits the edit.

Python standard library plus the `openssl` command, for the service account's RS256 signature:
nothing to install, nothing new in the supply chain. The private key is written only to a
0600 file in $XDG_RUNTIME_DIR (tmpfs) for the one `openssl` call, then deleted.

--dry-run signs a token locally and checks every file, without any network call.
"""
import argparse
import base64
import glob
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

PACKAGE = "com.ritwick.sudostamp"
API = "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/" + PACKAGE
UPLOAD = "https://androidpublisher.googleapis.com/upload/androidpublisher/v3/applications/" + PACKAGE
SCOPE = "https://www.googleapis.com/auth/androidpublisher"


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwt(sa):
    """The signed assertion a service account exchanges for an access token."""
    now = int(time.time())
    head = b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    claims = b64url(json.dumps({"iss": sa["client_email"], "scope": SCOPE, "aud": sa["token_uri"],
                                "iat": now, "exp": now + 3600}).encode())
    msg = (head + "." + claims).encode()
    rundir = os.environ.get("XDG_RUNTIME_DIR") or "/dev/shm"
    fd, keyfile = tempfile.mkstemp(dir=rundir, prefix="sudostamp-play-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(sa["private_key"])
        sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", keyfile], input=msg,
                             capture_output=True, check=True).stdout
    finally:
        os.unlink(keyfile)
    return head + "." + claims + "." + b64url(sig)


def call(method, url, token=None, body=None, ctype="application/json", data=None):
    headers = {"Content-Type": ctype}
    if token:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        sys.exit("play: %s %s -> %d %s" % (method, url.split("?")[0], e.code, e.read().decode("utf-8", "replace")[:600]))
    return json.loads(raw) if raw else {}


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read().strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--credentials", required=True)
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--track", default="production")
    ap.add_argument("--listing", default="fastlane/metadata/android/en-US")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    with open(a.credentials) as f:
        sa = json.load(f)
    for k in ("client_email", "private_key", "token_uri"):
        if k not in sa:
            sys.exit("play: the credentials file has no %s (is it a service account key?)" % k)
    L = a.listing
    listing = {"language": "en-US", "title": read(L + "/title.txt"),
               "shortDescription": read(L + "/short_description.txt"),
               "fullDescription": read(L + "/full_description.txt")}
    shots = sorted(glob.glob(L + "/images/phoneScreenshots/*.png"))
    images = [("icon", L + "/images/icon.png"), ("featureGraphic", L + "/images/featureGraphic.png")] + \
             [("phoneScreenshots", s) for s in shots]
    for _, p in images + [("bundle", a.bundle)]:
        if not os.path.isfile(p):
            sys.exit("play: missing " + p)
    assertion = jwt(sa)
    if a.dry_run:
        print("play: dry run ok -- token signed for %s; %d images; bundle %s" % (sa["client_email"], len(images), a.bundle))
        return

    tok = call("POST", sa["token_uri"], ctype="application/x-www-form-urlencoded",
               data=urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                            "assertion": assertion}).encode())["access_token"]
    edit = call("POST", API + "/edits", tok, body={})["id"]
    E = API + "/edits/" + edit
    U = UPLOAD + "/edits/" + edit

    with open(a.bundle, "rb") as f:
        code = call("POST", U + "/bundles?uploadType=media", tok, ctype="application/octet-stream", data=f.read())["versionCode"]
    print("play: uploaded bundle, versionCode %s" % code)
    notes_file = "%s/changelogs/%s.txt" % (L, code)
    notes = [{"language": "en-US", "text": read(notes_file)}] if os.path.isfile(notes_file) else []
    call("PUT", E + "/tracks/" + a.track, tok, body={"track": a.track, "releases": [
        {"name": "%s (%s)" % (a.version, code), "versionCodes": [str(code)], "status": "completed",
         "releaseNotes": notes}]})
    print("play: %s track -> %s (%s)" % (a.track, a.version, code))

    call("PUT", E + "/listings/en-US", tok, body=listing)
    for kind in ("icon", "featureGraphic", "phoneScreenshots"):
        call("DELETE", E + "/listings/en-US/" + kind, tok)
    for kind, p in images:
        with open(p, "rb") as f:
            call("POST", U + "/listings/en-US/%s?uploadType=media" % kind, tok, ctype="image/png", data=f.read())
    print("play: listing replaced from %s (%d images)" % (L, len(images)))

    call("POST", E + ":commit", tok)
    print("play: committed; Google reviews the release before it goes live")


if __name__ == "__main__":
    main()
