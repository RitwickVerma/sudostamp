#!/usr/bin/env python3
"""Build SudoStamp's site (https://sudostamp.ritwickverma.dev) into site/out/.

    python3 -I site/build.py            build
    python3 -I site/build.py --check    build, then check what must hold (CI)

The site is the app's own, owned by this repository and nothing else (not the developer's
portfolio): the pairing link's landing page, the app-link proof Android checks before the camera
may open that link in the app (.well-known/assetlinks.json), and the privacy policy, rendered from
docs/PRIVACY_POLICY.md so the two cannot drift. Standard library only; no third-party code on the
pages, and a Content-Security-Policy (static/_headers) that would refuse any.
"""
import html
import json
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(HERE, "out")
PACKAGE = "com.ritwick.sudostamp"


def inline(text):
    """Escape, then the little markdown the policy uses: `code`, **bold**, URLs and emails."""
    t = html.escape(text, quote=False)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"(?<![\w/\"])(https://[A-Za-z0-9./_~%-]*[A-Za-z0-9/_~%-])", r'<a href="\1">\1</a>', t)
    t = re.sub(r"\b([\w.+-]+@[\w-]+\.[\w.-]*\w)\b", r'<a href="mailto:\1">\1</a>', t)
    return t


def markdown(md):
    """Headings, paragraphs and pipe tables: exactly the shapes PRIVACY_POLICY.md has. Anything
    else is a build error, not a silent mangling."""
    out, para, rows = [], [], []

    def flush():
        if para:
            out.append("<p>%s</p>" % inline(" ".join(para)))
            para.clear()
        if rows:
            head, body = rows[0], rows[2:]
            if not re.fullmatch(r"\|(\s*-+\s*\|)+", rows[1].replace(" ", "")):
                raise SystemExit("table without a separator row")
            cells = lambda r: [c.strip() for c in r.strip().strip("|").split("|")]
            out.append('<div class="table"><table><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>' % (
                "".join("<th>%s</th>" % inline(c) for c in cells(head)),
                "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % inline(c) for c in cells(r)) for r in body)))
            rows.clear()

    for line in md.splitlines():
        s = line.rstrip()
        if not s:
            flush()
        elif s.startswith("|"):
            if para:
                flush()
            rows.append(s)
        elif s.startswith("## "):
            flush()
            out.append("<h2>%s</h2>" % inline(s[3:]))
        elif s.startswith("# "):
            flush()
            out.append("<h1>%s</h1>" % inline(s[2:]))
        elif s.startswith(("#", "- ", "* ", "1. ", ">", "```")):
            raise SystemExit("PRIVACY_POLICY.md: unsupported markdown here, extend site/build.py: %r" % s)
        else:
            if rows:
                flush()
            para.append(s)
    flush()
    return "\n".join(out)


def build():
    shutil.rmtree(OUT, ignore_errors=True)
    shutil.copytree(os.path.join(HERE, "static"), OUT)
    with open(os.path.join(ROOT, "docs", "PRIVACY_POLICY.md"), encoding="utf-8") as f:
        body = markdown(f.read())
    with open(os.path.join(OUT, "index.html"), encoding="utf-8") as f:
        page = f.read()
    # The home page's frame (head, brand, footer) around the policy.
    head = page[:page.index("<main>") + len("<main>")]
    brand = re.search(r'<header class="brand">.*?</header>', page, re.S).group(0)
    footer = re.search(r"<footer>.*?</footer>", page, re.S).group(0)
    head = re.sub(r"<title>.*?</title>", "<title>Privacy Policy · SudoStamp</title>", head)
    head = re.sub(r'<meta name="description" content="[^"]*">',
                  '<meta name="description" content="What SudoStamp does with your data: nothing leaves your phone and your own network.">', head)
    os.makedirs(os.path.join(OUT, "privacy-policy"))
    with open(os.path.join(OUT, "privacy-policy", "index.html"), "w", encoding="utf-8") as f:
        f.write("%s\n%s\n%s\n%s\n</main>\n</body>\n</html>\n" % (head, brand, body, footer))


def check():
    problems = []
    # The app-link proof names the certificate the app is really signed with (release.sh pins it).
    with open(os.path.join(ROOT, "scripts", "release.sh"), encoding="utf-8") as f:
        cert = re.search(r'^RELEASE_CERT="([0-9A-F:]{95})"', f.read(), re.M).group(1)
    with open(os.path.join(OUT, ".well-known", "assetlinks.json"), encoding="utf-8") as f:
        links = json.load(f)
    targets = [s["target"] for s in links if "delegate_permission/common.handle_all_urls" in s["relation"]]
    if targets != [{"namespace": "android_app", "package_name": PACKAGE, "sha256_cert_fingerprints": [cert]}]:
        problems.append("assetlinks.json does not name exactly %s signed by %s" % (PACKAGE, cert))
    # The host the app trusts is the host this site is.
    with open(os.path.join(ROOT, "app", "src", "main", "java", "com", "ritwick", "sudostamp", "QrLink.kt")) as f:
        host = re.search(r'const val HOST = "([^"]+)"', f.read()).group(1)
    with open(os.path.join(ROOT, "app", "src", "main", "AndroidManifest.xml")) as f:
        manifest = f.read()
    if 'android:host="%s"' % host not in manifest or 'android:autoVerify="true"' not in manifest:
        problems.append("the manifest does not verify %s" % host)
    # The headers that protect the pages (static/_headers): what the site promises the browser.
    with open(os.path.join(OUT, "_headers"), encoding="utf-8") as f:
        headers = f.read()
    for want in ("Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'",
                 "Referrer-Policy: no-referrer", "X-Content-Type-Options: nosniff", "frame-ancestors 'none'",
                 "/.well-known/assetlinks.json\n  Content-Type: application/json"):
        if want not in headers:
            problems.append("_headers lost: %s" % want.split("\n")[0])
    with open(os.path.join(OUT, "pair", "pair.js"), encoding="utf-8") as f:
        js = f.read()
    if '"intent://%s/pair?k="' % host not in js or "location.host" in js:
        problems.append("pair.js must open the app on %s itself, never on whatever host served it" % host)
    # Every word of the policy reaches the page.
    with open(os.path.join(ROOT, "docs", "PRIVACY_POLICY.md"), encoding="utf-8") as f:
        words = set(re.findall(r"[A-Za-z]{4,}", f.read()))
    with open(os.path.join(OUT, "privacy-policy", "index.html"), encoding="utf-8") as f:
        page = html.unescape(re.sub(r"<[^>]+>", " ", f.read()))
    missing = sorted(w for w in words if w not in page)
    if missing:
        problems.append("words of the policy missing from its page: %s" % missing[:10])
    # Nothing from anywhere else: no external script, style, image or font, no inline script.
    for dirpath, _, files in os.walk(OUT):
        for name in files:
            if not name.endswith(".html"):
                continue
            with open(os.path.join(dirpath, name), encoding="utf-8") as f:
                text = f.read()
            if re.search(r'<(script|link|img)[^>]+(src|href)="(https?:)?//', text) or \
                    re.search(r"<script(?![^>]*\bsrc=)[^>]*>", text) or re.search(r'\sstyle="', text):
                problems.append("%s loads something from elsewhere, or inline script/style" % name)
    for p in problems:
        print("site: " + p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    build()
    sys.exit(check() if "--check" in sys.argv[1:] else 0)
