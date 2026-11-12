#!/usr/bin/env python3
"""CycloneDX 1.5 SBOMs for the two things a SudoStamp release ships. Python standard library only.

    scripts/sbom.py apk  APK   [--version X.Y.Z] [-o FILE]
        The phone app. The subject (metadata.component) is the APK: version and SHA-256. The
        APP HAS NO RUNTIME DEPENDENCIES, and the document says so three ways: the subject has an
        empty `dependsOn`, a `compositions` entry marks that list complete, and every component
        below is `scope: excluded`: what the build used and the shipped APK does not contain.
        Those are everything gradle/verification-metadata.xml pins (each artifact by SHA-256),
        the Gradle distribution (pinned by distributionSha256Sum), and the Android command-line
        tools (pinned in scripts/ci-setup-sdk.sh), plus the unpinned-by-hash SDK parts and the JDK.

    scripts/sbom.py host SETUP_SH [--version X.Y.Z] [--cargo-lock FILE] [-o FILE]
        The host installer (dist/sudostamp-setup.sh). Its only third-party code is pam_rssh,
        which it builds from the commit pinned in tools/install.sh, and the crates in that
        commit's Cargo.lock (what `cargo build --locked` compiles into a module that runs as
        root in sudo's PAM stack, so all `scope: required`). The Cargo.lock comes from the
        commit's own URL, or --cargo-lock; either way it must have the SHA-256 pinned below, so a
        moved or tampered file stops the release instead of landing in the SBOM.

    scripts/sbom.py check FILE...
        Validates the shape of CycloneDX documents this script writes (exit 1 on a fault).

    scripts/sbom.py names FILE SHA256
        Exit 0 only if FILE's subject carries that SHA-256 (the SBOM describes those bytes).

Deterministic: the same inputs give the same bytes (serial number derived from the content,
timestamp from SOURCE_DATE_EPOCH or the last commit), so a reproducible APK has a reproducible SBOM.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
import uuid
import xml.etree.ElementTree as ET

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
PROJECT_URL = "https://gitlab.com/ritwick7/sudostamp"
APP_ID = "com.ritwick.sudostamp"
GRADLE_NS = {"g": "https://schema.gradle.org/dependency-verification"}

# SHA-256 of the Cargo.lock of pam_rssh at the commit tools/install.sh pins (RSSH_COMMIT).
# Bumping that commit means re-deriving this from the new commit's Cargo.lock and reviewing
# the crate changes: until then `sbom.py host` fails, which is the point.
PAM_RSSH_CARGO_LOCK_SHA256 = "9b40a9b4a50e7a6da301e6a535a8eac48bc137b2c62bb0880510832bec0bfb5c"

SPEC_VERSION = "1.5"
COMPONENT_TYPES = {"application", "framework", "library", "container", "platform", "operating-system", "device",
                   "device-driver", "firmware", "file", "machine-learning-model", "data"}
HASH_LENGTHS = {"MD5": 32, "SHA-1": 40, "SHA-256": 64, "SHA-384": 96, "SHA-512": 128}
SCOPES = {"required", "optional", "excluded"}


def die(msg):
    sys.exit("sbom: %s" % msg)


def read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        return f.read()


def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        die("cannot read %s: %s" % (path, e))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def must(pattern, text, what):
    m = re.search(pattern, text, re.M)
    if not m:
        die("cannot find %s" % what)
    return m.group(1)


def app_version():
    return must(r'^\s*versionName = "([^"]+)"', read("app/build.gradle.kts"), "versionName in app/build.gradle.kts")


def timestamp():
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if not epoch:
        try:
            epoch = subprocess.run(["git", "-C", ROOT, "log", "-1", "--format=%ct"], capture_output=True, text=True,
                                   check=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            epoch = ""
    secs = int(epoch) if epoch.isdigit() else int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    return datetime.datetime.fromtimestamp(secs, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def serial(*parts):
    return "urn:uuid:%s" % uuid.uuid5(uuid.NAMESPACE_URL, "sudostamp-sbom:" + ":".join(parts))


def sha256_hash(hexdigest):
    return {"alg": "SHA-256", "content": hexdigest}


def envelope(subject, components, dependencies, compositions, serial_number):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": timestamp(),
            "lifecycles": [{"phase": "build"}],
            "tools": {"components": [{"type": "application", "name": "scripts/sbom.py", "version": "1",
                                      "description": "SudoStamp's own generator: Python standard library only"}]},
            "authors": [{"name": "Ritwick Verma"}],
            "component": subject,
        },
        "components": components,
        "dependencies": dependencies,
        "compositions": compositions,
    }


def subject_component(bom_ref, name, version, sha256, description, props):
    return {
        "type": "application",
        "bom-ref": bom_ref,
        "supplier": {"name": "Ritwick Verma", "url": [PROJECT_URL]},
        "name": name,
        "version": version,
        "description": description,
        "hashes": [sha256_hash(sha256)],
        "licenses": [{"license": {"id": "MIT"}}],
        "purl": bom_ref,
        "externalReferences": [{"type": "vcs", "url": PROJECT_URL}, {"type": "website", "url": PROJECT_URL}],
        "properties": [{"name": k, "value": v} for k, v in props],
    }


# ------------------------------------------------------------------ the APK

def purl_maven(group, name, version):
    return "pkg:maven/%s/%s@%s" % (group, name, version)


def gradle_components():
    """Every component gradle/verification-metadata.xml pins, as an excluded (build-time) library."""
    # The file is this repository's own (reviewed in every diff), not input from anyone else, so the
    # standard library parser is enough: no entity expansion or external fetch is wanted or reachable.
    root = ET.parse(os.path.join(ROOT, "gradle", "verification-metadata.xml")).getroot()
    out = {}
    for c in root.findall("g:components/g:component", GRADLE_NS):
        group, name, version = c.get("group"), c.get("name"), c.get("version")
        arts = [(a.get("name"), a.find("g:sha256", GRADLE_NS).get("value")) for a in c.findall("g:artifact", GRADLE_NS)
                if a.find("g:sha256", GRADLE_NS) is not None]
        if not arts:
            die("%s:%s:%s is pinned with no SHA-256" % (group, name, version))
        # The code is the .jar/.aar; a component that only has a .pom/.module (a BOM, a platform) is
        # described by that file.
        primary = next((a for a in arts if a[0].endswith((".jar", ".aar", ".klib"))), None) \
            or next((a for a in arts if not a[0].endswith(".pom")), arts[0])
        ref = purl_maven(group, name, version)
        comp = {
            "type": "library",
            "bom-ref": ref,
            "group": group,
            "name": name,
            "version": version,
            "scope": "excluded",
            "hashes": [sha256_hash(primary[1])],
            "purl": ref,
            "properties": [{"name": "gradle:artifact:" + n, "value": h} for n, h in arts],
        }
        if ref in out:
            die("duplicate pinned component %s" % ref)
        out[ref] = comp
    return [out[k] for k in sorted(out)]


def tool_components():
    """The rest of the toolchain, named as exactly as the repository pins it."""
    wrapper = read("gradle/wrapper/gradle-wrapper.properties")
    gradle_version = must(r"distributionUrl=.*gradle-([0-9][^-]*)-", wrapper, "the Gradle version")
    gradle_sha = must(r"^distributionSha256Sum=([0-9a-f]{64})$", wrapper, "distributionSha256Sum")
    sdk = read("scripts/ci-setup-sdk.sh")
    tools_version = must(r'CMDLINE_TOOLS_VERSION="\$\{CMDLINE_TOOLS_VERSION:-([0-9]+)\}"', sdk, "CMDLINE_TOOLS_VERSION")
    tools_sha = must(r'CMDLINE_TOOLS_SHA256="\$\{CMDLINE_TOOLS_SHA256:-([0-9a-f]{64})\}"', sdk, "CMDLINE_TOOLS_SHA256")
    build_tools = must(r'SDK_BUILD_TOOLS="\$\{SDK_BUILD_TOOLS:-([0-9.]+)\}"', sdk, "SDK_BUILD_TOOLS")
    platform = must(r'SDK_PLATFORM="\$\{SDK_PLATFORM:-([0-9]+)\}"', sdk, "SDK_PLATFORM")
    image = must(r"^image: (\S+)$", read(".gitlab-ci.yml"), "the CI image")

    def tool(ref, name, version, desc, sha=None, kind="application"):
        c = {"type": kind, "bom-ref": ref, "name": name, "version": version, "scope": "excluded", "description": desc,
             "purl": ref}
        if sha:
            c["hashes"] = [sha256_hash(sha)]
        return c

    return [
        tool("pkg:generic/gradle@" + gradle_version, "gradle", gradle_version,
             "Gradle distribution; gradle-wrapper.properties pins its SHA-256", gradle_sha),
        tool("pkg:generic/android-commandlinetools@" + tools_version, "android-commandlinetools", tools_version,
             "Android command-line tools; scripts/ci-setup-sdk.sh pins the zip's SHA-256", tools_sha),
        tool("pkg:generic/android-build-tools@" + build_tools, "android-build-tools", build_tools,
             "aapt2, d8, apksigner; installed by sdkmanager at the version scripts/ci-setup-sdk.sh names"),
        tool("pkg:generic/android-platform@android-" + platform, "android-platform", "android-" + platform,
             "android.jar the app compiles against; not part of the APK", kind="platform"),
        tool("pkg:generic/jdk-container-image@" + image, "jdk-container-image", image,
             "The JDK 17 image CI builds in (.gitlab-ci.yml `image:`); release.sh uses the maintainer's JDK 17",
             kind="container"),
    ]


def apk_bom(apk_path, version):
    sha = sha256_file(apk_path)
    ref = "pkg:generic/%s@%s" % (APP_ID, version)
    subject = subject_component(ref, "SudoStamp", version, sha,
                                "Approves sudo on a Linux computer with the phone's fingerprint (ssh-agent over the LAN).",
                                [("sudostamp:apk-file", os.path.basename(apk_path)),
                                 ("sudostamp:runtime-dependencies", "0"),
                                 ("sudostamp:policy", "no third-party runtime dependencies; no AndroidX")])
    components = tool_components() + gradle_components()
    return envelope(
        subject, components,
        [{"ref": ref, "dependsOn": []}],
        # "complete": the dependency list of the app above is all of it, and it is empty.
        [{"aggregate": "complete", "dependencies": [ref]}],
        serial("apk", version, sha))


# ------------------------------------------------------------------ the host installer

def install_pins():
    text = read("tools/install.sh")
    return (must(r'^RSSH_REPO="([^"]+)"', text, "RSSH_REPO"), must(r'^RSSH_TAG="([^"]+)"', text, "RSSH_TAG"),
            must(r'^RSSH_COMMIT="([0-9a-f]{40})"', text, "RSSH_COMMIT"),
            must(r"^CARGO_MIN_MINOR=([0-9]+)", text, "CARGO_MIN_MINOR"),
            must(r'^PATCH_SHA256="([0-9a-f]{64})"', text, "PATCH_SHA256"))


def cargo_lock_url(commit):
    return "https://raw.githubusercontent.com/z4yx/pam_rssh/%s/Cargo.lock" % commit


def fetch_cargo_lock(commit):
    try:
        with urllib.request.urlopen(cargo_lock_url(commit), timeout=60) as r:
            return r.read()
    except OSError as e:
        die("cannot fetch pam_rssh's Cargo.lock at %s: %s (or pass --cargo-lock FILE)" % (commit, e))


def crate_purl(name, version, source):
    if source and source.startswith("git+"):
        url, _, rev = source[4:].partition("#")
        return "pkg:cargo/%s@%s?vcs_url=%s" % (name, version, url.split("?")[0] + ("@" + rev if rev else ""))
    return "pkg:cargo/%s@%s" % (name, version)


def cargo_components(lock_bytes, pam_ref):
    """(components, dependencies) from a Cargo.lock. The root package is pam_rssh itself."""
    try:
        import tomllib
    except ImportError:
        die("Python 3.11 or newer is needed to read Cargo.lock (tomllib)")
    data = tomllib.loads(lock_bytes.decode("utf-8"))
    pkgs = data.get("package", [])
    if not pkgs:
        die("the Cargo.lock lists no packages")
    by_name = {}
    for p in pkgs:
        by_name.setdefault(p["name"], []).append(p)

    def ref_of(p):
        return pam_ref if p.get("source") is None and p["name"] == "pam_rssh" else crate_purl(p["name"], p["version"], p.get("source"))

    def resolve(dep):
        # "name", "name version" or "name version (source)": Cargo.lock writes the long form only
        # when the short one would be ambiguous.
        parts = dep.split(" ")
        cands = by_name.get(parts[0], [])
        if len(parts) > 1:
            cands = [c for c in cands if c["version"] == parts[1]]
        if len(cands) != 1:
            die("cannot resolve dependency %r in Cargo.lock" % dep)
        return cands[0]

    comps, deps = [], []
    for p in pkgs:
        ref = ref_of(p)
        deps.append({"ref": ref, "dependsOn": sorted({ref_of(resolve(d)) for d in p.get("dependencies", [])})})
        if ref == pam_ref:
            continue
        c = {"type": "library", "bom-ref": ref, "name": p["name"], "version": p["version"], "scope": "required",
             "purl": ref}
        if p.get("checksum"):
            c["hashes"] = [sha256_hash(p["checksum"])]
        if p.get("source"):
            c["properties"] = [{"name": "cargo:source", "value": p["source"]}]
        comps.append(c)
    comps.sort(key=lambda c: c["bom-ref"])
    deps.sort(key=lambda d: d["ref"])
    return comps, deps


def host_bom(setup_path, version, lock_bytes):
    repo, tag, commit, min_minor, patch_sha = install_pins()
    lock_sha = hashlib.sha256(lock_bytes).hexdigest()
    if lock_sha != PAM_RSSH_CARGO_LOCK_SHA256:
        die("pam_rssh's Cargo.lock is %s, not the pinned %s (commit %s). A moved file, or a bumped commit: review the "
            "crate changes, then update PAM_RSSH_CARGO_LOCK_SHA256." % (lock_sha, PAM_RSSH_CARGO_LOCK_SHA256, commit))
    sha = sha256_file(setup_path)
    ref = "pkg:generic/sudostamp-setup@%s" % version
    subject = subject_component(ref, "sudostamp-setup.sh", version, sha,
                                "SudoStamp's host installer: pairs with the phone and adds it to sudo's PAM stack, "
                                "with the password still working.",
                                [("sudostamp:pam_rssh-source",
                                  "built from the pinned commit with cargo --locked; AUR and FreeBSD use the distribution package"),
                                 ("sudostamp:min-rust", "1.%s" % min_minor)])
    subject["type"] = "file"
    pam_ref = "pkg:github/z4yx/pam_rssh@%s" % commit
    crates, crate_deps = cargo_components(lock_bytes, pam_ref)
    pam = {
        "type": "library", "bom-ref": pam_ref, "name": "pam_rssh", "version": tag, "scope": "required",
        "description": "PAM module that authenticates through an ssh-agent; built from the commit tools/install.sh pins",
        "licenses": [{"license": {"id": "MIT"}}], "purl": pam_ref,
        # What runs is the pinned commit PLUS SudoStamp's timeouts patch (install.sh refuses to build
        # without it), so the patch is part of the pedigree, with the hash the build enforces.
        "pedigree": {"commits": [{"uid": commit, "url": repo[:-4] + "/commit/" + commit}],
                     "patches": [{"type": "unofficial",
                                  "diff": {"url": "tools/patches/pam_rssh-timeouts.patch"}}]},
        "externalReferences": [{"type": "vcs", "url": repo, "comment": "commit " + commit}],
        "properties": [{"name": "sudostamp:cargo-lock-sha256", "value": lock_sha},
                       {"name": "sudostamp:cargo-lock-url", "value": cargo_lock_url(commit)},
                       {"name": "sudostamp:patch-sha256", "value": patch_sha}],
    }
    dependencies = [{"ref": ref, "dependsOn": [pam_ref]}] + crate_deps
    return envelope(subject, [pam] + crates, dependencies,
                    [{"aggregate": "complete", "dependencies": [d["ref"] for d in dependencies]}],
                    serial("host", version, sha, lock_sha))


# ------------------------------------------------------------------ the shape checker

def validate(doc):
    """Returns a list of faults in a CycloneDX 1.5 document of the shape this script writes."""
    bad = []

    def need(cond, msg):
        if not cond:
            bad.append(msg)

    need(doc.get("bomFormat") == "CycloneDX", "bomFormat is not CycloneDX")
    need(doc.get("specVersion") == SPEC_VERSION, "specVersion is not " + SPEC_VERSION)
    need(re.fullmatch(r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", str(doc.get("serialNumber"))),
         "serialNumber is not a urn:uuid")
    need(isinstance(doc.get("version"), int) and doc["version"] >= 1, "version is not a positive integer")
    meta = doc.get("metadata", {})
    need(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", str(meta.get("timestamp"))), "metadata.timestamp malformed")
    refs = {}

    def check_component(c, where, subject=False):
        need(isinstance(c, dict), where + " is not an object")
        if not isinstance(c, dict):
            return
        need(c.get("type") in COMPONENT_TYPES, "%s: bad type %r" % (where, c.get("type")))
        need(isinstance(c.get("name"), str) and c["name"], where + ": no name")
        need(isinstance(c.get("version"), str) and c["version"], where + ": no version")
        ref = c.get("bom-ref")
        need(isinstance(ref, str) and ref, where + ": no bom-ref")
        need(ref not in refs, "%s: duplicate bom-ref %r" % (where, ref))
        refs[ref] = c
        if "scope" in c:
            need(c["scope"] in SCOPES, "%s: bad scope %r" % (where, c["scope"]))
        for h in c.get("hashes", []):
            need(h.get("alg") in HASH_LENGTHS and re.fullmatch(r"[0-9a-f]{%d}" % HASH_LENGTHS.get(h.get("alg"), -1), str(h.get("content"))),
                 "%s: bad hash %r" % (where, h))
        if subject:
            need(any(h.get("alg") == "SHA-256" for h in c.get("hashes", [])), where + ": the subject needs a SHA-256")
        if "purl" in c:
            need(re.fullmatch(r"pkg:[a-z]+/\S+@\S+", c["purl"]), "%s: bad purl %r" % (where, c["purl"]))

    check_component(meta.get("component"), "metadata.component", subject=True)
    comps = doc.get("components")
    need(isinstance(comps, list) and comps, "no components")
    for i, c in enumerate(comps or []):
        check_component(c, "components[%d]" % i)
    for d in doc.get("dependencies", []):
        need(d.get("ref") in refs, "dependency ref %r names no component" % d.get("ref"))
        for r in d.get("dependsOn", []):
            need(r in refs, "%r depends on %r, which is not a component" % (d.get("ref"), r))
    subject_ref = meta.get("component", {}).get("bom-ref")
    sub_deps = [d for d in doc.get("dependencies", []) if d.get("ref") == subject_ref]
    need(len(sub_deps) == 1, "the subject needs exactly one dependencies entry")
    for d in sub_deps:
        # Runtime dependencies of the subject are `required` components only: never an excluded one.
        for r in d.get("dependsOn", []):
            need(refs.get(r, {}).get("scope", "required") != "excluded", "the subject depends on an excluded (build-time) component %r" % r)
    return bad


def check_app_bom(doc):
    """What the APK document must say on top of the shape: nothing at runtime, everything else excluded."""
    bad = validate(doc)
    ref = doc.get("metadata", {}).get("component", {}).get("bom-ref")
    sub = [d for d in doc.get("dependencies", []) if d.get("ref") == ref]
    if sub and sub[0].get("dependsOn"):
        bad.append("the app must have no dependencies, has %r" % sub[0]["dependsOn"])
    for c in doc.get("components", []):
        if c.get("scope") != "excluded":
            bad.append("component %r is not scope excluded: the app has no runtime dependencies" % c.get("bom-ref"))
    return bad


# ------------------------------------------------------------------ command line

def emit(doc, out):
    text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("apk")
    a.add_argument("file")
    h = sub.add_parser("host")
    h.add_argument("file")
    h.add_argument("--cargo-lock")
    for p in (a, h):
        p.add_argument("--version")
        p.add_argument("-o", "--output")
    c = sub.add_parser("check")
    c.add_argument("files", nargs="+")
    n = sub.add_parser("names")
    n.add_argument("file")
    n.add_argument("sha256")
    args = ap.parse_args()

    if args.cmd == "names":
        subject = load_json(args.file).get("metadata", {}).get("component", {})
        return 0 if sha256_hash(args.sha256) in subject.get("hashes", []) else 1

    if args.cmd == "check":
        status = 0
        for f in args.files:
            doc = load_json(f)
            faults = check_app_bom(doc) if doc.get("metadata", {}).get("component", {}).get("name") == "SudoStamp" else validate(doc)
            for fault in faults:
                print("%s: %s" % (f, fault), file=sys.stderr)
            status |= bool(faults)
            if not faults:
                print("%s: ok (%d components)" % (f, len(doc.get("components", []))))
        return status

    if not os.path.isfile(args.file):
        die("no such file: %s" % args.file)
    version = args.version or app_version()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        die("version must be X.Y.Z")
    if args.cmd == "apk":
        doc = apk_bom(args.file, version)
        faults = check_app_bom(doc)
    else:
        if args.cargo_lock:
            with open(args.cargo_lock, "rb") as f:
                lock = f.read()
        else:
            lock = fetch_cargo_lock(install_pins()[2])
        doc = host_bom(args.file, version, lock)
        faults = validate(doc)
    if faults:
        die("generated an invalid document: " + "; ".join(faults))
    emit(doc, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
