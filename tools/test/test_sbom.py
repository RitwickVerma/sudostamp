#!/usr/bin/env python3
"""Tests for scripts/sbom.py: the SBOMs of a release are the right shape and say the right things.

    python3 -I tools/test/test_sbom.py
    SUDOSTAMP_ONLINE=1 python3 -I tools/test/test_sbom.py     # also fetches pam_rssh's real Cargo.lock

Standard library only. The shape checker is sbom.validate (CycloneDX 1.5 as this script writes it);
it is tested here on documents with one fault each, so a checker that passes everything fails.
The independent assertions (component counts, the app's hash, who depends on what) are computed
from the repository's files with plain regular expressions, not with the generator's own code.
"""
import copy
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

here = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(here, "..", ".."))
spec = importlib.util.spec_from_file_location("sbom", os.path.join(ROOT, "scripts", "sbom.py"))
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)
SBOM = os.path.join(ROOT, "scripts", "sbom.py")
ONLINE = os.environ.get("SUDOSTAMP_ONLINE") == "1"

# A Cargo.lock in miniature: a root package, a registry crate with a checksum, a git crate with none,
# and the long dependency spelling Cargo uses when a name is ambiguous.
LOCK = b'''version = 4

[[package]]
name = "alpha"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "%s"

[[package]]
name = "beta"
version = "0.2.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "%s"
dependencies = ["alpha"]

[[package]]
name = "beta"
version = "0.3.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "%s"

[[package]]
name = "gitdep"
version = "0.1.0"
source = "git+https://github.com/example/gitdep?branch=main#%s"

[[package]]
name = "pam_rssh"
version = "1.2.0"
dependencies = [
 "alpha",
 "beta 0.2.0",
 "gitdep",
]
''' % (b"a" * 64, b"b" * 64, b"c" * 64, b"d" * 40)


def slurp(path, mode="r"):
    with open(path, mode) as f:
        return f.read()


def spit(path, data):
    with open(path, "wb") as f:
        f.write(data)


def run(*args, env=None, check=False):
    e = dict(os.environ, SOURCE_DATE_EPOCH="1700000000")
    e.update(env or {})
    p = subprocess.run([sys.executable, "-I", SBOM] + list(args), capture_output=True, text=True, env=e)
    if check and p.returncode:
        raise AssertionError(p.stderr)
    return p


class Sbom(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        os.environ["SOURCE_DATE_EPOCH"] = "1700000000"
        cls.tmp = tempfile.TemporaryDirectory()
        cls.apk = os.path.join(cls.tmp.name, "sudostamp-v9.9.9.apk")
        spit(cls.apk, b"PK\x03\x04 pretend apk " * 100)
        cls.apk_sha = hashlib.sha256(slurp(cls.apk, "rb")).hexdigest()
        cls.setup_sh = os.path.join(cls.tmp.name, "sudostamp-setup.sh")
        spit(cls.setup_sh, b"#!/bin/bash\necho installer\n")
        cls.setup_sha = hashlib.sha256(slurp(cls.setup_sh, "rb")).hexdigest()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    # -------------------------------------------------------------- the APK document

    def test_apk_sbom_says_the_app_has_no_runtime_dependencies(self):
        doc = S.apk_bom(self.apk, "9.9.9")
        self.assertEqual(S.check_app_bom(doc), [])
        sub = doc["metadata"]["component"]
        self.assertEqual((sub["name"], sub["version"]), ("SudoStamp", "9.9.9"))
        self.assertEqual([h for h in sub["hashes"] if h["alg"] == "SHA-256"], [{"alg": "SHA-256", "content": self.apk_sha}])
        # No runtime dependency, stated three ways.
        self.assertEqual([d for d in doc["dependencies"] if d["ref"] == sub["bom-ref"]], [{"ref": sub["bom-ref"], "dependsOn": []}])
        self.assertIn({"aggregate": "complete", "dependencies": [sub["bom-ref"]]}, doc["compositions"])
        self.assertTrue(doc["components"])
        self.assertEqual({c["scope"] for c in doc["components"]}, {"excluded"})
        self.assertIn(("sudostamp:runtime-dependencies", "0"), [(p["name"], p["value"]) for p in sub["properties"]])
        self.assertEqual(doc["specVersion"], "1.5")

    def test_every_pinned_build_dependency_is_listed_with_its_hash(self):
        xml = slurp(os.path.join(ROOT, "gradle", "verification-metadata.xml"))
        pinned = re.findall(r'<component group="([^"]+)" name="([^"]+)" version="([^"]+)">(.*?)</component>', xml, re.S)
        self.assertGreater(len(pinned), 100)
        doc = S.apk_bom(self.apk, "9.9.9")
        by_ref = {c["bom-ref"]: c for c in doc["components"]}
        for group, name, version, body in pinned:
            c = by_ref.get("pkg:maven/%s/%s@%s" % (group, name, version))
            self.assertIsNotNone(c, "%s:%s:%s missing from the SBOM" % (group, name, version))
            shas = re.findall(r'<artifact name="([^"]+)">\s*<sha256 value="([0-9a-f]{64})"', body)
            self.assertEqual({p["name"][len("gradle:artifact:"):]: p["value"] for p in c["properties"]}, dict(shas))
            self.assertIn(c["hashes"][0]["content"], [h for _, h in shas])
            self.assertEqual(c["scope"], "excluded")
        # And nothing else but the five named tools.
        tools = [c for c in doc["components"] if not c["bom-ref"].startswith("pkg:maven/")]
        self.assertEqual(sorted(c["name"] for c in tools),
                         ["android-build-tools", "android-commandlinetools", "android-platform", "gradle", "jdk-container-image"])
        self.assertEqual(len(doc["components"]), len(pinned) + len(tools))
        gradle = next(c for c in tools if c["name"] == "gradle")
        self.assertEqual(gradle["hashes"][0]["content"],
                         re.search(r"^distributionSha256Sum=([0-9a-f]{64})", slurp(os.path.join(ROOT, "gradle/wrapper/gradle-wrapper.properties")), re.M)[1])

    def test_output_is_deterministic(self):
        a = run("apk", self.apk, "--version", "9.9.9", check=True).stdout
        b = run("apk", self.apk, "--version", "9.9.9", check=True).stdout
        self.assertEqual(a, b)
        other = os.path.join(self.tmp.name, "other.apk")
        spit(other, b"different")
        self.assertNotEqual(json.loads(run("apk", other, "--version", "9.9.9", check=True).stdout)["serialNumber"],
                            json.loads(a)["serialNumber"])
        self.assertEqual(json.loads(a)["metadata"]["timestamp"], "2023-11-14T22:13:20Z")

    def test_cli_writes_a_file_that_check_accepts(self):
        out = os.path.join(self.tmp.name, "apk.cdx.json")
        run("apk", self.apk, "--version", "9.9.9", "-o", out, check=True)
        p = run("check", out)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("ok (", p.stdout)
        self.assertEqual(run("apk", self.apk, "--version", "9.9").returncode, 1)
        self.assertEqual(run("apk", os.path.join(self.tmp.name, "nope.apk"), "--version", "9.9.9").returncode, 1)

    # -------------------------------------------------------------- the checker catches faults

    def test_the_checker_fails_documents_with_one_fault_each(self):
        good = S.apk_bom(self.apk, "9.9.9")
        self.assertEqual(S.check_app_bom(good), [])

        def broken(mutate, app=True):
            d = copy.deepcopy(good)
            mutate(d)
            return (S.check_app_bom if app else S.validate)(d)

        faults = {
            "specVersion": lambda d: d.update(specVersion="1.4"),
            "bomFormat": lambda d: d.update(bomFormat="SPDX"),
            "serialNumber": lambda d: d.update(serialNumber="1234"),
            "version": lambda d: d.update(version=0),
            "timestamp": lambda d: d["metadata"].update(timestamp="yesterday"),
            "subject hash missing": lambda d: d["metadata"]["component"].update(hashes=[]),
            "subject hash length": lambda d: d["metadata"]["component"].update(hashes=[{"alg": "SHA-256", "content": "ab"}]),
            "unknown hash alg": lambda d: d["components"][0].update(hashes=[{"alg": "CRC32", "content": "0" * 8}]),
            "uppercase hash": lambda d: d["components"][0].update(hashes=[{"alg": "SHA-256", "content": "A" * 64}]),
            "bad type": lambda d: d["components"][0].update(type="gadget"),
            "bad scope": lambda d: d["components"][0].update(scope="sometimes"),
            "no version": lambda d: d["components"][0].pop("version"),
            "bad purl": lambda d: d["components"][0].update(purl="maven:foo"),
            "duplicate bom-ref": lambda d: d["components"][1].update({"bom-ref": d["components"][0]["bom-ref"]}),
            "dangling dependency": lambda d: d["dependencies"].append({"ref": "pkg:generic/ghost@1", "dependsOn": []}),
            "dangling dependsOn": lambda d: d["dependencies"][0].update(dependsOn=["pkg:generic/ghost@1"]),
            "app depends on a build tool": lambda d: d["dependencies"][0].update(dependsOn=[d["components"][0]["bom-ref"]]),
            "a required component": lambda d: d["components"][0].update(scope="required"),
            "no components": lambda d: d.update(components=[]),
            "no subject entry": lambda d: d.update(dependencies=[]),
        }
        for name, mutate in faults.items():
            self.assertTrue(broken(mutate), "the checker accepted: " + name)

    # -------------------------------------------------------------- the installer document

    def with_pin(self, lock, fn):
        old = S.PAM_RSSH_CARGO_LOCK_SHA256
        S.PAM_RSSH_CARGO_LOCK_SHA256 = hashlib.sha256(lock).hexdigest()
        try:
            return fn()
        finally:
            S.PAM_RSSH_CARGO_LOCK_SHA256 = old

    def test_host_sbom_lists_pam_rssh_at_the_pinned_commit_and_its_crates(self):
        doc = self.with_pin(LOCK, lambda: S.host_bom(self.setup_sh, "9.9.9", LOCK))
        self.assertEqual(S.validate(doc), [])
        install = slurp(os.path.join(ROOT, "tools", "install.sh"))
        commit = re.search(r'^RSSH_COMMIT="([0-9a-f]{40})"', install, re.M)[1]
        tag = re.search(r'^RSSH_TAG="([^"]+)"', install, re.M)[1]
        refs = {c["bom-ref"]: c for c in doc["components"]}
        pam = refs["pkg:github/z4yx/pam_rssh@" + commit]
        self.assertEqual((pam["version"], pam["scope"]), (tag, "required"))
        self.assertEqual(pam["pedigree"]["commits"][0]["uid"], commit)
        self.assertEqual(doc["metadata"]["component"]["hashes"], [{"alg": "SHA-256", "content": self.setup_sha}])
        # The four non-root crates, registry ones with their lock checksums, all `required`.
        self.assertEqual(sorted(c["name"] + "@" + c["version"] for c in doc["components"] if c["bom-ref"] != pam["bom-ref"]),
                         ["alpha@1.0.0", "beta@0.2.0", "beta@0.3.0", "gitdep@0.1.0"])
        self.assertEqual(refs["pkg:cargo/alpha@1.0.0"]["hashes"], [{"alg": "SHA-256", "content": "a" * 64}])
        self.assertNotIn("hashes", refs["pkg:cargo/gitdep@0.1.0?vcs_url=https://github.com/example/gitdep@" + "d" * 40])
        self.assertEqual({c["scope"] for c in doc["components"]}, {"required"})
        deps = {d["ref"]: d["dependsOn"] for d in doc["dependencies"]}
        self.assertEqual(deps[doc["metadata"]["component"]["bom-ref"]], [pam["bom-ref"]])
        # "beta 0.2.0" resolved to that beta and not the other.
        self.assertEqual(deps[pam["bom-ref"]], sorted(["pkg:cargo/alpha@1.0.0", "pkg:cargo/beta@0.2.0",
                                                       "pkg:cargo/gitdep@0.1.0?vcs_url=https://github.com/example/gitdep@" + "d" * 40]))
        self.assertEqual(deps["pkg:cargo/beta@0.2.0"], ["pkg:cargo/alpha@1.0.0"])

    def test_a_cargo_lock_that_is_not_the_pinned_one_stops_the_host_sbom(self):
        with self.assertRaises(SystemExit) as ctx:
            S.host_bom(self.setup_sh, "9.9.9", LOCK)                  # the miniature is not the pinned file
        self.assertIn("pinned", str(ctx.exception))
        lockfile = os.path.join(self.tmp.name, "Cargo.lock")
        spit(lockfile, LOCK)
        p = run("host", self.setup_sh, "--version", "9.9.9", "--cargo-lock", lockfile)
        self.assertEqual(p.returncode, 1)
        self.assertIn("pinned", p.stderr)
        # One byte off the real thing is as wrong as a different file.
        self.assertNotEqual(hashlib.sha256(LOCK + b"\n").hexdigest(), S.PAM_RSSH_CARGO_LOCK_SHA256)

    def test_broken_cargo_locks_are_refused_not_guessed(self):
        for lock in (b"", b'version = 4\n', b"not toml [[", LOCK.replace(b'"gitdep",\n', b'"ghost",\n')):
            with self.assertRaises((SystemExit, ValueError)):
                self.with_pin(lock, lambda: S.host_bom(self.setup_sh, "9.9.9", lock))

    @unittest.skipUnless(ONLINE, "set SUDOSTAMP_ONLINE=1 to fetch pam_rssh's Cargo.lock")
    def test_the_real_pinned_cargo_lock_matches_the_pin(self):
        _, _, commit, _ = S.install_pins()
        lock = S.fetch_cargo_lock(commit)
        self.assertEqual(hashlib.sha256(lock).hexdigest(), S.PAM_RSSH_CARGO_LOCK_SHA256,
                         "tools/install.sh pins a pam_rssh commit whose Cargo.lock is not the one pinned in scripts/sbom.py")
        doc = S.host_bom(self.setup_sh, "9.9.9", lock)
        self.assertEqual(S.validate(doc), [])
        packages = lock.count(b"[[package]]")
        self.assertEqual(len(doc["components"]), packages)           # every package, the root as pam_rssh itself
        out = os.path.join(self.tmp.name, "host.cdx.json")
        run("host", self.setup_sh, "--version", "9.9.9", "-o", out, check=True)
        self.assertEqual(run("check", out).returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=1)
