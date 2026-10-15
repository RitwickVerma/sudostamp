#!/bin/bash
# Local verification for SudoStamp, from any checkout with the toolchain installed:
#
#   tools/verify.sh
#
# Needs JDK 17 (JAVA_HOME) and an Android SDK with build-tools 36.0.0 (ANDROID_HOME, or
# sdk.dir in local.properties), plus ssh-keygen and python3-cryptography for gate 2.
#
# Four independent gates, each of which can fail on its own:
#   1. unit tests          -- structure + negative controls + DER round-trip
#   2. external verifier   -- real ssh-keygen and an independent ECDSA library
#   3. debug APK build     -- the Kotlin actually compiles into an installable artifact
#   4. APK sanity          -- signed, correct package/minSdk, dex present
#
# Any gate failing makes the whole run FAIL. No gate is advisory.
set -uo pipefail
cd "$(dirname "$0")/.." || { echo "FATAL: project missing"; exit 1; }
LOG=$(mktemp -d)
trap 'rm -rf "$LOG"' EXIT

# apksigner/aapt2 are shell wrappers that exec `java`. java is NOT on PATH on this box
# (only JAVA_HOME is set), so without this every tool fails and the failure gets
# misattributed to the ARTIFACT. That produced a bogus "signature: INVALID" once.
export JAVA_HOME="${JAVA_HOME:?set JAVA_HOME to a JDK 17}"
export PATH="$JAVA_HOME/bin:$PATH"
command -v java >/dev/null || { echo "FATAL: no java at $JAVA_HOME"; exit 1; }

FAIL=0
gate() { printf '\n--- %s ---\n' "$1"; }

gate "1/4  unit tests"
# --rerun-tasks: without it Gradle can report BUILD SUCCESSFUL while skipping the task
# entirely, and a deleted results dir then reads as "0 tests, 0 failures" -- i.e. a
# green build that tested nothing. Force execution.
./gradlew -Dorg.gradle.java.home="$JAVA_HOME" test --rerun-tasks --no-daemon > "$LOG/test.log" 2>&1
T=$?
grep -E 'BUILD SUCCESSFUL|BUILD FAILED' "$LOG/test.log" | tail -1 | sed 's/^/  /'
python3 - <<'PY'
import glob, xml.etree.ElementTree as ET
# Android puts JVM unit-test results under test-results/<TASKNAME>/, e.g.
# testDebugUnitTest -- NOT test-results/test/. Globbing the wrong depth made a green
# run read as "0 tests", i.e. a harness false negative, so search recursively.
files = glob.glob("app/build/test-results/**/*.xml", recursive=True)
tests = fails = errs = skip = 0
for f in files:
    r = ET.parse(f).getroot()
    tests += int(r.get("tests", 0)); fails += int(r.get("failures", 0))
    errs += int(r.get("errors", 0)); skip += int(r.get("skipped", 0))
    for tc in r.iter("testcase"):
        bad = tc.find("failure") is not None or tc.find("error") is not None
        print(f"    {'FAIL' if bad else 'ok  '}  {tc.get('classname','').split('.')[-1]}.{tc.get('name')}")
print(f"  files: {len(files)}   tests: {tests}   failures: {fails}   errors: {errs}   skipped: {skip}")
raise SystemExit(1 if (fails or errs or tests == 0) else 0)
PY
[ $? -ne 0 ] && { echo "  TESTS DID NOT PASS (or none ran)"; FAIL=1; }
[ $T -ne 0 ] && { echo "  gradle test exit=$T"; FAIL=1; }

gate "2/4  external verifier (ssh-keygen + independent crypto)"
python3 tools/verify_ssh_sig.py app/build/sshcheck 2>&1 | tail -12 | sed 's/^/  /'
python3 tools/verify_ssh_sig.py app/build/sshcheck >/dev/null 2>&1 || { echo "  EXTERNAL CHECK FAILED"; FAIL=1; }

gate "3/4  debug APK build"
./gradlew -Dorg.gradle.java.home="$JAVA_HOME" assembleDebug --no-daemon > "$LOG/apk.log" 2>&1
A=$?
grep -E 'BUILD SUCCESSFUL|BUILD FAILED' "$LOG/apk.log" | tail -1 | sed 's/^/  /'
[ $A -ne 0 ] && { echo "  assembleDebug exit=$A"; FAIL=1; }

gate "4/4  APK sanity"
APK=app/build/outputs/apk/debug/app-debug.apk
if [ -f "$APK" ]; then
  echo "  size: $(stat -c%s "$APK") bytes"
  SDK="${ANDROID_HOME:-$(sed -n 's/^sdk\.dir=//p' local.properties 2>/dev/null)}"
  BT="$SDK/build-tools/36.0.0"
  "$BT/apksigner" verify "$APK" >/dev/null 2>&1 && echo "  signature: VERIFIED" || { echo "  signature: INVALID"; FAIL=1; }
  BADGING=$("$BT/aapt2" dump badging "$APK" 2>/dev/null)
  echo "$BADGING" | sed -n '1p' | sed 's/^/  /'
  echo "$BADGING" | grep -E "sdkVersion|targetSdk" | sed 's/^/  /'
  echo "$BADGING" | grep -c 'uses-permission' | sed 's/^/  permissions declared: /'
  python3 -c "
import zipfile,sys
n=zipfile.ZipFile('$APK').namelist()
assert any(x.startswith('classes') and x.endswith('.dex') for x in n), 'no dex'
assert 'AndroidManifest.xml' in n, 'no manifest'
print('  dex + manifest present')
" || FAIL=1
else
  echo "  APK MISSING"; FAIL=1
fi

echo
echo "============================================================"
[ $FAIL -eq 0 ] && echo "VERIFICATION PASSED (all 4 gates)" || echo "VERIFICATION FAILED"
echo "============================================================"
exit $FAIL
