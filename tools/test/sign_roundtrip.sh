#!/usr/bin/env bash
# Round trip for scripts/sign-apk.sh, with a throwaway key made here (never the release key):
#   1. it signs an unsigned release build and both outputs carry the expected certificate;
#   2. moving that signature onto the SAME unsigned APK with apksigcopier gives the signed bytes
#      back -- the property scripts/verify-reproducible.sh relies on for every release;
#   3. it refuses a wrong expected certificate and an input that is already signed.
#
#   tools/test/sign_roundtrip.sh UNSIGNED.apk UNSIGNED.aab
# Needs JAVA_HOME, ANDROID_HOME, and apksigcopier on PATH.
set -euo pipefail
cd "$(dirname "$0")/../.."
[ $# -eq 2 ] || { echo "usage: $0 UNSIGNED.apk UNSIGNED.aab" >&2; exit 2; }
APK=$1; AAB=$2
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
fail() { echo "sign_roundtrip: FAIL: $*" >&2; exit 1; }

export SUDOSTAMP_KEYSTORE="$W/test.jks" SUDOSTAMP_KEY_ALIAS=t
SUDOSTAMP_KEYSTORE_PASSWORD=$(head -c 18 /dev/urandom | base64); SUDOSTAMP_KEY_PASSWORD=$SUDOSTAMP_KEYSTORE_PASSWORD
export SUDOSTAMP_KEYSTORE_PASSWORD SUDOSTAMP_KEY_PASSWORD
"$JAVA_HOME/bin/keytool" -genkeypair -keystore "$SUDOSTAMP_KEYSTORE" -alias t -keyalg RSA -keysize 2048 \
  -validity 2 -dname CN=sign-roundtrip -storepass:env SUDOSTAMP_KEYSTORE_PASSWORD \
  -keypass:env SUDOSTAMP_KEY_PASSWORD >/dev/null 2>&1
CERT=$("$JAVA_HOME/bin/keytool" -exportcert -keystore "$SUDOSTAMP_KEYSTORE" -alias t \
  -storepass:env SUDOSTAMP_KEYSTORE_PASSWORD | sha256sum | cut -d' ' -f1 | tr 'a-f' 'A-F' | sed 's/../&:/g; s/:$//')

# 1. signs, and both outputs carry the certificate
scripts/sign-apk.sh "$APK" "$AAB" "$W/out" "$CERT" || fail "signing with the right certificate"

# 2. the signature moves onto the unsigned build and gives the same bytes back
apksigcopier copy "$W/out/app-release.apk" "$APK" "$W/copied.apk"
cmp -s "$W/out/app-release.apk" "$W/copied.apk" || fail "apksigcopier does not reproduce the signed APK"

# 3. negative controls: each must fail
WRONG=$(printf '%s' "$CERT" | sed 's/^../00/')
[ "$WRONG" != "$CERT" ] || WRONG=$(printf '%s' "$CERT" | sed 's/^../11/')
if scripts/sign-apk.sh "$APK" "$AAB" "$W/wrong" "$WRONG" 2>"$W/err"; then fail "accepted a wrong certificate"; fi
grep -q 'the APK is signed with' "$W/err" || fail "the APK certificate check did not fire: $(cat "$W/err")"
if scripts/sign-apk.sh "$W/out/app-release.apk" "$AAB" "$W/again" "$CERT" 2>/dev/null; then fail "signed an already signed APK"; fi
if scripts/sign-apk.sh "$APK" "$W/out/app-release.aab" "$W/again" "$CERT" 2>/dev/null; then fail "signed an already signed bundle"; fi
echo "sign_roundtrip: ok (signed, signature transplant reproduces the APK, 3 refusals)"
