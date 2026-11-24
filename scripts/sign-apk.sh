#!/usr/bin/env bash
# Sign an UNSIGNED release APK and app bundle with the release key, outside Gradle.
#
#   scripts/sign-apk.sh UNSIGNED.apk UNSIGNED.aab OUTDIR EXPECTED_CERT
#
# Why outside Gradle: a key handed to Gradle is in the same JVM as every build plugin and
# dependency. Here the build has already finished before any key exists, and only apksigner,
# jarsigner and keytool (JDK and SDK build-tools, not this project's dependencies) see it.
#
# Why these apksigner flags: they reproduce what AGP wrote for minSdk 30 (APK Signature Scheme
# v2 only) and keep the zip entries exactly where the unsigned build put them. That is what the
# reproducibility proof needs: apksigcopier moves this signature onto anyone's unsigned rebuild
# and must get the published bytes back (scripts/verify-reproducible.sh). Without
# --alignment-preserved apksigner re-aligns entries and the proof fails.
#
# Key material from the environment, never argv (argv is visible to every process):
#   SUDOSTAMP_KEYSTORE           path to the keystore (in tmpfs)
#   SUDOSTAMP_KEY_ALIAS          its alias
#   SUDOSTAMP_KEYSTORE_PASSWORD  store password
#   SUDOSTAMP_KEY_PASSWORD       key password
# Also: JAVA_HOME (JDK 17), ANDROID_HOME (build-tools 36.0.0).
# Writes OUTDIR/app-release.apk and OUTDIR/app-release.aab, each checked against EXPECTED_CERT
# (SHA-256, colon-separated upper-case hex) before it exits 0.
set -euo pipefail
die() { echo "sign-apk: $*" >&2; exit 1; }
[ $# -eq 4 ] || die "usage: scripts/sign-apk.sh UNSIGNED.apk UNSIGNED.aab OUTDIR EXPECTED_CERT"
IN_APK=$1; IN_AAB=$2; OUT=$3; WANT=$4
[[ "$WANT" =~ ^([0-9A-F]{2}:){31}[0-9A-F]{2}$ ]] || die "EXPECTED_CERT is not a SHA-256 fingerprint"
: "${JAVA_HOME:?}" "${ANDROID_HOME:?}"
BT="$ANDROID_HOME/build-tools/36.0.0"
for v in SUDOSTAMP_KEYSTORE SUDOSTAMP_KEY_ALIAS SUDOSTAMP_KEYSTORE_PASSWORD SUDOSTAMP_KEY_PASSWORD; do
  [ -n "${!v:-}" ] || die "$v is not set"
done
[ -s "$SUDOSTAMP_KEYSTORE" ] || die "no keystore at \$SUDOSTAMP_KEYSTORE"
[ -s "$IN_APK" ] && [ -s "$IN_AAB" ] || die "missing input"
# Signing an already signed file would hide which key the build itself used: refuse it.
! "$BT/apksigner" verify "$IN_APK" >/dev/null 2>&1 || die "$IN_APK is already signed"
AAB_LIST=$(unzip -l "$IN_AAB") || die "$IN_AAB is not a zip"
! printf '%s\n' "$AAB_LIST" | grep -qE ' META-INF/[^/]+\.(RSA|EC|DSA)$' || die "$IN_AAB is already signed"
mkdir -p "$OUT"

"$BT/apksigner" sign --ks "$SUDOSTAMP_KEYSTORE" --ks-key-alias "$SUDOSTAMP_KEY_ALIAS" \
  --ks-pass env:SUDOSTAMP_KEYSTORE_PASSWORD --key-pass env:SUDOSTAMP_KEY_PASSWORD \
  --alignment-preserved --v1-signing-enabled false --v2-signing-enabled true \
  --v3-signing-enabled false --v4-signing-enabled false \
  --out "$OUT/app-release.apk" "$IN_APK" || die "apksigner could not sign the APK"
cp "$IN_AAB" "$OUT/app-release.aab"
"$JAVA_HOME/bin/jarsigner" -keystore "$SUDOSTAMP_KEYSTORE" \
  -storepass:env SUDOSTAMP_KEYSTORE_PASSWORD -keypass:env SUDOSTAMP_KEY_PASSWORD \
  -digestalg SHA-256 "$OUT/app-release.aab" "$SUDOSTAMP_KEY_ALIAS" >/dev/null \
  || die "jarsigner could not sign the bundle"

"$BT/apksigner" verify "$OUT/app-release.apk" || die "apksigner rejects the signed APK"
CERT=$("$BT/apksigner" verify --print-certs "$OUT/app-release.apk" \
  | sed -n 's/^Signer #1 certificate SHA-256 digest: //p' | head -1 | tr 'a-f' 'A-F' | sed 's/../&:/g; s/:$//')
[ "$CERT" = "$WANT" ] || die "the APK is signed with $CERT, not $WANT"
AAB_VERIFY=$("$JAVA_HOME/bin/jarsigner" -verify "$OUT/app-release.aab" 2>&1) || die "jarsigner rejects the signed bundle"
printf '%s\n' "$AAB_VERIFY" | grep -q '^jar verified' || die "jarsigner did not verify the bundle: $AAB_VERIFY"
AAB_CERT=$("$JAVA_HOME/bin/keytool" -printcert -jarfile "$OUT/app-release.aab" | sed -n 's/^[[:space:]]*SHA256: //p' | head -1)
[ "$AAB_CERT" = "$WANT" ] || die "the bundle is signed with $AAB_CERT, not $WANT"
echo "signed: APK and bundle, certificate $CERT"
