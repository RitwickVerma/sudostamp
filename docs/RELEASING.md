# Releasing

A release is a Git tag. CI builds the app, signs it with **your** release key, and publishes the
APK with a SHA-256 checksum. The key lives only in CI variables; it is never in the repo.

## One-time setup

1. **Create the signing key** on a machine you trust, and keep a backup of it somewhere safe and
   offline. If you lose it you can never publish an update that installs over the old one.

   ```sh
   keytool -genkeypair -keystore sudostamp-release.jks -alias sudostamp \
     -keyalg EC -groupname secp256r1 -validity 10000 -dname "CN=SudoStamp release"
   ```

2. **Add four CI/CD variables** (Settings → CI/CD → Variables), each **Masked** and **Protected**:

   | Variable | Value |
   |---|---|
   | `SUDOSTAMP_KEYSTORE_B64` | `base64 -w0 sudostamp-release.jks` |
   | `SUDOSTAMP_KEYSTORE_PASSWORD` | the store password |
   | `SUDOSTAMP_KEY_ALIAS` | `sudostamp` |
   | `SUDOSTAMP_KEY_PASSWORD` | the key password |

3. **Protect the tag pattern** `v*` (Settings → Repository → Protected tags, allowed to create:
   Maintainers). Protected variables are only exposed to protected refs, so this is what keeps the
   key out of reach of anyone else's branch or tag.

## Cutting a release

1. Bump `versionCode` and `versionName` in `app/build.gradle.kts`, add a `CHANGELOG.md` section,
   commit and push.
2. Tag exactly the `versionName`: `git tag v1.3.0 && git push origin v1.3.0`.
3. The `build-release` job refuses a tag that does not match `versionName`. It signs, verifies with
   `apksigner`, and attaches `sudostamp-vX.Y.Z.apk` and its `.sha256`; `publish-release` creates the
   Release page.

Check a download: `sha256sum -c sudostamp-vX.Y.Z.apk.sha256`, and
`apksigner verify --print-certs sudostamp-vX.Y.Z.apk` (the certificate fingerprint should be the
same on every release; publish it in the release notes once so people can pin it).

## Switching from a debug build to a release build

Debug and release builds are signed with different keys, so Android will not install one over the
other. You must **uninstall** first, and uninstalling **deletes the phone's Keystore key**. Afterwards:
open the app, Create key, and run `tools/install.sh stage` again to pin the new key on the host
(`rollback` first if you want to be sure nothing stale is left). Updates between release builds
signed with the same key keep the key, like `adb install -r` does for debug builds.

## Testing the shrunk build

The release APK is minified (R8, no `-keep` rules). Unit tests never see that code, so before the
first release and after any change to the manifest, `proguard-rules.pro` or anything loaded by
name, install the SIGNED release build on an emulator or phone and check the paths that are
reached only through the manifest: a full approval (`tools/simulate_pam_rssh.py`, 18/18), **Deny**
on the notification, the app closing itself after approval, and the listener coming back after
`adb install -r`. A throwaway keystore is enough for this.

## Without a key

`./gradlew assembleRelease` with no `SUDOSTAMP_KEYSTORE*` variables builds an unsigned APK that
Android refuses to install. That is deliberate: there is no way to produce an installable release
without the key.
