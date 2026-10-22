# Releasing SudoStamp

Source of truth: **https://gitlab.com/ritwick7/sudostamp**. A release is a merge request plus a tag.
CI runs every check on the tag, and the one job that touches the signing key (`package`) runs only
when the owner clicks it. `scripts/release.sh package X.Y.Z` does the same signed build locally, as a
dry run or a fallback.

## 1. One-time setup (owner)

1. **Signing key.** Already created: an RSA-4096 keystore (`CN=SudoStamp, O=Ritwick Verma`, valid
   until 2054), certificate SHA-256
   `7B:CB:0B:51:24:61:97:B9:BB:99:77:9E:09:A3:AD:CB:BA:EB:2D:59:A0:ED:EC:F8:D2:E8:BE:67:84:4D:06:57`,
   pinned in `scripts/release.sh`. It lives only in the maintainer's infrastructure repository as
   `sops/sudostamp/release-signing.sops.env` (keystore + passwords, age-encrypted). Two recipients:
   - **its own age key**, `~/.config/sops/age/sudostamp-release.txt` on the maintainer's machine. It
     opens this file and nothing else, so storing it in CI exposes no other secret;
   - the homelab recovery key, so losing the first is recoverable.

   **Never put the keystore or a password in this repository.** `tools/check-secrets.py` (CI and the
   pre-commit hook) blocks `*.jks`, `*.keystore` and credential-shaped text; `gitleaks` scans the whole
   history on every pipeline. Losing the key means no update can ever install over a released app.
2. **CI signing.** `scripts/setup-ci-secrets.sh` (owner only; it asks first) stores the age key and
   the vault ciphertext as two **protected File variables** and protects the `v*` tags, so only a
   maintainer's tag pipeline receives them. Without it, sign locally (section 3).
3. `master` is protected (Maintainers merge, no force push).

## 2. Cutting a release

```sh
# 1. On master (via a normal merge request): a "## X.Y.Z — unreleased" section in CHANGELOG.md and
#    the store notes fastlane/metadata/android/en-US/changelogs/<next versionCode>.txt (<= 500 chars).
# 2. Release branch + merge request. No secrets; your checkout is not touched:
scripts/release.sh prepare X.Y.Z      # bumps versionCode/versionName, dates the section, runs release-check
# 3. The MR pipeline (tests, release-check) goes green -> merge it.
# 4. Tag THE MERGE COMMIT (not master before it):
git switch master && git pull && git tag -a vX.Y.Z -m "SudoStamp X.Y.Z" && git push origin vX.Y.Z
# 5. Tag pipeline: every check, then click `package` -> signed APK + installer uploaded,
#    `publish-release` creates the GitLab Release.
```

A tag on the wrong commit fails `release-check` within seconds and nothing else starts. Delete it
(`git push origin :refs/tags/vX.Y.Z`) and tag again.

| Gate | Where |
|---|---|
| secret scan (tree), gitleaks (full history), shellcheck | `hygiene`, `gitleaks` |
| unit tests + independent signature check, lint, debug build | `unit-test`, `lint`, `assemble-debug` |
| host installer end to end on 7 distributions | `host-e2e` |
| versions, store notes, dated changelog, store listing | `release-check` (tags and `release/*`) |
| signed build, certificate == pinned release key, not debuggable | `package` (manual) |
| GitLab Release with APK, installer, SHA256SUMS, mapping | `publish-release` |

## 3. Signing locally (dry run, or no CI secrets)

```sh
git worktree add --detach /tmp/rel vX.Y.Z && cd /tmp/rel
JAVA_HOME=~/opt/jdk ANDROID_HOME=~/opt/android-sdk scripts/release.sh package X.Y.Z
# dist/: sudostamp-vX.Y.Z.apk, sudostamp-setup.sh, mapping-vX.Y.Z.txt, SHA256SUMS. Nothing is uploaded.
cd - && git worktree remove --force /tmp/rel
```

The vault is read from the infrastructure repository's `origin/master` (whatever branch its checkout
is on) and decrypted into a private tmpfs directory that is wiped on exit. To publish such a build,
create the GitLab Release by hand and attach the four files.

## 4. Before a release that touches the app

- Install the **signed** release build on an emulator or test phone (`package` output) and check the
  paths R8 can break, since unit tests never see shrunk code: create key, pairing
  (`tools/install.sh setup` against it), an approval (`tools/simulate_pam_rssh.py`, 18/18), **Deny**
  from the notification, the app closing itself after approval, the listener coming back after
  `adb install -r`.
- `tools/test/e2e.sh` runs in CI on every push; check it is green on the merge request.

## 5. Version numbers

`versionCode` only goes up (`release-check` compares it with every earlier tag). 1.3.0, the first public
release, is versionCode 8; earlier codes were internal builds and never published.

## 6. Switching from a debug build to a release build

Debug and release builds are signed with different keys, so Android will not install one over the
other. You must **uninstall** first, and uninstalling **deletes the phone's Keystore key**. Afterwards:
open the app, **Get started**, and run `setup` on the computer again to pair the new key. Updates
between release builds keep the key, like `adb install -r` does for debug builds.

## 7. Distribution channels

| Channel | How it gets the build | Who |
|---|---|---|
| GitLab Releases | `publish-release` | automatic after `package` |
| Obtainium | reads GitLab Releases | nothing to do |
| AUR (`sudostamp`, host side) | `scripts/update-aur.sh X.Y.Z`, push `packaging/aur/` to `aur@aur.archlinux.org:sudostamp.git` | owner (AUR account) |
| IzzyOnDroid / F-Droid | `fastlane/metadata/android/en-US/` + the signed APK | owner files the inclusion request once |

## 8. Updating dependencies

Every build dependency is pinned by SHA-256 in `gradle/verification-metadata.xml`. After bumping AGP,
Kotlin, Gradle or JUnit, regenerate it **from an empty cache in the CI image**, or CI fails on files your
own cache already had:

```sh
podman run --rm -v "$PWD":/src:ro -v "$PWD/gradle":/out eclipse-temurin:17-jdk bash -c '
  cp -a /src /p && cd /p && rm gradle/verification-metadata.xml &&
  CI_PROJECT_DIR=/p ANDROID_HOME=/p/sdk bash scripts/ci-setup-sdk.sh >/dev/null &&
  ANDROID_HOME=/p/sdk GRADLE_USER_HOME=/p/.g ./gradlew -q --write-verification-metadata sha256 \
    testDebugUnitTest lintDebug assembleDebug assembleRelease &&
  cp gradle/verification-metadata.xml /out/'
```

Then review the diff: every changed checksum should belong to something you meant to upgrade.
