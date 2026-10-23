# Releasing SudoStamp

Source of truth: **https://gitlab.com/ritwick7/sudostamp**. A release is a merge request, a tag,
and a signed build published **from the maintainer's machine**. CI runs every check on the tag but
never holds a signing key: the runner is shared with other projects and runs unprotected branches,
and GitLab hands protected variables to every job of a protected ref, so a key there would be one
compromised container image away from leaking.

## 1. One-time setup (owner)

1. **Signing keys.** Both already exist, each only age-encrypted in the maintainer's infrastructure
   repository, opened by a dedicated age key (`~/.config/sops/age/sudostamp-release.txt`) that opens
   these two files and nothing else, plus the homelab recovery key:
   - `sops/sudostamp/release-signing.sops.env`: the APK keystore (RSA-4096, `CN=SudoStamp,
     O=Ritwick Verma`, valid until 2054), certificate SHA-256
     `7B:CB:0B:51:24:61:97:B9:BB:99:77:9E:09:A3:AD:CB:BA:EB:2D:59:A0:ED:EC:F8:D2:E8:BE:67:84:4D:06:57`,
     pinned in `scripts/release.sh`. Losing it means no update can ever install over a released app.
   - `sops/sudostamp/installer-signing.sops.env`: the ed25519 key that signs the installer and
     `SHA256SUMS` (`ssh-keygen -Y sign`, namespace `sudostamp-release`). Public half:
     `keys/allowed_signers`, also carried in the app and the README (`release-check` keeps all three
     identical). Losing it means a new key in all three places, in a new app release.

   **Never put a key or a password in this repository, or in CI variables.** `tools/check-secrets.py`
   (CI and the pre-commit hook) refuses key files by name and credential-shaped text; `gitleaks`
   scans the whole history on every pipeline.
2. `master` is protected (Maintainers merge, no force push); `v*` tags are protected.
3. `glab` logged in to gitlab.com as a maintainer (for `publish`).

## 2. Cutting a release

```sh
# 1. On master (via a normal merge request): a "## X.Y.Z — unreleased" section in CHANGELOG.md and
#    the store notes fastlane/metadata/android/en-US/changelogs/<next versionCode>.txt (<= 500 chars).
# 2. Release branch + merge request. No secrets; your checkout is not touched:
scripts/release.sh prepare X.Y.Z      # bumps versionCode/versionName, dates the section, runs release-check
# 3. The MR pipeline (tests, release-check) goes green -> merge it.
# 4. Tag THE MERGE COMMIT (not master before it):
git switch master && git pull && git tag -a vX.Y.Z -m "SudoStamp X.Y.Z" && git push origin vX.Y.Z
# 5. The tag pipeline goes green. Then, on your machine, from a worktree at the tag:
git worktree add --detach /tmp/rel vX.Y.Z && cp local.properties /tmp/rel/ && cd /tmp/rel
JAVA_HOME=~/opt/jdk ANDROID_HOME=~/opt/android-sdk scripts/release.sh publish X.Y.Z
cd - && git worktree remove --force /tmp/rel
```

`publish` builds and signs (as `package` below), shows the six files and asks, then uploads them to
the package registry, creates the GitLab Release with permanent `/-/releases/permalink/latest/`
links, downloads the installer and APK back anonymously, and verifies them. A tag on the wrong
commit fails `release-check` within seconds; delete it (`git push origin :refs/tags/vX.Y.Z`) and tag
again.

| Gate | Where |
|---|---|
| secret scan (tree), gitleaks (full history), shellcheck, Python tests | CI `hygiene`, `gitleaks` |
| unit tests + independent signature check, lint, debug build | CI `unit-test`, `lint`, `assemble-debug` |
| host installer end to end on 7 distributions, including what must fail | CI `host-e2e` |
| versions, store notes, dated changelog, store listing, signer line in app + README | CI `release-check` (tags and `release/*`) |
| signed build, certificate == pinned release key, not debuggable, installer signature verifies | `release.sh package` |
| upload, Release, anonymous download verified | `release.sh publish` |

## 3. Signing without publishing (dry run)

```sh
git worktree add --detach /tmp/rel vX.Y.Z && cp local.properties /tmp/rel/ && cd /tmp/rel
JAVA_HOME=~/opt/jdk ANDROID_HOME=~/opt/android-sdk scripts/release.sh package X.Y.Z
# dist/: sudostamp-vX.Y.Z.apk, sudostamp-setup.sh(.sig), SHA256SUMS(.sig), mapping-vX.Y.Z.txt.
cd - && git worktree remove --force /tmp/rel
```

The vaults are read from the infrastructure repository's `origin/master` (whatever branch its
checkout is on) and decrypted into a private tmpfs directory that is wiped on exit; Gradle's project
cache (whose execution history records hashes of the keystore passwords) lives in that directory
too. The script refuses to run if `$XDG_RUNTIME_DIR` is not tmpfs.

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
| GitLab Releases | `scripts/release.sh publish` | owner |
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
