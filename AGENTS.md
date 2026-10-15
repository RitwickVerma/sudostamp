# AGENTS.md

Operating guide for anyone (human or agent) changing this repo. Start with
[README.md](README.md) for what it is, [docs/DESIGN.md](docs/DESIGN.md) for why it is shaped
this way, [SECURITY.md](SECURITY.md) for the threat model.

## Run

Android app (Kotlin, `:app`). Toolchain: JDK 17, an Android SDK with platform 36 and build-tools
36.0.0 (`ANDROID_HOME`, or `sdk.dir` in the gitignored `local.properties`), Gradle 9.3.1 via the
wrapper, AGP 9.0.0.

```sh
./gradlew assembleDebug                                   # app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/debug/app-debug.apk  # -r keeps the Keystore key; NEVER uninstall
tools/verify.sh                                           # four gates; needs JAVA_HOME
```

- No SDK: `ANDROID_HOME=<dir> bash scripts/ci-setup-sdk.sh` installs the pinned one (CI does this).
- If `~/.gradle/gradle.properties` sets a stale `org.gradle.java.home`, pass
  `-Dorg.gradle.java.home=$JAVA_HOME` (verify.sh does).
- Host side: `tools/install.sh {stage|test|apply|rollback|status}`, configured by
  `--phone <ip>:7777` (or `SUDOSTAMP_PHONE`), run with plain `sudo`, never `sudo -E`. **Never run `apply` or `rollback` unless asked**:
  they replace `/etc/pam.d/sudo`. `stage` and `test` leave it alone.

## Test

```sh
./gradlew testDebugUnitTest                          # 31 JVM tests, no emulator, no mocks
python3 tools/verify_ssh_sig.py app/build/sshcheck   # AFTER the unit tests
./gradlew lintDebug
python3 tools/check-secrets.py --all
shellcheck -S warning tools/*.sh scripts/*.sh
```

- `SshSigTest` writes `test.pub`/`msg.bin`/`sig.bin` to `app/build/sshcheck`;
  `verify_ssh_sig.py` checks them with ssh-keygen and `cryptography`, i.e. with code that is not
  this project's. Wire-format changes need both.
- UI without a phone: an emulator with a PIN and an enrolled fingerprint (`adb emu finger touch 1`)
  runs the full approval; `adb forward tcp:17777 tcp:7777` and
  `SUDOSTAMP_PHONE=127.0.0.1:17777 SUDOSTAMP_KEYFILE=<key line file> tools/simulate_pam_rssh.py`.
- On a device, no finger: `SUDOSTAMP_PHONE=<ip>:7777 python3 tools/reuse_connection_test.py --slow`
  (framing, refusals that must not prompt, frame cap, connection budget). With one approval:
  `tools/simulate_pam_rssh.py` (pam_rssh's exact sequence, 18 checks; reads the pinned key from
  `/etc/authorized_keys/$USER.keys`).
- `MainActivity`, `AgentService`, `Keys`, `StartReceiver` have no automated coverage (Keystore and
  biometrics need hardware). Pure logic lives in `Approval`, `AgentProtocol`, `SshSig`, `Net` so it
  can be tested on the JVM; keep it that way.

## Source map

| Path (`app/src/main/java/com/ritwick/sudostamp/`) | Responsibility |
|---|---|
| `AgentProtocol.kt` | ssh-agent framing; only REQUEST_IDENTITIES and SIGN_REQUEST; `refusal()` = sign policy (our key, exactly 32 bytes) |
| `AgentService.kt` | Foreground service: serial TCP listener on 7777, LAN-only peers, per-connection budget, parks one `Approval`, wake lock while pending, notifications |
| `Approval.kt` | One pending request; resolves exactly once (approve/deny/timeout) |
| `Keys.kt` | Keystore EC P-256 key, fresh strong biometric per use, invalidation detection |
| `SshSig.kt` | SSH key blob, authorized_keys line, DER -> SSH signature blob; no crypto |
| `MainActivity.kt` | Setup screen + approval flow; `sync()` is the single place that reconciles UI and prompt with the service |
| `KnownHosts.kt` | Hosts approved before (first-host warning) |
| `StartReceiver.kt` | Restarts the listener on boot and app update |
| `Ui.kt` | The design system: colours, type, cards, pills, buttons, checklist rows, the width-capped column |
| `FingerprintView.kt`, `ResultMark.kt` | The animated mark (radar, or countdown ring on approval); the drawn check/cross result |
| `Net.kt` | Address helpers, LAN check |

UI text lives in `res/values/strings.xml`. Screenshots: the BiometricPrompt is a secure window, so
`screencap` shows it black -- that is not a rendering bug.

`tools/`: `install.sh` (host installer, every platform), `pam_check.py` (authenticates one PAM
service via libpam; replaces pamtester), `sudostamp-is-local.sh` (PAM gate: exit 1 under
sshd/sshd-session/mosh-server), device probes, `verify.sh`, `verify_ssh_sig.py`,
`check-secrets.py`. `tools/test/`: `mock_agent.py` (software-key stand-in for the phone,
loopback only, tests only) and `e2e.sh` (the host side end to end in a throwaway container).

Host side, per distribution, without a phone:

```sh
podman run --rm -v "$PWD":/src:ro <image> bash /src/tools/test/e2e.sh   # CI: host-e2e matrix
```

Do not edit `e2e.sh` while a run is reading it: bash reads scripts as it goes. Copy the tree to
a snapshot first if you need to keep working. Runtime state outside the repo: the key in the phone's TEE,
`/etc/authorized_keys/<user>.keys`, `/etc/pam.d/sudo`, `/usr/local/sbin/sudostamp-is-local`.

## Conventions

- Zero third-party runtime dependencies is a security property: `dependencies {}` holds JUnit
  (test-only) and nothing else. No AndroidX.
- `minSdk = 30` is the floor of the hard gate (`setUserAuthenticationParameters`). Do not lower it.
- Comments explain WHY, usually the failure that taught it. Keep that density and tone.
- Fail closed: every error path in the agent ends in `SSH2_AGENT_FAILURE` or a closed socket,
  never a signature. Every error path in the host tooling ends in the password still working.
- `.editorconfig`: UTF-8, LF; 4-space kt/kts/xml, 2-space yml/sh.
- A verified change is committed **and pushed** in the same breath, so CI always runs the newest
  commit; committed-but-unpushed work counts as unfinished.
- Commits: imperative subject, a body that says why and what was verified. Log notable changes
  with evidence in `docs/STATUS.md` and user-visible ones in `CHANGELOG.md`; bump `versionCode`.

## Pitfalls (each one cost a session)

1. pam_rssh sends REQUEST_IDENTITIES then SIGN_REQUEST on **one** connection. Serve frames until
   EOF; `readFrame` returns `null` on a clean EOF. A test that reconnects per request hides this.
2. `POST_NOTIFICATIONS` must be requested at runtime; the notification *is* the prompt. Symptom:
   only `Suppressing notification … by user request` in logcat.
3. Channel importance is frozen at creation: `sudostamp-listener` (LOW) and `sudostamp-approval`
   (HIGH) must stay separate channels.
4. A visible activity gets no `onResume` when a request lands: the service calls `onChange`, and
   `sync()` prompts. Prompt only from a resumed activity.
5. A request must resolve exactly once (`Approval`): the listener's timeout and a late fingerprint
   race. Show "Approved" only when `approve()` returned true.
6. `System.nanoTime` and Java timeouts stop while a dozing phone is suspended. Budgets use
   `SystemClock.elapsedRealtimeNanos()`; the approval wait holds a wake lock.
7. Approval flash then `finishAndRemoveTask()` after 750 ms; a new request cancels the close
   (`ui.removeCallbacksAndMessages(null)`). Use the `Handler` field, not `View.postDelayed`.
8. SSH ECDSA signatures are 70–74 bytes (length-prefixed mpints, `0x00` pad on a set top bit).
   A checker expecting 64 is wrong; `SshSig` is right.
9. `verify.sh` needs `--rerun-tasks` or Gradle reports green having run nothing; results are under
   `test-results/testDebugUnitTest/`. apksigner/aapt2 need `java` on PATH.
10. pam_rssh args: no spaces inside any argument; `${user}` not `%u`; always set `ssh_agent_addr`
    (unset falls back to `$SSH_AUTH_SOCK`); root-owned `auth_key_file` and directory.
11. In `Paint().apply { }`, a bare `color` is the Paint's own property: a parameter named
    `color` is shadowed, and `color = color` silently paints black. Name it `tint`.
12. After deleting or renaming resources, a stale incremental build can fail with
    `resource … not found`; `./gradlew clean` first.
13. Notification channels must exist before the user can configure them: `ensureChannels()` runs
    at start. And `cmd notification set_dnd on` is *total silence*, where nothing breaks through;
    test the channel override with `set_dnd priority`. Samsung's One UI has no per-channel
    override switch at all; its DND page has an app allow-list, which is where the app links.
14. The installer inserts a marked block (`# >>> SudoStamp >>>`) above the first auth rule and
    never rewrites the rest of the file. Debian's first auth rule is `@include common-auth`;
    openSUSE has no `/etc/pam.d/sudo` at all until an override is copied from `/usr/lib/pam.d`.
15. pam_rssh v1.2.1's lockfile needs Rust >= 1.88; Debian 13 and Ubuntu 24.04 ship older. Install
    only commands that are missing: RHEL images carry curl-minimal, and asking for `curl` is a
    package conflict. Minimal images lack diffutils, so tests compare with `cksum`.
    openSUSE sudo defaults to `targetpw` (authenticates as root, so pam_rssh looks up
    root.keys and never asks the phone). Under `pipefail`, `cat a b | grep` fails when `a` is
    missing even if grep matched: it once silently skipped that whole test block.
16. A release-signed APK cannot be installed over a debug-signed one (different keys): switching
    means uninstalling, which deletes the Keystore key and needs a new `install.sh stage`.
    `docs/RELEASING.md`. In CI YAML, a script line containing `: ` inside a plain scalar parses
    as a mapping and invalidates the whole pipeline: quote the line.
17. The release build is shrunk by R8 (~110 KB) with no `-keep` rules. Anything reflection-like
    would break it silently, and unit tests run on the unshrunk code, so after touching
    `proguard-rules.pro`, the manifest or anything loaded by name, re-test the shrunk, signed
    build on a device: approval, Deny from the notification, restart on update
    (`docs/RELEASING.md`).
18. Dependency verification (`gradle/verification-metadata.xml`) must be regenerated after any
    dependency or AGP/Kotlin bump, FROM AN EMPTY CACHE in the CI image, or CI fails on artifacts
    your local cache already had (parent POMs, `.module` files). See docs/RELEASING.md.
19. The installer must never let root open, copy or chmod a path inside a user-owned directory:
    read it with `sudo -u "$TARGET_USER" cat`, write the result as root. Root temp files go in
    `root_tmp`. Python as root is `python3 -I`.
20. `adb install -r`, never uninstall: uninstalling destroys the Keystore key, and the host's pinned
    key no longer matches.
