# SudoStamp — status

**Approve `sudo` with the phone's fingerprint, LAN-only, with the fingerprint enforced by
hardware.** In daily use on one Arch Linux host with a Samsung Galaxy foldable (Android 17) since
2026-09. This file is the verification log: what was checked, how, and what it showed. Release
notes are in [CHANGELOG.md](../CHANGELOG.md).

## 2026-10-14 — polish pass (app 1.2.2)

Re-read every file and walked every state on a throwaway emulator (Android 16), with screenshots.

| found | how | now |
|---|---|---|
| "Create key" with no fingerprint enrolled failed with an exception toast | read | onboarding offers enrollment (opens the system's lock-then-enroll flow, verified) or says the phone lacks a strong sensor; it flips to "Create key" by itself on return (verified) |
| the setup screen's DND **Allow** opened Settings and it closed at once | tapped it | the approval channel did not exist until the first request; both channels are now created at start (`dumpsys`: both present on a fresh install), and Allow lands on the channel page |
| DND said Ready while still silencing | the system intercepted a request (`mIntercept=true`) with the override on | that DND was total silence, which no app passes; now detected and named. In priority mode with the override on: `mIntercept=false`, the heads-up appeared |
| notification body cut off ("touch the sens…") | screenshot | "From <host> · tap to approve" |
| same bell icon for notifications and DND | screenshot | DND has its own glyph |

Full run through priority DND on the emulator: pop-up, tap from the shade, fingerprint →
`simulate_pam_rssh.py` **18/18**. Timeout measured at 60.0 s (`identities requested` 27:36.691 →
`denied` 28:36.697). 4 gates, lint clean. Phone: `versionName=1.2.2`, probe 11/11, key exact; it is
in priority DND with the override off (`mBypassDnd=false`), so the screen now shows the warning.

## 2026-10-14 — first real sudo on 1.2, and a silent approval (app 1.2.1)

`sudo -k && sudo true` on the host: the host's own reader timed out (~15 s), then the phone
signed — `signed via biometric`, sudo exit 0 after 29 s. But the approval made no pop-up. The
phone's log showed why: Do Not Disturb was on (`zen_mode=1`), `isIntercepted` for the approval
notification, which was also auto-grouped under the listener notice. The channel itself was
correct (importance HIGH). 1.2.1 gives each notification its own group and flags DND on the setup
screen with a link to the channel's override switch. Installed on the phone (`versionName=1.2.1`,
listener up); the DND state itself is the user's setting and was left alone.

## 2026-10-14 — interface redesign (app 1.2)

Onboarding, setup checklist, approval with countdown, drawn results — see CHANGELOG. Verified on a
Pixel 7 emulator (Android 16, PIN + enrolled virtual fingerprint), every screen screenshotted:

| check | evidence |
|---|---|
| full approval through the new UI | `simulate_pam_rssh.py` over `adb forward` → **18/18 PASSED**, twice; `signed via biometric` → `approved: closing the app` 750 ms later |
| Deny button | `denied` in the log, the probe got FAILURE, "Denied" result shown |
| states | onboarding, Ready, Notifications off (revoked + user-fixed), landscape (column capped, scrolls) |
| found by looking | the result mark painted black (a shadowed `color` in `Paint().apply`), and button icons pinned to the edge; both fixed and re-shot |
| on the real phone | `adb install -r` → `versionName=1.2`, listener restarted on update, `reuse_connection_test.py` 11/11, pinned key byte-exact |

`tools/verify.sh` all 4 gates; lint no errors. Not exercised: the first-host warning on the phone
itself and the boot restart (emulator showed the warning path's opposite — a known host — only).

## State after the security review (2026-10-14, app 1.1)

| layer | evidence |
|---|---|
| JVM unit tests | 31 tests (ApprovalTest 6, NetTest 2, AgentProtocolTest 15, SshSigTest 8), 0 failures |
| independent signature check | `tools/verify_ssh_sig.py`: ssh-keygen parses the key blob, `cryptography` verifies the signature, tamper and wrong-message rejected |
| build | `lintDebug` no errors; `assembleDebug` OK; `apksigner` VERIFIED; `tools/verify.sh` all 4 gates PASS |
| CI hygiene job | run in its real image (`debian:stable-slim`, podman): secret scan clean, shellcheck clean, tools compile |
| installed over the live app | `adb install -r` → `Success`, `versionName=1.1`, Keystore key kept (pinned key still byte-exact with the phone's) |
| restarts itself after an update | without opening the app: `listener started on android.intent.action.MY_PACKAGE_REPLACED` → `listening on 7777`, service `isForeground=true` |
| hardening on the device | `tools/reuse_connection_test.py --slow` → 12/12: wrong key, 64-byte payload and `SSHSIG` payload all refused **without a prompt**; 9th frame on one connection cut off; a slow-drip client cut off after 35 s (30 s budget + one 5 s drip) on a dozing phone |
| generated PAM stack | `tools/install.sh`'s stack is line-for-line identical to the one in production |

**Not yet re-verified with a finger on 1.1:** the approval itself (`tools/simulate_pam_rssh.py`,
18 checks), the new first-host warning, Deny from the notification, the key-invalidated screen and
the boot restart. They need a human at the phone; the protocol and signing code they exercise is
unchanged from 1.0, which passed 18/18.

## 2026-10-14 — security review, hardening, and public release preparation

A full review of the app, the host tooling and the repo, ahead of making it public.

**Real defects fixed**

1. **A late fingerprint was reported as an approval.** The listener gave up after 60 s while the
   biometric prompt stayed up; a touch after that flashed "Approved" and closed the app although
   the agent had already answered FAILURE. Worse, the stale prompt held the "prompting" flag, so the
   *next* sudo was never prompted at all. Now each request resolves exactly once (`Approval`, a
   single `CompletableFuture`), the UI says "Approved" only if its signature was the one delivered,
   and a prompt whose request is gone is cancelled.
2. **The 60 s timeout was not 60 s on a sleeping phone.** Java timeouts run on a clock that stops
   while the CPU is suspended, and pam_rssh sets no timeout of its own — so with the screen off, a
   sudo could hang until something woke the phone. A partial wake lock is now held while (and only
   while) a request is pending.
3. **The agent would sign anything for anyone on the LAN who got a touch.** It now signs only
   pam_rssh's 32-byte challenge, refusing SSH-login and `SSHSIG`-shaped payloads unprompted, and it
   serves only private-range peers (mobile data can carry a public address).
4. **A slow-drip client could hold the single listener indefinitely** (soTimeout restarts on every
   byte). Connections now get a 30 s budget of non-approval time and 8 frames. The first version of
   that budget used `System.nanoTime`, and the device showed it holding past 45 s on a dozing phone —
   it counts awake time only. It now uses `elapsedRealtimeNanos`.
5. **A key invalidated by a new fingerprint enrollment looked healthy** ("listening") while every
   sudo failed. The setup screen now detects it and offers a reset.
6. **"listening" was shown whenever a key existed**, whether or not the socket was bound; a bind
   failure stopped the service silently. The screen now shows the listener's real state, and binding
   retries.
7. **The listener did not come back after a reboot or an app update** until the app was opened.
   A boot/update receiver restarts it (verified on the device for updates).
8. **`install.sh apply` wrote `/etc/pam.d/sudo` in place** — an interrupted write would leave a
   truncated file. It now writes beside it and renames atomically (rollback too).
9. **`install.sh stage` pinned whatever key answered at the phone's address** (trust on first use
   over plain TCP). It now shows the fingerprint and pins only after it is confirmed against the
   phone screen.
10. **The app's icons were derived from downloaded stock images** of unclear licence. Replaced with
    Google's Material Symbols fingerprint (Apache-2.0), as vector drawables; the stock images are
    gone from the tree.

**Hardening and hygiene:** first-host warning on the approval screen; Deny action on the
notification; overlays hidden over the app (Android 12+); `taskAffinity=""`; strict DER parsing
(every length must account for every byte); no per-frame allocation in the animated mark; Wi-Fi
address preferred over a cellular one; the PAM gate also recognises OpenSSH 9.8+'s `sshd-session`;
Gradle distribution and CI's cmdline-tools pinned by SHA-256; host tooling made generic
(`SUDOSTAMP_PHONE`, the invoking user) and limited to the PAM layout it was tested on; `verify.sh`
runnable from any checkout; MIT licence, SECURITY.md, NOTICE, CONTRIBUTING.md, CHANGELOG.md.

## 2026-09-15 — the app closes itself after an approval

An approval used to flash "Approved ✓" and then drop back to the setup screen, parking the phone
on a screen nobody asked for. The flash (750 ms — a window that vanishes the instant the sensor
matches reads as a crash) is now followed by `finishAndRemoveTask()`, which also keeps the screen
out of recents. The listener lives in the foreground service and is untouched: verified after the
close with `dumpsys` (`isForeground=true`) and a fresh TCP connect, and by a second full approval
60 s later (18/18 again).

## 2026-09-15 — CI

GitLab CI: unit tests followed by `tools/verify_ssh_sig.py` in the same job (structure tests can
pass on bytes no SSH implementation accepts; the external check rules that out), lint, and a debug
APK. The SDK comes from pinned Google cmdline-tools, cached, so CI never depends on a local path.
The whole pipeline was dry-run in the real CI image before the first push.

## 2026-09-14 — review fixes

Seven defects from reading the whole repo, one fatal on older devices:

1. **`minSdk` was 28 but the hard gate is API 30.** `setUserAuthenticationParameters(0,
   AUTH_BIOMETRIC_STRONG)` arrived in Android 11; key creation would have thrown
   `NoSuchMethodError`. Lint caught it.
2. Key creation did not start the listener.
3. Request-handling errors closed the socket with no reply; now a proper `SSH2_AGENT_FAILURE`.
4. A 120 s idle timeout let silent connections squat the single worker; now 30 s.
5. `authenticate()` can throw (no biometrics enrolled) and stalled the request; now denies.
6. The prompt could be raised from a non-resumed activity and fail instantly; now gated.
7. A stale "notifications off" warning after toggling the permission in Settings.

Also: no backup or device transfer of anything (`dataExtractionRules`), `usesCleartextTraffic`
removed (meaningless for raw sockets), and the framing layer got its first tests.

## 2026-09-14 — three bugs that broke every authentication

The app "worked" in an earlier session only because the test differed from real use. Found by
replaying pam_rssh's exact code path against the phone and reading its source.

1. **One frame per connection.** pam_rssh keeps one connection open and sends
   `REQUEST_IDENTITIES` *then* `SIGN_REQUEST` over it. The agent answered one frame and hung up, so
   every sign request hit a dead socket — no error, no log line. An end-to-end test that opened a
   new connection per request passed against the broken server.
2. **`POST_NOTIFICATIONS` never requested at runtime** (Android 13+). The only symptom was
   `Suppressing notification … by user request` in logcat. The notification *is* the prompt, so the
   entire approval path was dead.
3. **A request arriving while the app was already visible** got no `onResume`, so nothing prompted.

And two found only on hardware: the approval notification shared a channel created at
`IMPORTANCE_LOW` (Android freezes a channel's importance at creation), and the listener only
started on a button tap.

**Confirmed correct, do not "fix":** the signature encoding — SSH's form is
`string(algo) + string(string(mpint r) + string(mpint s))`, 70–74 bytes, not a raw 64; and no
`socat` is needed — pam_rssh dials TCP directly.

## Battery

One thread blocked in `accept()` when idle: no polling, no alarms, no jobs, no wake locks (one is
held only while a request is pending, ≤60 s). Audited on the device: the app does not appear in
`dumpsys cpuinfo` at idle. Requests are answered instantly even in forced Doze; the setup screen
offers the battery-optimization exemption for OEM builds that freeze foreground services.
