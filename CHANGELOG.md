# Changelog

Versions are the app's `versionName`. The host-side tooling is versioned with the repo.

## Unreleased

### Smaller release build
- The release APK is shrunk with R8 and resource shrinking: 2.2 MB -> about 110 KB. There are no
  `-keep` rules by design (no reflection or libraries; everything reached from outside is in the
  manifest). Verified on a device with the shrunk, signed build: a full approval (18/18), Deny from
  the notification, the app closing itself, and the listener restarting after an update.
  `mapping.txt` is published with each release to decode stack traces. Debug builds are unchanged.

### Releases
- Tagging `vX.Y.Z` builds a signed release APK in CI and publishes it with a SHA-256 checksum
  (`build-release`, `publish-release`). The signing key lives only in protected, masked CI
  variables; `assembleRelease` without them builds an unsigned, uninstallable APK. The job refuses
  a tag that does not match `versionName`. Setup and the debug-to-release switch (which needs an
  uninstall, and so a new key) are in `docs/RELEASING.md`.

### Host side: cross-platform
- `tools/install.sh` supports Arch, Debian/Ubuntu, Fedora/RHEL and openSUSE families (detected
  from `/etc/os-release`), plus experimental macOS (`/etc/pam.d/sudo_local`) and FreeBSD.
- It inserts one marked block above the first auth rule of sudo's existing stack instead of
  replacing the file, so every distribution's own layout and password path are kept;
  `rollback` removes exactly that block. openSUSE's vendor file is handled.
- pam_rssh comes from the AUR or ports where available, otherwise it is built from tag v1.2.1,
  verified to be commit e8dd046c, with `--locked`, as the user. A too-old distribution Rust
  falls back to a newer side package (Debian 12 `cargo-web`, Ubuntu `cargo-1.NN`) or, with
  consent, a checksum-verified rustup toolchain that is deleted after the build.
- The fingerprint is checked before anything is installed.
- Detects sudoers `Defaults targetpw`/`rootpw` (openSUSE's default), where sudo authenticates as
  root and the phone would never be asked, and prints the one-line override. Never edits sudoers.
- `test` no longer needs pamtester: `tools/pam_check.py` drives libpam directly, against a
  scratch service that only the phone can satisfy.
- `tools/test/e2e.sh` + `tools/test/mock_agent.py`: the full host flow, including a real `sudo`,
  on seven distributions in CI.

## 1.2.4 — 2026-10-14

### Fixed
- After allowing SudoStamp through Do Not Disturb, the setup screen kept saying "Silenced"
  until it was reopened. It now re-checks whenever its window regains focus, not only on resume.

## 1.2.3 — 2026-10-14

### Fixed
- Samsung's One UI has no per-channel "Override Do Not Disturb" switch, so the setup screen's
  Allow link led nowhere useful there. It now opens Do Not Disturb's own settings, where both
  One UI and stock Android list the apps allowed through, and the text says to add SudoStamp.

## 1.2.2 — 2026-10-14

### Fixed
- The approval channel only came into existence with the first request, so its Do Not Disturb
  override could not be granted beforehand, and the setup screen's link to it opened and closed
  at once. Both channels are now created when the app starts.
- The Do Not Disturb check only looked at the channel override, so in total silence or
  alarms-only modes (which no app can break through) the screen said Ready while approvals were
  silent. Those modes are now named and link to Do Not Disturb settings instead.

### Changed — polish
- Onboarding checks for an enrolled strong biometric first: it offers fingerprint enrollment,
  or says plainly that the phone cannot hold a key, instead of a failed "Create key".
- Notifications: the approval reads "Approve sudo? From <host> · tap to approve"
  with its arrival time in the header rather than the text; the listener notice is just "Ready
  to approve sudo"; no redundant large icon; both channels describe themselves in Settings, and
  the approval channel's description says to let it override Do Not Disturb.
- The countdown reads "Denied automatically in N s"; only values (fingerprint, address, host)
  are selectable; "Expired" is announced as expired, not denied, to screen readers.
- Do Not Disturb has its own icon rather than reusing the notification bell.

## 1.2.1 — 2026-10-14

### Fixed
- Approval requests arrived silently, with no pop-up, while Do Not Disturb was on: the system
  intercepted them. The setup screen now detects this ("Silenced by Do Not Disturb") and links
  straight to the switch that lets approvals through; only the user can grant it.
- The approval was auto-grouped under the "listening" notice; each notification now has its
  own group.

## 1.2 — 2026-10-14

### Changed — interface redesign
- New onboarding: what the app does in three steps, one button.
- The setup screen is a live checklist (listener, notifications, battery) with one-tap fixes and
  a single status: *Ready* only when a request can really be approved.
- **Copy setup command**: a ready-to-paste `install.sh stage` line carrying the key's
  fingerprint, so the host pins this key and no other.
- The approval screen shows a countdown ring and "N s left", the requesting host and when it
  asked, and a first-host warning.
- Results are drawn (an animated check or cross) with haptics; a denial or expiry is shown
  instead of silently returning to setup.
- Own header instead of the system title bar; edge to edge with proper insets; content capped at
  a readable width on foldables and in landscape; scrolls on short screens.
- Strings moved to resources (translatable); notifications tinted with the accent; buttons are
  real buttons for screen readers.

### Fixed
- Icons on buttons are centred with their label.

## 1.1 — 2026-10-14

### Security
- Signs only pam_rssh's 32-byte challenge; any other payload (an SSH login blob, an `SSHSIG`
  signature request) is refused without prompting.
- Serves only LAN peers (RFC 1918, link-local, loopback); anything else is dropped before reading.
- Each connection gets 30 s of non-approval time and at most 8 frames, so a slow or chatty client
  cannot hold the listener. The budget counts time the phone spends asleep.
- A request now resolves exactly once: a fingerprint that lands after the timeout is no longer
  reported as "Approved", and a prompt whose request is gone is taken down.
- Detects a key invalidated by a new fingerprint enrollment and offers a reset.
- Flags a request from a host that has never been approved before.
- Hides other apps' overlays over the app (Android 12+); `taskAffinity=""`.
- `install.sh stage` pins the phone's key only after its fingerprint is confirmed.
- `install.sh apply` and `rollback` replace `/etc/pam.d/sudo` atomically.
- Gradle distribution and CI's Android cmdline-tools pinned by SHA-256.

### Fixed
- The 60 s approval timeout held on a sleeping phone; a dozing phone could leave sudo waiting
  far longer. A wake lock is held while (only while) a request is pending.
- "listening" was shown whenever a key existed; it now reflects the bound socket, and binding
  retries instead of stopping the service.
- The listener restarts after a reboot or an app update.
- The address shown prefers Wi-Fi over a cellular address.
- The local-vs-remote PAM gate recognises OpenSSH 9.8+'s `sshd-session`.

### Changed
- Deny directly from the approval notification.
- Icons redrawn from Material Symbols "fingerprint" (Apache-2.0), replacing stock images.
- The host installer is now `tools/install.sh`, configured by `SUDOSTAMP_PHONE`; the device
  tools take the same variable and read the pinned key from `/etc/authorized_keys`.
- Released under the MIT licence.

## 1.0 — 2026-09-15

First working version: Keystore ECDSA P-256 key gated by a fresh strong biometric per signature,
a minimal ssh-agent (`REQUEST_IDENTITIES`, `SIGN_REQUEST`) over TCP for pam_rssh, approval by
notification and BiometricPrompt, staged host installer with rollback.
