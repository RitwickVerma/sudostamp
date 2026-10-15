# Security Policy

## Reporting a vulnerability

Use GitLab's **confidential issue** on this project (`Issues → New issue → mark as confidential`),
or email **verma1997@gmail.com** (already public in this repo's commit metadata).

Please include the affected file/function, what an attacker gains, and a minimal reproducer. There
is no bounty. Expect an acknowledgement, and a fix or a reasoned "won't fix" — this is a one-person
project with no support contract.

## What SudoStamp is for

It replaces *typing a password* for `sudo` with *touching the phone's fingerprint sensor*. It is a
convenience with a hardware-enforced gate, built so that every failure falls back to the password.
It is **not** a second factor in the stack described here: the password still works on its own, by
design, so nobody is locked out by a dead phone.

## Trust boundaries

| Component | Trusted for | Provided by |
|---|---|---|
| `pam_rssh` on the host | generating the challenge, verifying the signature, failing closed | third party ([z4yx/pam_rssh](https://github.com/z4yx/pam_rssh)) |
| `/etc/authorized_keys/<user>.keys` | which key may approve | root-owned file; pam_rssh does no ownership checks itself |
| Phone TEE / StrongBox | holding the key, refusing to sign without a fresh strong biometric | Android Keystore |
| The phone app | showing *who* is asking, relaying the challenge, encoding the signature | this repo |
| The LAN | nothing | — |

The app never verifies anything and holds no secret it could leak: the private key never leaves
the secure hardware.

## Threat model

| Threat | Outcome |
|---|---|
| Malware on the phone tries to sign | **Fails.** The key requires a fresh strong biometric for every use, enforced by the TEE. |
| Someone who knows the phone's PIN enrolls their own finger | **Fails.** Enrollment invalidates the key (`setInvalidatedByBiometricEnrollment(true)`); the app says so and the password path takes over until a new key is pinned. |
| LAN attacker asks the phone to sign | Sees nothing useful: the request needs the user's finger. A request for any key but ours, or any payload that is not a 32-byte challenge, is refused **without** prompting. |
| LAN attacker obtains a signature (user approved their request) | It is over their own 32 bytes. pam_rssh issues a fresh random challenge per attempt, so it cannot be replayed into a sudo; and since only 32-byte payloads are ever signed, it cannot be an SSH login or `SSHSIG` signature either. |
| Eavesdropper on the LAN | Sees the public key, a random challenge and its signature. None of it is reusable. There is deliberately no TLS: the signature is the security, not the channel. |
| MITM / ARP spoof between host and phone | Can relay or drop, cannot forge. Dropping means the password prompt. |
| Impostor or man in the middle while you run `install.sh setup` | **Pairing**: the phone commits to its key before seeing the computer's nonce, then both show a 6-digit code that you type into the computer. An attacker cannot steer either code: one-in-a-million per attempt, and the phone allows one attempt per *Pair a computer* tap (a second attempt aborts with a warning), so the code cannot be ground down. Nothing is installed or pinned unless the codes match. Tested in CI with a relaying man in the middle. Scripted alternatives: `--fingerprint` (full SHA-256) or `--key` (pasted, no network). |
| Fake phone on the LAN answers discovery | Discovery is a convenience only: whatever it finds still has to pass pairing. A fake answer can waste an attempt, never pin a key. The phone advertises only while its pairing screen is open. |
| Impostor smuggles a second key into the pinned file (a newline in the key comment) | **Fixed in the 2026-10-15 audit.** The phone's answer is parsed strictly (one P-256 key, nothing else), its comment is discarded, and exactly one line is written. Covered by the end-to-end test. |
| Someone spams approval requests, hoping for a tired tap ("MFA fatigue"), e.g. on café Wi-Fi | A host that has never been approved is refused **without asking** for 30 s after each denial or timeout. Your own (known) hosts are never silenced. |
| Class 3 face unlock approves at a glance | No: the prompt requires explicit confirmation for passive biometrics. |
| Internet host reaches the phone (e.g. a carrier giving mobile data a public IP) | Refused before a byte is read: only RFC 1918, link-local and loopback peers are served. Carrier NAT (100.64/10) is refused too. |
| Overlay app draws over the approval screen | Hidden on Android 12+ (`setHideOverlayWindows`). The biometric prompt itself is system UI. |
| Another app adopts the approval screen into its task ("StrandHogg") | `taskAffinity=""` on the activity. |
| Unprivileged user edits the pinned key | Root-owned directory and file; the installer creates both. |

## Residual risks — accept these knowingly

- **Do not reuse the PAM line outside `sudo`.** pam_rssh substitutes `${user}` (the raw PAM user
  name) into the key file path. In `sudo` that name is the already-logged-in caller. In `sshd`,
  `login` or a display manager it is whatever was typed at the prompt *before* authentication, so
  a name like `../../home/mallory/x` would make pam_rssh read a key file the attacker wrote.
- **Approval confusion is the real attack.** Anyone on the LAN can make the phone ask, and can time
  the request to land when you expect your own. Mitigations: the requesting host is shown in the
  notification and on screen; a host never approved before is flagged; Deny is one tap from the
  notification; unanswered requests die after 60 s. If a request arrives that you did not cause,
  deny it.
- **The prompt cannot name the command.** pam_rssh sends an opaque challenge. A process running as
  you on the host can start a sudo and you will see a request from the right host — the same
  position as a password prompt that process could have shown you.
- **Availability on the LAN is not defended.** A hostile LAN client can keep the single listener
  busy (each connection is bounded to 30 s of non-approval time and 8 frames, but it can reconnect)
  or keep posting requests. The result is the password prompt, never a bypass. Segment the network
  if that matters to you.
- **The local-vs-remote gate is a convenience, not a boundary.** `tools/sudostamp-is-local.sh` only
  chooses whether the host's own fingerprint reader is tried first; a process detached from its SSH
  session reads as local. Either way a physical finger is still needed, and the gate fails open to
  "local" so it can never lock anyone out.
- **No key attestation.** The app does not prove to the host that the key is hardware-backed. The
  key is created hardware-backed and non-exportable; attestation would prove it to a third party.
- **The password still works.** That is the point of the design, and it means SudoStamp adds no
  protection against someone who knows your password.

## Never commit credentials

This repository must contain **no** keystores, signing keys, tokens or passwords. `.gitignore`
covers the usual shapes, and a client-side scan enforces it, because GitLab's server-side secret
push protection is not available on the free tier:

```bash
python3 tools/check-secrets.py --staged     # pre-commit
python3 tools/check-secrets.py --all        # whole tree (CI runs this)
```

Debug builds are signed with the developer's local `~/.android/debug.keystore`, which never enters
the tree.

## The host installer runs as root

`tools/install.sh` is run with `sudo` and takes several precautions because it touches files a
regular user controls:

- **Root never follows a path inside a user-owned directory.** The pam_rssh build happens as the
  invoking user; the finished module, the gate script and the rustup binary are read, checked and
  `chmod`ed *as that user*, then written by root. A symlink planted in the build directory (to
  `/etc/shadow`, say) therefore fails with "permission denied" instead of being copied or
  `chmod`ed by root. The module must also be a real shared library (ELF or Mach-O) before it is
  installed.
- **Temporary files** live in one private, root-only directory created from an explicit `/tmp`
  template, never at names derivable from a world-listable directory, and never under a
  caller-supplied `TMPDIR`.
- **Python runs isolated** (`python3 -I`), so a module file in the current directory cannot be
  imported into a root process.
- **`--phone` is validated strictly** (a hostname or IPv4 address and a port), because it is
  written into a PAM configuration line.
- **Settings are arguments, not `sudo -E`.** `sudo -E` hands the caller's whole environment to root
  (`APT_CONFIG` survives sudo's filter, for example); the documented commands use plain `sudo`.
- The local-vs-remote gate script that `pam_exec` runs as root sets its own `PATH`.

What is inherent and stays true: you run code from your checkout as root. Read `tools/install.sh`
first, as with any installer, and keep the checkout somewhere only you can write.

## Supply chain

- The app has no third-party runtime dependencies (`dependencies {}` holds only JUnit, test-only).
- The Gradle distribution is pinned by SHA-256 (`distributionSha256Sum`), and the committed
  `gradle-wrapper.jar` matches Gradle's published checksum for 9.3.1.
- CI's Android cmdline-tools download is pinned by SHA-256, cross-checked against the SHA-1 in
  Google's own repository manifest.
- On the host, `install.sh` prefers a distribution or AUR/ports package of pam_rssh. Otherwise it
  builds tag `v1.2.1` and refuses unless the checkout is exactly commit `e8dd046c…` (a tag can be
  moved, a commit cannot), with `cargo --locked`, as the invoking user, never as root.
- If the distribution's Rust is too old, it can fetch the official `rustup-init` over HTTPS,
  check it against the SHA-256 rust-lang publishes, and use it in the build directory only; it is
  deleted with the build. It asks first (or needs `SUDOSTAMP_ALLOW_RUSTUP=1`).
- **Gradle dependency verification** (`gradle/verification-metadata.xml`): every plugin and library
  the build downloads (314 components: the Android Gradle Plugin, the Kotlin compiler, lint, JUnit
  and their dependencies) is pinned by SHA-256, and Gradle refuses a mismatch. Tested by corrupting
  one checksum. The file was generated from an empty cache inside the CI image, so it covers
  exactly what CI downloads.
- The two CI jobs that touch a release (`build-release`, which holds the signing key, and
  `publish-release`) use images pinned by digest, not floating tags.
- `tools/test/mock_agent.py` signs with a software key and exists only for automated tests: it
  binds loopback only and its key is generated per run. It must never stand in for the phone.

## CI runner

This public project's pipelines run on a self-hosted runner. GitLab runs pipelines for merge
requests from forks in the fork's own project by default, so outside contributors cannot reach
it unless a maintainer explicitly starts a fork's pipeline in this project. Keep it that way, and
on the runner keep `privileged = false` and no Docker socket in job containers: a job that could
escape its container would be inside the owner's network. Job logs are public; they name the
runner but contain no addresses or credentials (checked).

## Supported versions

`master` only. There are no releases; build from source.
