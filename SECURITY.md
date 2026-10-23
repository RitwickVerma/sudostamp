# Security Policy

## Reporting a vulnerability

Use GitLab's **confidential issue** on this project (`Issues → New issue → mark as confidential`),
or email **verma1997@gmail.com** (already public in this repo's commit metadata).

Please include the affected file/function, what an attacker gains, and a minimal reproducer. There
is no bounty. Expect an acknowledgement, and a fix or a reasoned "won't fix" — this is a one-person
project with no support contract.

## Review status — read this first

SudoStamp grants root. Its code, tests and documentation were written with an AI assistant, and
have been through an AI-run security audit (2026-10-23, four independent reviews: the app, the host
installer and PAM stack, the release chain, the protocol), whose findings are fixed in 1.4.0 and
listed below. **No human security professional has reviewed it.** Until one has, treat it as you
would any young project that sits in front of `sudo`: read `tools/install.sh` and the PAM block it
writes, keep your password, and decide for yourself. Reviews are very welcome (see above).

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
| Phone TEE / StrongBox | holding the keys, refusing to sign without a fresh strong biometric | Android Keystore |
| The phone app | showing *which computer* is asking, relaying the challenge, encoding the signature | this repo |
| The LAN | nothing | — |

The app never verifies anything and holds no secret it could leak: the private keys never leave
the secure hardware.

## One key per computer

Since 1.4.0 the phone makes a separate Keystore key for every computer it pairs with. A sign
request names a key; the key names the computer; the approval screen and the fingerprint prompt
show that computer's name. Consequences:

- A signature made for one computer does not verify on another.
- A request for a key the phone did not make for a paired computer is refused **before anything is
  shown** — a device that never paired cannot put a prompt on the screen at all.
- A computer stays marked *new* until one of its requests has been approved.

Phones updated from 1.3 keep their single old key as one entry, "Computers paired before 1.4",
flagged on every request; pair those computers again and remove it.

## Threat model

| Threat | Outcome |
|---|---|
| Malware on the phone tries to sign | **Fails.** Each key requires a fresh strong biometric for every use, enforced by the TEE. A key that the Keystore would put in software is refused at creation (release builds). |
| Someone who knows the phone's PIN enrolls their own finger | **Fails.** Enrollment invalidates every key (`setInvalidatedByBiometricEnrollment(true)`); the app marks those computers and the password path takes over until they are paired again. |
| A device on the LAN that never paired asks the phone to sign | **Refused without a prompt**: its key is not one the phone made. Payloads other than a 32-byte challenge are refused without a prompt too. |
| A LAN attacker obtains a signature (the user approved their request) | It is over their own 32 bytes, with the key of the computer they named — and the prompt showed that computer's name. pam_rssh issues a fresh random challenge per attempt, so it cannot be replayed into a sudo; only 32-byte payloads are signed, so it cannot be an SSH login or `SSHSIG` signature either. |
| A relay passes one computer's challenge to the phone during another computer's sudo | The challenge must be signed with **the key of the computer that issued it**; asking for that key puts that computer's name on the prompt. Signing with the other key produces a signature the issuing computer rejects. |
| A request queued behind a real one, to read as "sudo asked twice" | Refused **without asking** for 3 s after any approval. And the fingerprint prompt opens by itself only for the request whose notification you tapped; any other request waits for a tap on *Approve*. |
| Eavesdropper on the LAN | Sees public keys, a random challenge and its signature. None of it is reusable. There is deliberately no TLS: the signature is the security, not the channel. |
| Man in the middle between computer and phone | Can drop or delay. Cannot forge, and (above) cannot make a relayed request carry another computer's name. A connection that is accepted and never answered is cut off by the host's reachability check within seconds, and the password prompt follows (see residual risks for the limit). |
| Impostor or man in the middle while you run setup | **Pairing**: the phone makes a key for this computer and commits to it, its nonce, the address it was dialled on and the address to keep, before seeing the computer's nonce; both then show a 6-digit code that you type into the computer. One-in-a-million per attempt, one attempt per *Pair a computer* tap. Tested in CI with a key-substituting man in the middle. |
| Something answers discovery first and relays pairing unchanged | **Refused** (new in 1.4.0): the phone states the address it was dialled on, and it is not the relay's. Version 1.3 pinned the real key but the relay's address. Tested in CI. |
| An attacker races the person's computer and finishes pairing first | Any second pairing attempt while the pairing screen is open cancels the pairing — **even one that already finished** — and deletes its key; the person's own computer arriving is such an attempt. A pairing that did slip through is still *new* until a request is approved, and flagged on screen until then. |
| Someone spams approval requests, hoping for a tired tap | Only paired computers can ask at all. After a denial or timeout that computer is refused without asking (5 s if trusted, 60 s if new); after 4 unapproved requests within 10 minutes, all requests are refused without asking until the window clears. Never keyed by IP address, so changing addresses does not help. |
| Class 3 face unlock approves at a glance | The prompt asks for explicit confirmation for passive biometrics (`setConfirmationRequired`; Android documents this as a hint the system may ignore). |
| A device on mobile data, a VPN or another subnet reaches the phone | **Refused before a byte is read**: the peer must be inside the subnet of the Wi-Fi or Ethernet address the connection arrived on, and a LAN-range address. Loopback only in debug builds. |
| Overlay app draws over the approval screen | Hidden on Android 12+ (`setHideOverlayWindows`); on Android 11 touches through an overlay are dropped. The biometric prompt itself is system UI. |
| Another app adopts the approval screen into its task ("StrandHogg") | `taskAffinity=""` on the activity. |
| Unprivileged user edits the pinned key | Root-owned directory and file; the installer creates both. |
| A replaced installer in the release downloads | The package registry accepts re-uploads, so files there can change after publishing. The installer and `SHA256SUMS` are signed (`ssh-keygen -Y`, key in `keys/allowed_signers`, also carried in the app); the documented command verifies before running anything. |

## Residual risks — accept these knowingly

- **Do not reuse the PAM line outside `sudo`.** pam_rssh substitutes `${user}` (the raw PAM user
  name) into the key file path. In `sudo` that name is the already-logged-in caller. In `sshd`,
  `login` or a display manager it is whatever was typed at the prompt *before* authentication, so
  a name like `../../home/mallory/x` would make pam_rssh read a key file the attacker wrote.
- **The prompt cannot name the command.** pam_rssh sends an opaque challenge. A process running as
  you on a paired computer can start a sudo and you will see a request from that computer — the same
  position as a password prompt that process could have shown you.
- **A stalling peer after the reachability check.** pam_rssh sets no timeout on its socket. The
  installer puts a check in front of it (`sudostamp-probe`: the phone must answer with this user's
  key within 4 s, or pam_rssh is skipped), which covers a dead phone, a different device on the
  phone's old address, and anything that accepts and never answers. Something that answers that
  check and then stalls pam_rssh — a man in the middle on your LAN — can still hold sudo until you
  press Ctrl-C. Fixing that needs a timeout in pam_rssh itself. On macOS and FreeBSD (OpenPAM, no
  way to skip a line) there is no check at all.
- **Pairing proves the key, not the person.** Whoever completes pairing while the pairing screen is
  open gets a key. The defences are the cancellation and *new* flag above; read the name on the
  first request from a newly paired computer.
- **Availability on the LAN is not defended.** A hostile LAN client can keep the single listener
  busy (each connection is bounded to 30 s of non-approval time and 8 frames, but it can reconnect).
  The result is the password prompt, never a bypass.
- **The local-vs-remote gate is a convenience, not a boundary.** `tools/sudostamp-is-local.sh` only
  chooses whether the host's own fingerprint reader is tried first; a process detached from its SSH
  session (tmux, screen) reads as local. Either way a physical finger is still needed, and the gate
  fails open to "local" so it can never lock anyone out. A `pam_fprintd` line you added to the sudo
  stack yourself is not covered by the gate at all.
- **No key attestation.** The phone does not prove to the computer that a key is hardware-backed; it
  checks that itself at creation.
- **Tethering is not a LAN.** A computer connected through the phone's own hotspot is not on a
  Wi-Fi or Ethernet network the phone *joined*, so it is refused.
- **The password still works.** That is the point of the design, and it means SudoStamp adds no
  protection against someone who knows your password.

## Never commit credentials

This repository must contain **no** keystores, signing keys, tokens or passwords. `.gitignore`
covers the usual shapes, and a scan enforces it, because GitLab's server-side secret push
protection is not available on the free tier:

```bash
python3 tools/check-secrets.py --staged     # pre-commit (scripts/setup-dev.sh installs the hook)
python3 tools/check-secrets.py --all        # whole tree (CI runs this)
```

It refuses key and keystore files by name (`.jks`, `.keystore`, `.p12`, `.pem`, `.key`, `.age`)
and flags credential-shaped text, including age secret keys and the signing vault's entries. CI
also runs `gitleaks` over the full history. Debug builds are signed with the developer's local
`~/.android/debug.keystore`, which never enters the tree.

## Release signing

- **APK**: one RSA-4096 key, certificate SHA-256
  `7B:CB:0B:51:24:61:97:B9:BB:99:77:9E:09:A3:AD:CB:BA:EB:2D:59:A0:ED:EC:F8:D2:E8:BE:67:84:4D:06:57`,
  checked against that pin by `scripts/release.sh` on every build.
- **Installer and `SHA256SUMS`**: an ed25519 key, `ssh-keygen -Y sign`, namespace
  `sudostamp-release`; the public half is `keys/allowed_signers`.

Both keys exist only age-encrypted in the maintainer's private infrastructure repository, opened by
a dedicated age key that unlocks nothing else. **CI never signs**: `scripts/release.sh` decrypts
both into tmpfs on the maintainer's machine, wipes them when it exits, and keeps Gradle's execution
history (which records hashes of the keystore passwords) inside the same tmpfs directory. The
self-hosted runner is shared with other projects and runs unprotected branches, and GitLab hands
protected variables to every job of a protected ref, so a signing key there would be one compromised
container image away from leaking — and a stolen Android signing key can never be revoked.

## The host installer runs as root

`tools/install.sh` is run with `sudo` and takes several precautions because it touches files a
regular user controls:

- **Root never follows a path inside a user-owned directory.** The pam_rssh build happens as the
  invoking user; the finished module, the helper scripts and the rustup binary are read, checked and
  `chmod`ed *as that user*, then written by root. The module must be a real shared library (ELF or
  Mach-O) before it is installed. On macOS it goes to `/opt/sudostamp/lib`, and the installer
  refuses unless every directory on that path is root-owned and writable by no one else (Intel
  Homebrew makes `/usr/local/lib` the user's).
- **Its own `PATH`.** Where sudoers sets no `secure_path`, a `python3` early in the caller's PATH
  would otherwise run as root.
- **Temporary files** live in one private, root-only directory created from an explicit `/tmp`
  template, never under a caller-supplied `TMPDIR`.
- **Python runs isolated** (`python3 -I`), so a module file in the current directory cannot be
  imported into a root process.
- **`--phone` is validated character by character, then parsed**: an IPv4 address or a bracketed
  IPv6 address and a port, nothing else — no host names, no second line (a newline would have been
  a second PAM rule).
- **The PAM block cannot authenticate by itself.** Only `pam_fprintd` and `pam_rssh` can say yes,
  both `sufficient`; the helper lines use `[success=ignore ignore=ignore default=1]`, so their
  success never counts towards the result (1.3's `success=ok` did, which a stack with no required
  module below would have turned into a bypass). Tested in CI with real libpam.
- **Rollback refuses damaged markers** (a BEGIN without its END would have removed the whole auth
  stack, password included), and refuses to leave a file with no auth rule.
- **Backups live in `/var/lib/sudostamp/backups`** (root-only), not in `/etc/pam.d`, where every
  file is a PAM service any program may name. The scratch test service is removed after each test.
- **Settings are arguments, not `sudo -E`**, which would hand the caller's whole environment to root.

What is inherent and stays true: you run code from the internet as root. Verify the signature (the
documented command does), read `tools/install.sh` first, as with any installer.

## Supply chain

- The app has no third-party runtime dependencies (`dependencies {}` holds only JUnit, test-only).
- The Gradle distribution is pinned by SHA-256 (`distributionSha256Sum`), and the committed
  `gradle-wrapper.jar` matches Gradle's published checksum for 9.3.1.
- **Gradle dependency verification** (`gradle/verification-metadata.xml`): every plugin and library
  the build downloads is pinned by SHA-256 in strict mode, and Gradle refuses a mismatch. Checksums,
  not signatures.
- CI's Android cmdline-tools download is pinned by SHA-256, cross-checked against the SHA-1 in
  Google's own repository manifest.
- On the host, `install.sh` builds pam_rssh tag `v1.2.1` and refuses unless the checkout is exactly
  commit `e8dd046c…` (a tag can be moved, a commit cannot), with `cargo --locked`, as the invoking
  user, never as root — on every distribution. (1.3 installed it from the AUR with an AUR helper
  when one was present: no pin, no review. Removed.) FreeBSD uses the ports package.
- If the distribution's Rust is too old, it can fetch the official `rustup-init` over HTTPS and
  check it against the SHA-256 rust-lang publishes (same origin, so this guards against corruption
  rather than a compromised server), and use it in the build directory only. It asks first.
- The AUR package (`sudostamp`) depends on the AUR's `pam_rssh`, so on that path you trust that
  package's maintainer instead of the pinned build.
- `tools/test/mock_agent.py` signs with software keys and exists only for automated tests: it binds
  loopback only and its keys are generated per run. It must never stand in for the phone.

## CI runner

This public project's pipelines run on the owner's self-hosted runner, which also serves other
projects. No signing key and no secret is given to CI. Merge requests from forks run in the fork's
own project by default, so outside contributors cannot reach the runner unless a maintainer starts a
fork's pipeline here; keep it that way, and on the runner keep `privileged = false` and no Docker
socket in job containers. Job logs are public; they contain no addresses or credentials.

## Supported versions

The latest release only. Fixes ship as a new release; there are no backports.
