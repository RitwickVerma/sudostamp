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

For sudo the app verifies nothing and holds no secret it could leak: the private keys never leave
the secure hardware. Secret requests (2.0, below) are the exception: the app checks the computer's
signature, and a secret the person types is in its memory for the seconds before it is encrypted.

## Key attestation (1.5)

While the pairing screen is open and after `pair-done`, the computer that paired may send
`attest-v1@sudostamp`; the phone answers with the certificate chain Android's Keystore produced
for that one key (leaf first, DER) and the challenge it was made with. Before `pair-done`, after
the pairing ends, to any other address, or for any other key, the answer is `SSH2_AGENT_FAILURE`:
nothing leaks about other keys. The chain is a few KB and the answer is capped. `tools/pair.py`
verifies it with `tools/attest.py`: the signatures with the system `openssl`, link by link up to
a pinned root (not `openssl verify`: real Pixel 2 chains carry a `CA:FALSE` certificate that signs
the leaf and path validation would reject them), the single KeyDescription in the leaf, the
challenge and the key. The challenge is `SHA-256(tag, Np, D, S)`: the Keystore needs it before the
key exists, so it cannot cover the key or the computer's nonce, but the key is checked against the
leaf separately. Roots, with the source and date: `tools/attest.py` (fetched 2026-11-12 from
developer.android.com/privacy-and-security/security-key-attestation).

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

## Secrets typed on the phone (`sudostamp input`, 2.0)

A program on a paired computer can ask for a secret (`sudostamp input restic --why "weekly
backup"`); the person types or autofills it on the phone and approves with a fingerprint. The phone
stores nothing. Design and wire format: [docs/design/secrets.md](docs/design/secrets.md).

Since a released secret is useful to whoever receives it, the phone must know which computer asks.
Pairing v3 gives each computer a host key H (P-256, `~/.config/sudostamp/host-key.pem`, 0600, made
as the user), covered by the pairing code or the QR secret. A request is signed by H over a nonce
the phone chose for this connection; the answer is HPKE-sealed (RFC 9180, DHKEM P-256, HKDF-SHA256,
AES-128-GCM, composed from platform primitives and checked against the RFC vectors and pyca) to a
key the computer made for this one request, and signed by that computer's Keystore key, which needs
the fingerprint.

| Threat | Outcome |
|---|---|
| A LAN device asks for a secret in a paired computer's name | **Refused without a prompt**: the request must be signed by that computer's host key over this connection's nonce. |
| A captured request is replayed | **Refused without a prompt**: its nonce belonged to another connection, and each nonce is spent by the first request. |
| A man in the middle swaps the computer's encryption key | **Refused**: the key is inside the signed request. |
| A LAN device answers in the phone's place with a value it chose | **Detected**: the computer requires the phone key's signature over the request and the ciphertext, and writes nothing otherwise (exit 65). |
| An eavesdropper on the LAN | Sees the name and the reason (chosen by the asker, made to be shown) and a ciphertext under a key that lives for one request. |
| Malware on the phone without root | Cannot produce an answer: the signature needs the fingerprint, enforced by the TEE. It cannot draw over the screen (as for sudo) or capture it (`FLAG_SECURE`). |
| A man in the middle at pairing substitutes the host key | **Fails**, one time in a million: the host key is inside what the 6-digit code (or the QR secret) covers. |
| A computer paired before 2.0 | Cannot ask; nothing shown; pair it again. Sudo keeps working. |
| Someone wins the race for the 6-digit pairing code and pairs their own machine | **Cannot ask for secrets**: a computer asks only after the person has approved one of its sudo requests, and that first request carries the new-computer warning. |
| Two machines hold the same host key (a synced `~/.config`, a cloned VM or image) | **One of them**: one host key is one computer, so the second pairing replaces the first. |
| Two computers with the same name | Told apart on the secret screen by the address the request came from and the pairing date. |
| Another app on the phone opens SudoStamp at a pending request | **No**: requests are named by random 63-bit ids, not a counter. |
| Another app takes the typed value out of the field | **No**: only paste and select-all work in it, shown or not (no copy, cut, share, drag, or "process text"); it is marked sensitive for accessibility (Android 14+), and the keyboard's full-screen mode is off. |
| A flood of refused requests from the LAN | Cannot push an approval or denial out of the history: refusals are dropped first. |
| Spam for a tired tap | The sudo limiter, shared: per-computer cooldown, global cap. |
| Someone holding the locked phone | The secret screen is never shown over the lock screen, and the notification says only which computer asks. |

**What it does NOT protect:**

- **The requesting computer gets the secret.** That is the feature. Anything running as that user
  can read the host key and ask; the phone names the computer, not the program. Root on that
  computer, or any process that can read the CLI's memory or its consumer's, gets every value
  released there.
- **The reason is the asker's word.** Signed by the computer's host key, so it is that computer's
  word, but any program of that user can write any reason.
- **The phone sees the value in clear** for the seconds between the field and the encryption, in
  app memory. Root malware on the phone, an accessibility service, or a third-party keyboard (it
  receives every typed character) can take it. Autofill from the phone's password manager avoids
  the keyboard; it does not avoid root.
- **SudoStamp cannot know the value is right**, or that the person meant this computer: read the
  name.
- **A stolen host key lets the thief ask**, named as that computer, until that computer is unpaired.
  Pairing again with the same key does not help (it is the same computer to the phone). To recover:
  Unpair it on the phone, delete `~/.config/sudostamp/host-key.pem` there, and run setup again. A
  stolen key does not open past answers: each was encrypted to a key that lived for one request.
- **Never sync, copy or bake the host key into an image.** A second machine with the same key is
  the same computer to the phone.
- **The phone's own copies.** The value is encoded into one buffer and wiped, and the field is wiped
  when the screen goes away, but the text field and the keyboard keep internal copies the app cannot
  reach until the memory is reused.

## Threat model

| Threat | Outcome |
|---|---|
| Malware on the phone tries to sign | **Fails.** Each key requires a fresh strong biometric for every use, enforced by the TEE. A key that the Keystore would put in software is refused at creation (release builds). |
| The key the phone hands over is not really in secure hardware (a software Keystore, an emulator, a modified app or OS) | **Detected at pairing** (new in 1.5). The release app refuses software keys itself, but that is the phone's word. Now the Keystore's attestation chain is checked on the computer, against Google's attestation roots pinned in the repository (`tools/attest.py`): the chain must verify to a pinned root, say TEE or StrongBox, carry this pairing's challenge and be for the very key being pinned. A genuine chain that says software, or is for another key or pairing, **refuses the pairing**. A chain that cannot be checked (no Google root, no `openssl`, an old app) is reported as `NOT hardware-attested` and allowed, unless `--require-attestation`. |
| A real phone's attestation chain is replayed by something that is not that phone | **Refused.** The chain carries a challenge derived from this pairing's phone nonce and both addresses, and a leaf key that must equal the key being pinned; a chain for another pairing or key fails both. |
| Someone who knows the phone's PIN enrolls their own finger | **Fails.** Enrollment invalidates every key (`setInvalidatedByBiometricEnrollment(true)`); the app marks those computers and the password path takes over until they are paired again. |
| A device on the LAN that never paired asks the phone to sign | **Refused without a prompt**: its key is not one the phone made. Payloads other than a 32-byte challenge are refused without a prompt too. |
| A LAN attacker obtains a signature (the user approved their request) | It is over their own 32 bytes, with the key of the computer they named — and the prompt showed that computer's name. pam_rssh issues a fresh random challenge per attempt, so it cannot be replayed into a sudo; only 32-byte payloads are signed, so it cannot be an SSH login or `SSHSIG` signature either. |
| A relay passes one computer's challenge to the phone during another computer's sudo | The challenge must be signed with **the key of the computer that issued it**; asking for that key puts that computer's name on the prompt. Signing with the other key produces a signature the issuing computer rejects. |
| A request queued behind a real one, to read as "sudo asked twice" | Refused **without asking** for 3 s after any approval. And the fingerprint prompt opens by itself only for the request whose notification you tapped; any other request waits for a tap on *Approve*. |
| Eavesdropper on the LAN | Sees public keys, a random challenge and its signature. None of it is reusable. There is deliberately no TLS: the signature is the security, not the channel. From 1.6 it also sees the description of an agent's run (`sudostamp ask`: the script's hash, the agent's name and its reason), which is made to be shown. An ordinary sudo's command line is never sent (it can hold a password): the probe describes only the installed runner. |
| Man in the middle between computer and phone | Can drop or delay. Cannot forge, and (above) cannot make a relayed request carry another computer's name. A connection that is accepted and never answered is cut off by the host's reachability check within seconds, and the password prompt follows (see residual risks for the limit). |
| Impostor or man in the middle while you run setup | **Pairing**: the phone makes a key for this computer and commits to it, its nonce, the address it was dialled on and the address to keep, before seeing the computer's nonce; both then show a 6-digit code that you type into the computer. One-in-a-million per attempt, one attempt per *Pair a computer* tap. Tested in CI with a key-substituting man in the middle. **The phone's side** (2.0): the computer's "codes match" crosses the network too, so a party in the middle could send it for a pairing it altered (its own host key) while your computer says nothing was pinned. The phone therefore asks you whether the computer said the codes match, and records the computer only on your *Yes*; *No*, leaving the screen or two minutes without an answer throw its key away. The computer waits until the phone lists its key before pinning anything. |
| Something answers discovery first and relays pairing unchanged | **Refused** (new in 1.4.0): the phone states the address it was dialled on, and it is not the relay's. Version 1.3 pinned the real key but the relay's address. Tested in CI. |
| An attacker races the person's computer and finishes pairing first | Any second pairing attempt while the pairing screen is open cancels the pairing — **even one that already finished** — and deletes its key; the person's own computer arriving is such an attempt. A code pairing is also recorded only after the person's *Yes* (above). A pairing that did slip through is still *new* until a request is approved, and flagged on screen until then. |
| Someone sees the computer's pairing QR code (shoulder, screen share) and is on the LAN with SudoStamp | **Can win** that one pairing if their phone answers first: whoever holds the code's secret is, to the protocol, the person. Limited by a two-minute code that is never reused, refusal when two phones answer, the window naming the phone it found, and the person's own phone not saying Paired (pairing again replaces the key). The typed code is not open to this. |
| Someone sends a pairing link (chat, web page) to get a phone to pair | **Needs the person.** The link opens a "Pair with …?" screen; nothing happens without the tap, and the computer must still be on the LAN and hold the secret. |
| Someone spams approval requests, hoping for a tired tap | Only paired computers can ask at all. After a denial or timeout that computer is refused without asking (5 s if trusted, 60 s if new); after 4 unapproved requests within 10 minutes, all requests are refused without asking until the window clears. Never keyed by IP address, so changing addresses does not help. |
| Class 3 face unlock approves at a glance | The prompt asks for explicit confirmation for passive biometrics (`setConfirmationRequired`; Android documents this as a hint the system may ignore). |
| A device on mobile data, a VPN or another subnet reaches the phone | **Refused before a byte is read**: the peer must be inside the subnet of the Wi-Fi or Ethernet address the connection arrived on, and a LAN-range address. Loopback only in debug builds. |
| Overlay app draws over the approval screen | Hidden on Android 12+ (`setHideOverlayWindows`); on Android 11 touches through an overlay are dropped. The biometric prompt itself is system UI. |
| Another app adopts the approval screen into its task ("StrandHogg") | `taskAffinity=""` on the activity. |
| Someone holding your locked phone | Sees a pending request's computer name if they tap its notification, nothing else: the approval screen is allowed over the lock screen only for the request whose notification was tapped and only while it is pending, and every other screen draws nothing while the phone is locked. Approving still needs the enrolled finger, because every key demands a fresh strong biometric for each signature. |
| A computer misuses its pairing (malware running sudo as you) | Every request the phone sees is in the on-phone history, including those it refused without asking, so a request you did not make can be noticed. Away stops listening altogether. |
| Something sends a false description of a sudo (`context-v1@sudostamp`: "update the packages" for something else): any program on a paired computer, under any account, or any device on the LAN | **It can mislead, not approve.** The description is a claim, attributed on screen to the address it came from ("Reported by 192.168.1.20, not verified: any program on that computer could report something else"), never to the paired computer's name. Nothing about whether a request is refused or approved depends on it, and the signature still needs your finger and covers only the pam_rssh challenge. It is used once, by the next request from the same address within 5 s; two different descriptions in that window show a red warning instead of any text. It is never in a notification (a locked screen, a watch or a notification listener could read that) nor stored for a refused request. The text is scrubbed (controls, format and bidi characters, invisible and blank-looking ones shown as `?`; odd spaces as plain ones; 2048 bytes in, 512 characters, a few lines on screen, left to right). The installed runner's path is required before text is read as an agent's run. |
| Unprivileged user edits the pinned key | Root-owned directory and file; the installer creates both. |
| The event socket (1.6): the user replaces `/run/user/<uid>/sudostamp/events.sock` with a symlink to a root daemon's socket (journald's native one), hoping the probe's datagram, which carries a command line the user chose, is delivered as root and forges that daemon's input | **Nothing reaches it.** The probe and its hook touch that directory only as the user: under sudo `pam_exec` runs them with the caller's real uid, so they already are the user with no privilege, and a root caller (`su`, `pam_check`, `pam_exec seteuid`) first drops to the user with `setpriv` (real, effective and saved ids, and the groups). A symlink then reaches only what the user could already write. Tested in CI against a root-owned `0600` socket, with the probe run both ways, and with a control showing that a root sender would have reached it. Without `setpriv` there are no events: never "as root instead". |
| A missing, wrong or stuck event socket (no app running, a regular file, a stream socket, a datagram socket whose queue is full) | **sudo behaves exactly as before**: same exit status, the 4 s phone check untouched, every failure ignored, and each helper killed at 250 ms (tested: the probe stays under its 500 ms cap over the bare phone check, with a full socket; about 20 ms on a desktop). Nothing in the event path can make anything authenticate. |
| A process of the user forges datagrams to the desktop app, or reads the socket | Dropped unless the sender is a real sudo (real uid the user's, effective uid 0; unreadable means dropped), and only checked events count against the rate limit, so a flood of forgeries cannot hide a real sudo. The app treats every field as untrusted text and only displays it; an event approves nothing and the phone never hears of it. What a datagram holds is sudo's own command line, which that same user can read from `/proc` anyway. |
| The pause flag (1.6): `/run/user/<uid>/sudostamp/paused`, set by anything running as the user | The only effect is that the probe skips the phone, so sudo asks for the password and the phone sees nothing: a flag can never make a sudo succeed. It is read as the user, never by root, so a symlink to a root-only file is unreadable and counts as not paused (tested: the target is `0600` root, empty, and would pause everything if root opened it). Only a regular file of at most 32 bytes counts (a FIFO would hold sudo), empty or a future unix time; on tmpfs, so a reboot or logout resumes. |
| The hook after pam_rssh (1.6) | Its control is `[success=ignore ignore=ignore default=ignore]` and it exits 0: whatever it returns, the result of the stack is the one it had. It runs only when the phone path did not authenticate and only sends `not-approved`. Tested: after a failing module it cannot grant, after a granting one it cannot take back, and the same line with a granting control would grant (so the test can fail). |
| An agent's script is changed between what was approved and what runs (`sudostamp ask`, 1.6) | **Refused before it runs.** The script reaches root only on stdin, checked against the SHA-256 in sudo's own command line (what sudo logs, the desktop shows and the phone is told); `sudostamp-run` exits 65 and runs nothing if they differ. Root never opens a path the agent names. See [docs/AGENTS-SUDO.md](docs/AGENTS-SUDO.md). |
| An agent rides on a cached sudo, or a refused approval drops it at a password prompt | **Neither.** `ask` runs `sudo -k` (every run is its own approval on the phone) with no controlling terminal, so a denied or timed-out approval ends at once with exit 77 instead of waiting on a password. |
| An agent asks for root when the phone cannot answer | **Not asked.** `ask` checks first (set up, not paused, the phone offering your key within 4 s) and exits 75 with the reason. |
| A replaced installer in the release downloads | The package registry accepts re-uploads, so files there can change after publishing. The installer and `SHA256SUMS` are signed (`ssh-keygen -Y`, key in `keys/allowed_signers`, also carried in the app); the documented command verifies before running anything. |

## Residual risks — accept these knowingly

- **Setup trusts your account while it runs.** Where pam_rssh is built from source, it is built as
  you, with your toolchain, and the result is installed as root as the module that answers for
  sudo; from a checkout, `sudo tools/install.sh` runs files you can write. Malware already running
  as you at that moment could put its own module there, which would let every sudo through without
  the phone (and `doctor` would see the file it recorded). It is the same malware that could take
  the sudo password you type into that setup, so run setup from a session you trust. (A root-owned
  toolchain under a separate build account would close this; not built yet.)

- **Do not reuse the PAM line outside `sudo`.** pam_rssh substitutes `${user}` (the raw PAM user
  name) into the key file path. In `sudo` that name is the already-logged-in caller. In `sshd`,
  `login` or a display manager it is whatever was typed at the prompt *before* authentication, so
  a name like `../../home/mallory/x` would make pam_rssh read a key file the attacker wrote.
- **The prompt cannot name the command.** pam_rssh sends an opaque challenge. A process running as
  you on a paired computer can start a sudo and you will see a request from that computer — the same
  position as a password prompt that process could have shown you. The optional desktop app (1.6)
  does show the command, taken from the sudo's own command line, as text for you to read: it is
  information, never authorisation, and any process running as you can send it a different one.
- **A stalling peer after the reachability check.** Upstream pam_rssh sets no timeout on its
  socket. Two layers now bound it. The installer puts a check in front of pam_rssh
  (`sudostamp-probe`: the phone must answer with this user's key within 4 s, or pam_rssh is
  skipped), which covers a dead phone, a different device on the phone's old address, and anything
  that accepts and never answers. And the pam_rssh the installer builds carries a small patch
  (`tools/patches/pam_rssh-timeouts.patch`, pinned by SHA-256): connect 5 s, listing keys 10 s, and
  a signature 75 s, deliberately longer than the phone's own 60 s approval window. The limit covers
  the whole exchange, so a peer sending one byte at a time gains nothing, and a timeout is never
  retried. A man in the middle that answers the probe and then stalls therefore holds sudo for at
  most 75 s, after which the password prompt comes. What is still open: a pam_rssh that SudoStamp
  did not build has no timeouts (FreeBSD installs the port as is; a distribution package of
  pam_rssh is left alone, and the patched build is installed beside it). `doctor` says which you
  have (`pam_rssh: patched (timeouts)`). macOS builds the same patched module (experimental,
  untested) but, like FreeBSD (OpenPAM, no way to skip a line), has no probe in front of it.
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
- **Key attestation proves where the key lives, nothing more.** It says the key is in the phone's TEE
  or StrongBox and was made for this pairing. It does not say the phone is yours, that its operating
  system is unmodified (the boot state in the chain is not read), or that the key still requires a
  fingerprint: the last is enforced by the TEE from the moment of creation, and is not checked here.
  A phone without Google's hardware attestation (an emulator, many custom ROMs, some older phones)
  cannot be checked and is only warned about, unless you pass `--require-attestation`. The roots
  are the ones Google publishes, embedded in `tools/attest.py` and pinned by SHA-256; certificate
  validity dates are not checked (phones sold under the 2016 root, which expired in May 2026, still
  attest under it). Revocation is checked only with `--check-revocation`, so an offline install
  cannot learn that Google has since revoked a device's attestation key. Computers paired before 1.5
  have no attestation.
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
  when one was present: no pin, no review. Removed.) FreeBSD uses the ports package. Before the
  build, `tools/patches/pam_rssh-timeouts.patch` is applied to that checkout: the installer reads it
  into a root-private file, refuses unless its SHA-256 is the one pinned in `install.sh` and it
  applies cleanly, and records the build (path, SHA-256 of the module, patch hash) in
  `/var/lib/sudostamp/pam_rssh.built`.
- `doctor` only reads. `uninstall` removes the pam_rssh module only when that record says
  SudoStamp built it and the file still has the recorded hash, never a package's.
- If the distribution's Rust is too old, it can fetch the official `rustup-init` over HTTPS and
  check it against the SHA-256 rust-lang publishes (same origin, so this guards against corruption
  rather than a compromised server), and use it in the build directory only. It asks first.
- The AUR package (`sudostamp`) depends on the AUR's `pam_rssh`, so on that path you trust that
  package's maintainer instead of the pinned build.
- **SBOMs.** Every release carries two CycloneDX 1.5 documents, `sudostamp-vX.Y.Z.apk.cdx.json` and
  `sudostamp-setup.cdx.json`, listed in the signed `SHA256SUMS`. The APK's says what the tests assert:
  no runtime dependencies, and everything the build used (every Gradle artifact by SHA-256, the Gradle
  distribution, the Android tools) as `scope: excluded`. The installer's lists pam_rssh at its pinned
  commit and every crate of that commit's `Cargo.lock`, whose SHA-256 is pinned in `scripts/sbom.py`.
- **Reproducible, and proved in CI.** The CI job `reproducible` rebuilds each tag with no key, copies the
  published signature onto the result and fails unless the APK is byte-identical; it also checks that the
  signed `SHA256SUMS` lists it and that the installer rebuilt from the tag is the one listed
  (`scripts/verify-reproducible.sh`, `docs/RELEASING.md`). It needs no secret, and `release.sh ship`
  fails the release if it does not match. It proves the published APK is this source, not that the source
  is safe.
- **Parsers of untrusted bytes are fuzzed.** The agent's frame and request readers, the DER signature
  reader, address and subnet logic and the pairing messages (JVM), and the installer's mDNS, agent-reply
  and `--phone` parsing (Python) are tested on every push with seeded random and structure-aware damaged
  input (length lies, pointer loops, truncation, one-byte reads), against independent reference parsers:
  only the documented errors, no read or allocation beyond the 64 KiB cap, no signature for anything but a
  paired key and exactly 32 bytes. It found one gap, now closed: the DER reader accepted non-canonical
  signatures. Another stays open in `tools/pair.py` (a truncated mDNS A record ends discovery; the
  address can still be typed), pinned by a known-failure test.
- `tools/test/mock_agent.py` signs with software keys and exists only for automated tests: it binds
  loopback only and its keys are generated per run. It must never stand in for the phone.

## CI runner

This public project's pipelines run on the owner's self-hosted runner, which also serves other
projects. No signing key is given to CI, and no secret reaches the test jobs; the one exception is
the `site` job, which runs only on master, in the protected environment `site`, and holds a
Cloudflare Pages token that can deploy the `sudostamp` Pages project and nothing else. Merge requests from forks run in the fork's
own project by default, so outside contributors cannot reach the runner unless a maintainer starts a
fork's pipeline here; keep it that way, and on the runner keep `privileged = false` and no Docker
socket in job containers. Job logs are public; they contain no addresses or credentials.

## Supported versions

The latest release only. Fixes ship as a new release; there are no backports.
