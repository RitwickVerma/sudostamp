# Design: secrets the computer must not store (`sudostamp input`, later `unseal`)

Status: **proposal, not approved, no code.** Target: 2.0 (the wire format and pairing change).

## 1. Problem

SudoStamp proves that a person approved something: the phone signs a challenge with a key that the
TEE releases only after a fresh fingerprint. Some programs need more than approval. They need a
**secret that the computer should not keep**:

- a backup passphrase (restic `RESTIC_PASSWORD_COMMAND`, borg `BORG_PASSCOMMAND`),
- the master password of a small password-manager account used by an automation or an AI agent
  (`bw unlock --passwordfile`),
- a disk unlock (`cryptsetup open --key-file=-`),
- a one-off password for a login.

Today that secret ends up in a plaintext file on disk, gets pasted into a terminal or a chat with an
agent (where it lands in scrollback, logs and model context), or needs a separate vault product and
an always-unlocked client on the machine. All three put the secret on the computer at rest or in
places nobody audits.

What we want: the program asks; the person's phone shows *which computer* asks and *what for*;
after a fingerprint the secret goes to **that computer's process only**, through a pipe, and
exists on the computer only in that process's memory.

## 2. The finding that shapes everything: the phone does not know who is asking

The sudo path is safe against requests from anyone because its output is useless to anyone but
the issuer: a signature over pam_rssh's random challenge only lets the computer that made the
challenge in. So today **any device on the LAN may name any paired computer's key**, and the
phone shows that computer's name (SECURITY.md: "A relay passes one computer's challenge...").

A released secret is useful to whoever receives it. If the sudo path's rules were reused, a
device on the LAN could send "*build-box* wants: restic passphrase" with its own encryption key,
the person would see a familiar name and touch the sensor, and the secret would go to the
attacker. Encrypting the answer does not help when the phone cannot tell whose key it encrypts to.

So, whichever capability ships, the phone must **authenticate the requesting computer**. The
computer has no secret today: pairing only gives the computer the phone's public key. Hence:

- every computer that wants secrets gets a **host key** (P-256), generated on the computer at
  pairing, its public half committed into the pairing transcript (so the 6-digit code or the QR
  secret covers it, exactly as they cover the phone's key);
- every secret request is signed with it, over a phone-chosen nonce;
- the answer is encrypted (HPKE) to a fresh key the computer made for that one request and signed
  with the phone's per-computer key, behind the fingerprint.

This is a pairing change (version 3) and a wire-format change. It is the bulk of the work, and both
candidate capabilities need all of it.

## 3. Non-goals

- **Not a password manager.** No list, no search, no sync, no sharing, no generation. Phase 2
  (`unseal`) keeps a few named secrets, and the phone is never their only copy.
- **Not a backup.** A sealed secret dies with a fingerprint enrollment, an uninstall or a lost
  phone, on purpose (section 8).
- **No protection once released.** The requesting process gets the plaintext; anything that can
  read that process (same user, root) gets it too. SudoStamp decides *whether* a secret leaves the
  phone and *to which computer*, never what happens next.
- **Not for unattended use.** Every release needs a finger, every time. No caching, no "remember
  for 15 minutes". A job that must run while nobody is there is not a SudoStamp use case.
- **No remote use.** Same LAN rules as sudo: Wi-Fi or Ethernet subnet only, no relay service.
- **No files, no keys.** Text secrets up to 1 KiB. A LUKS keyfile or an SSH private key is out of
  scope (trigger to revisit: a concrete consumer that cannot take a passphrase).
- **No multi-host secrets, no multi-phone.** One sealed secret, one computer.

## 4. Options considered

| Option | Verdict |
|---|---|
| **Don't build it: use the existing password manager's agent** (e.g. Bitwarden Agent Access, `bw serve`, `rbw`, `pass` + gpg-agent) | Rejected as the answer, kept as the honest alternative in the README. They put an unlocked vault client on the computer, hand plaintext credentials to the caller, and their approval is a desktop prompt or none: the step a compromised computer controls. Some are labelled previews. Where a user already runs one with hardware-backed unlock, they should keep it. |
| **Don't build it: systemd-creds / TPM2 sealing** | Rejected for this problem: it binds a secret to the *machine*, which is exactly what must not be able to release it alone. Good for "this disk on this board", wrong for "only when I touch my phone". |
| **Don't build it: a YubiKey / FIDO2 `hmac-secret`** | The strongest alternative and named in the README. It needs a token at the computer (no remote LAN prompt, no context line on a screen) and turns the key into a KEK, not a typed secret. Users with a token should prefer it. |
| **Reuse the sudo path: encrypt the secret to a key the request carries, no host authentication** | Rejected: section 2. A LAN device can request in any computer's name. |
| **Authenticate the host by its IP address** | Rejected: addresses change (DHCP, IPv6 privacy addresses) and are not identities on a hostile LAN (ARP/ND spoofing). The project already refuses to make IPs a boundary (the limiter is "never keyed by IP"). |
| **TLS between computer and phone** | Rejected: a certificate authority or pinned certificates, a TLS stack in the app (no third-party dependencies) and more code than the two signatures and one HPKE seal below. The signatures already give mutual authentication; HPKE gives confidentiality of the one value that needs it. |
| **Host key added after pairing in its own message** | Rejected: with the typed code nothing authenticates a message after `pair-done`, so a man in the middle could substitute the host key. It must be inside the transcript the code covers. |
| **Host Ed25519 / X25519** | Rejected: Ed25519 verify and XDH arrive in the Android platform at API 33 / later; `minSdk` is 30 and is the floor of the hard gate. P-256 ECDSA and ECDH are in every supported release. |
| **StrongBox/Keystore ECDH (`PURPOSE_AGREE_KEY`) for the answer** | Not needed: the phone is the HPKE *sender*, whose key is ephemeral by definition and gains nothing from hardware. Keystore ECDH is API 31+ and StrongBox support varies by device. The hardware-bound, fingerprint-gated step is the existing signature with K. (Phase 2's at-rest key is Keystore AES-GCM, section 12.) |
| **Phone keeps secrets (`seal`/`unseal`) first** | Deferred to phase 2: section 5. |
| **Phone stores nothing; person enters the secret per request (`input`) first** | **Chosen.** |

## 5. What ships first: `input`, then `unseal` only on a trigger

**`input`**: the computer asks for a secret by name and reason; the phone shows a masked field;
the person types it or fills it with their phone's password manager (Android Autofill), touches
the sensor, and the value goes to the computer encrypted. The phone keeps nothing.

**`unseal`**: the phone keeps a named secret behind a Keystore key that needs a fingerprint per
use, and releases it to the one computer it was sealed for.

Argument for `input` first:

1. **It is a strict prefix of `unseal`.** Host key, pairing v3, the signed request, the HPKE
   answer, the phone's signature, the CLI, the exit codes, the screens, the tests: `unseal` needs
   all of it and adds only storage. Nothing built for `input` is thrown away. (Sealing a secret
   is itself an `input` screen.)
2. **The phone holds no secret at rest.** SECURITY.md today can say "the app holds no secret it
   could leak". `input` keeps that sentence almost true (plaintext lives in app memory for the
   seconds of one request). `unseal` ends it, and adds at-rest storage, loss, invalidation,
   backup exclusion and a list UI: real running cost and a new section of threat model.
3. **Its design is closed.** `input` needs one cryptographic operation behind the fingerprint
   (the phone's signature) and therefore one BiometricPrompt. `unseal` needs two keys behind one
   prompt (the AES key that decrypts, and the signing key that authenticates the answer); Android
   binds one CryptoObject per prompt, and a timeout-window key would break the project's "no
   validity window" rule. Section 12 lists the options; none is free.
4. **The person's existing password manager is a better vault than ours.** With Autofill the
   secret stays in Bitwarden/KeePassDX/etc. on the phone, behind their own unlock, synced and
   backed up by them. SudoStamp is only the authenticated, fingerprint-gated pipe.

Cost of `input` first: each release is open-notification, fill, touch (about three taps) instead
of one touch. For the motivating cases (an agent unlocking its password-manager session a few
times a day, a weekly backup) that is acceptable; for anything more frequent it is the friction
that would justify `unseal`.

**Trigger for `unseal`:** a real consumer releasing the same secret more than about daily, with
users reporting the fill step as the obstacle, **and** a chosen answer to section 12's
one-prompt question tested on a real device.

## 6. Chosen design

### 6.1 Primitives (all platform or long-established, none new)

| Use | Primitive | Phone (API 30+) | Computer |
|---|---|---|---|
| Host identity | ECDSA P-256, SHA-256 | `Signature("SHA256withECDSA")` verify | key generated with the system `openssl` at pairing; signs with pyca `cryptography` |
| Phone identity, fingerprint-gated | the existing per-computer Keystore key K (ECDSA P-256, TEE/StrongBox, auth per use) | `Keys.newSigner` in a `CryptoObject` | pyca verify against the pinned key |
| Answer confidentiality | **HPKE, RFC 9180, base mode**, suite DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM (0x0010/0x0001/0x0001) | composed from `KeyPairGenerator("EC")`, `KeyAgreement("ECDH")`, `Mac("HmacSHA256")` (HKDF per RFC 5869), `Cipher("AES/GCM/NoPadding")`; checked against RFC 9180 Appendix A.3 vectors | pyca primitives (ECDH, HKDF, AESGCM; in every packaged version); cross-checked in tests against pyca's own `hpke.Suite` (≥ 47) and the RFC vectors |
| Freshness | 32-byte phone nonce per connection | `SecureRandom` | — |
| Transcript hashing | SHA-256 over tagged SSH strings | `Pairing.framed` style | same as `pair.py` |

The Android HPKE API is newer than `minSdk`, so the phone composes the suite from platform
primitives. That is an implementation of a published standard with published vectors, not a new
construction; the composition is about 80 lines and gets the same treatment as `SshSig`: tests
against code that is not this project's (pyca's HPKE).

**Key reuse, stated:** K now signs two kinds of message. The sudo path signs exactly 32 bytes
(enforced by `refusal()`). The secret path signs `"sudostamp-secret-answer-v1\0" || ...`, always
longer than 32 bytes and computed by the phone over a transcript that includes the phone's own
fresh nonce, so no secret-path message is a valid pam_rssh challenge and no pam_rssh challenge is
a valid secret-path message. A test asserts both directions.

**New host dependency:** pyca `cryptography`, for `sudostamp input` only (not for sudo, not for
pairing). Justification: stdlib Python has no elliptic-curve or AEAD code, and `openssl enc` does
not do AES-GCM. pyca is packaged by every supported distribution and already used by the test
tools. Only long-standing APIs are used at runtime. `doctor` reports whether it is present.

### 6.2 Pairing version 3

Additive to v2 and `qr-v1`; vectors in both suites, as today.

- The computer generates a host key H (P-256) per paired user before pairing:
  `$XDG_CONFIG_HOME/sudostamp/host-key.pem`, mode 0600, directory 0700, owned by the user.
  Generated as the user, never by root (AGENTS.md pitfall 19).
- Code pairing: `pair-reveal-v3(Nh, H)`; the code becomes `H(code-tag-v3 || K || Np || Nh || D || S || H)`.
  H is sent after the phone's commitment, so a substituted H changes the code exactly like a
  substituted Nh does.
- QR pairing: `pair-qr-v2(Nh, H, macC)` with `macC = HMAC(S_, c-tag-v2 || Nh || Nc || R || H)`; the
  phone's `macP` and `macD` include H.
- The phone stores H with the computer (`Hosts`), so a computer now has K (phone's) and H
  (computer's).
- v2 pairings keep working for sudo unchanged. A computer without H is refused secret requests
  **before anything is shown**. `install.sh setup` says once: "pair again to use `sudostamp input`".
- Attestation is unchanged.

### 6.3 Wire format (ssh-agent extensions on port 7777, frame type 27)

pam_rssh never sends these; the sudo path and the probe are untouched. All strings are SSH strings.

```
computer -> phone   secret-hello-v1@sudostamp
                      string  K           phone key blob the computer pinned (selects the computer)
phone    -> computer SUCCESS  string Np    32 random bytes, valid for this connection only
                   | FAILURE               unknown K, no H for it, Away, rate-limited: nothing shown

computer -> phone   secret-request-v1@sudostamp     (same connection, next frame)
                      string  kind        "input"  (phase 2: "unseal")
                      string  name        what is asked for: 1..64 of [A-Za-z0-9._@+-]
                      string  why         the context line: strict UTF-8, ≤ 2048 bytes, scrubbed as context-v1
                      string  pkR         HPKE recipient key, 65-byte uncompressed P-256, fresh per request
                      string  sigH        ECDSA(H, T), T = tag-req || K || Np || kind || name || why || pkR

phone: verify sigH with the H stored for K; Np unspent
       (spend it now). Any failure: FAILURE, nothing shown, nothing stored, counted by the limiter.
       Then the screen; the connection waits up to APPROVAL_TIMEOUT_MS (60 s).

phone    -> computer SUCCESS
                      string  enc         HPKE encapsulated key
                      string  ct          HPKE ciphertext of the secret (≤ 1024 bytes of UTF-8)
                      string  sigK        ECDSA(K, tag-ans || T || enc || ct), behind the fingerprint
                   | FAILURE               refused, timed out, sensor locked out
```

- HPKE `info = "sudostamp-secret-v1\0" || SHA-256(T)`, `aad` empty: the request binds the answer.
- One request per connection; `Np` is spent by the first request whether it verifies or not.
  A second hello on the same connection is refused.
- The computer checks `sigK` with the pinned K **before** decrypting, then opens with its
  ephemeral key, which never touches disk and is dropped after one use.
- The frame cap (64 KiB) and the 8-frame / 30 s connection budget apply unchanged.
- No `version` negotiation: an old phone answers FAILURE to an unknown extension, which the CLI
  maps to "phone too old" by its `secret-hello` failing on a phone that does answer
  `REQUEST_IDENTITIES` with K. Protocol version: these are new extension names; the existing
  ones do not change, so 1.x hosts and phones interoperate for sudo.

No dialled-address field, unlike pairing. Pairing needs one because nothing else stops a relay
from standing in for the phone there. Here sigH, pkR inside T and sigK already make a relay a
blind pipe, and real setups put a TCP relay between a computer and the phone on purpose (a host
on another subnet reaching the phone through a LAN box). A dialled-address check would refuse
exactly those and add no protection.

Why each field is there:

| Field | Without it |
|---|---|
| sigH over Np | any LAN device, or a replay of a captured request, could put a prompt up in this computer's name and receive the answer |
| pkR inside the signed T | a man in the middle swaps in its own key and reads the answer |
| sigK | a LAN device answering in the phone's place could feed the computer a value it chose (matters for "set a new password" consumers); and it is what makes the fingerprint a TEE-enforced condition for the release rather than an app-level prompt |
| name, why inside T | a relay could not change what the screen says without breaking sigH |

### 6.4 Phone behaviour

- Same listener, same `allowedPeer`, same Away (Away refuses everything, unshown).
- Same `Limiter` with the same per-computer cooldowns and the global cap; a secret request counts
  as a request. A refused request leaves **no text** on the phone: the history records time,
  computer, "secret: refused" and **not** the name or the reason. Approved: time, computer,
  name, reason (the value never).
- Exactly one pending request at a time across sudo and secrets (`Approval` already enforces one).
- The value is held in a `CharArray`/`ByteArray`, never a `String`, zeroed after sealing;
  the field is cleared on pause, on timeout and on deny.
- Screen: `FLAG_SECURE`; `TYPE_TEXT_VARIATION_PASSWORD`; `IME_FLAG_NO_PERSONALIZED_LEARNING`;
  `importantForAutofill=yes` with `autofillHints=password`; no copy out of the field; **not shown
  over the lock screen** (unlike the sudo approval: typing a secret on a locked phone is not a
  thing we want to support).
- Notification: "*build-box* asks for a secret". Never the name or the reason (locked screen,
  watch, notification listeners), matching the context-v1 rule.

### 6.5 Computer side

```
sudostamp input <name> --why <text> [--to-tty]
```

- Prints the secret to **stdout, raw, no newline**. Refuses (exit 64) when stdout is a terminal,
  unless `--to-tty` (scrollback is disk, in the end).
- Never takes a secret on argv, never reads it from the environment, never writes it to a file,
  log, history or the desktop app's event socket (the event says only "secret asked/answered").
- Sets `RLIMIT_CORE` to 0 and `PR_SET_DUMPABLE` 0 before asking.
- Reads H from the user's 0600 file (refuses group/world-readable, like ssh), K and the phone's
  address from the existing pairing record.
- One code path, one file (`tools/secret.py`), installed as `sudostamp-input` and dispatched by the
  existing `sudostamp` entry point.
- **No library yet.** The two named callers (a vault-unlock gate and a weekly patch job) can both
  exec the CLI, and the weekly patch job needs `ask`, not `input`. A library is a second stable
  interface to keep secure. Trigger: a caller that cannot spawn a process, or that needs the value
  without it crossing a pipe.

Exit codes (sysexits, consistent with `ask`):

| Code | Meaning |
|---|---|
| 0 | secret written to stdout |
| 64 | usage, or stdout is a terminal |
| 65 | the phone's answer failed verification (sigK, decryption): nothing written |
| 69 | this computer is not paired for secrets (no H, v2 pairing), or pyca missing |
| 75 | phone unreachable, Away, paused, or too old (`secret-hello` refused) |
| 77 | refused, timed out or the sensor locked out |

Consumers:

```sh
RESTIC_PASSWORD_COMMAND='sudostamp input restic --why "weekly backup"' restic backup ~
sudostamp input vault-agent --why "unlock for today's tasks" | bw unlock --passwordfile /dev/stdin --raw
sudostamp input disk --why "open the backup disk" | sudo cryptsetup open --key-file=- /dev/sdX backup
```

## 7. Threat-model delta (lands in SECURITY.md)

| Threat | Outcome |
|---|---|
| A LAN device asks for a secret in a paired computer's name | **Refused without a prompt**: the request must be signed by that computer's host key over this connection's phone nonce. |
| A captured request is replayed | **Refused without a prompt**: its nonce was this connection's and is spent. |
| A man in the middle swaps the computer's HPKE key | **Refused**: the key is inside the signed request. |
| A LAN device answers in the phone's place with a value it chose | **Detected**: the computer requires the phone's per-computer key's signature over the request and the ciphertext, and writes nothing otherwise (exit 65). |
| An eavesdropper on the LAN | Sees the name and the reason (as with context-v1: chosen by the asker and made to be shown) and ciphertext under a key that lives for one request. |
| Malware on the phone without root | Cannot produce an answer: the signature needs the fingerprint, enforced by the TEE. It can draw over other apps (blocked on this screen as for sudo) and cannot read the `FLAG_SECURE` window. |
| A man in the middle at pairing substitutes the host key | **Fails**, one time in a million: the host key is inside what the 6-digit code (or the QR secret) covers. |
| A computer paired before 2.0 | Cannot ask; nothing shown; "pair again". |
| Spam for a tired tap | The sudo limiter, shared: per-computer cooldown, global cap. |

**What it does NOT protect (also lands in SECURITY.md, in these words):**

- **The requesting computer gets the secret.** That is the feature. Anything running as that user
  can read the host key and ask; the phone names the computer, not the program. Same position as
  a password prompt that program could have shown you. Root on that computer, or any process that
  can read the CLI's memory or its consumer's, gets every value released there.
- **The reason is the asker's word.** Signed by the computer's host key, so it is that computer's
  word, but any program of that user can write any reason.
- **The phone sees the value in clear** for the seconds between the field and the encryption, in
  app memory. Root malware on the phone, an accessibility service, or a third-party keyboard (it
  receives every typed character) can take it. Autofill from the phone's password manager avoids
  the keyboard; it does not avoid root.
- **Typing it on the phone is the person's choice of source.** SudoStamp cannot know the value is
  right or that the person meant this computer: read the name.
- **No forward secrecy for a stolen host key against a past recording**: none needed, the answer
  is encrypted to a per-request key the host key only signs. A stolen host key lets the thief
  *ask* (and be named as that computer) until the person pairs again.

## 8. UX (screens and copy, Material 3 as the rest of the app)

**Notification** (approval channel, HIGH): title "*build-box* asks for a secret", body "Tap to
review". Actions: *Deny*. No name, no reason.

**Secret screen** (not over the lock screen):

```
  build-box asks for a secret                         (headline; computer name from pairing)

  restic                                              (title: the name)
  "weekly backup"                                     (body: the reason, as context-v1, ≤ 4 lines)
  Named and described by build-box. Any program on that computer could
  ask with other words.                               (supporting text, as context-v1's)

  [ ••••••••••••••          (eye) ]                   (outlined password field; autofill)

  [ Deny ]                [ Send with fingerprint ]   (send disabled while empty)

  Sent once, to build-box only. SudoStamp keeps no copy.   (footnote)
```

- BiometricPrompt title "Send the secret to build-box", subtitle "restic". Negative button
  "Cancel" = deny.
- After sending: the drawn check, "Sent", screen closes as for sudo. Denied or timed out: the
  cross, and the field is already empty.
- A new (*unapproved*) computer gets the same yellow pill as on sudo prompts.
- TalkBack: the field announces "Secret for restic, password field"; the reason is read before the
  field. Touch targets ≥ 48 dp. Reduced motion: no countdown animation, the remaining seconds as text.
- History row: "Secret · restic · build-box · sent" or "Secret · build-box · refused".

**Computer side:** on stderr only, one line: `waiting for your phone (60 s)...`, then
`sent` / `refused` / the exit-code reason.

## 9. Test plan

Each guard gets a negative test that is run once with the guard removed and seen to go red
(recorded in docs/STATUS.md with the commit that mutated it).

**Shared vectors (Kotlin `SecretProtocolTest` ⇄ Python `test_secret.py`):** transcript T, the
signed messages, HPKE `info`, pairing v3 code and QR MACs with H. As `PairingTest` does today.

**HPKE:** RFC 9180 A.3 vectors (DHKEM(P-256), HKDF-SHA256, AES-128-GCM) through the Kotlin
composition; a round trip Kotlin-seal → pyca `hpke.Suite.decrypt` and pyca encrypt → Kotlin open
(an implementation that is not ours, as `verify_ssh_sig.py` does for signatures).

**Fuzzing:** `secret-hello` and `secret-request` parsers (JVM, structure-aware, 20 000 cases per
property, against a reference parser written separately); the CLI's answer parser (Python). Only
the documented errors, no allocation past the frame cap.

**Negative tests (JVM where pure, emulator where Keystore):**

| Case | Expected | Guard removed to prove it |
|---|---|---|
| unknown K | FAILURE, nothing shown | the K lookup |
| v2 computer (no H) | FAILURE, nothing shown | the H-present check |
| sigH by another computer's H | FAILURE | the verify |
| replay of a full request on a new connection | FAILURE (other Np) | nonce check |
| second request on the same connection | FAILURE | nonce spend |
| pkR changed after signing | FAILURE | pkR inside T |
| answer with a bad sigK | CLI exit 65, empty stdout | the host's verify |
| 32-byte message to the secret path / tagged message to the sudo path | refused both ways | `refusal()` and the tag check |
| timeout, deny, locked phone, Away, limiter | FAILURE; history has no name/reason | each in turn |
| stdout is a TTY | exit 64, nothing asked | the isatty check |
| host key file mode 0644 | exit 69 | the mode check |

**End to end:** emulator with an enrolled fingerprint (`adb emu finger touch 1`), `tools/secret.py`
over `adb forward`, the value typed through `adb shell input text`, output compared by hash; plus
pairing v3 with the key-substituting man in the middle already in CI, now substituting H.

**Device:** one release-signed run on a real phone with Autofill from a password manager, and a
`screencap` showing the window black (FLAG_SECURE).

## 10. Migration

- 2.0 app + 2.0 host tooling: sudo works with every existing pairing, unchanged.
- To use secrets: `install.sh setup` again (pairing v3); the old key for that computer is replaced
  as any re-pairing does.
- Old host tooling against a 2.0 phone: unaffected (it never sends the new extensions).
- New host tooling against an old phone: `sudostamp input` exits 75 "phone too old".
- Major version: pairing v3 is a breaking change to what a *new* pairing sends, and v2 pairing
  from 2.0 tooling is no longer offered. Semver says 2.0.
- CHANGELOG (user-facing): "Programs on a paired computer can ask your phone for a secret, which
  you type or fill and approve with your fingerprint. Pair again to use it."

## 11. Effort (one engineer, AI-assisted, with review)

| Piece | Estimate |
|---|---|
| Pairing v3 both sides + vectors + MITM test for H | 2 days |
| HPKE composition (Kotlin) + RFC vectors + pyca cross-check | 1.5 days |
| Protocol, parsers, fuzzing, negative tests (JVM + Python) | 2.5 days |
| Secret screen, notification, history, accessibility, screenshots | 2 days |
| CLI, exit codes, installer/doctor/AUR/bundle wiring | 1.5 days |
| SECURITY.md, DESIGN.md, README, emulator e2e, device run | 1.5 days |
| **Total `input` (2.0)** | **≈ 11 working days** |
| `unseal` later (storage, list UI, section 12, invalidation UX) | +5–7 days |

## 12. Open for phase 2 (`unseal`), not decided now

- **One prompt, two keys.** Decrypting the sealed value needs an auth-per-use AES-GCM key; signing
  the answer needs K. Options: (a) one prompt for the decrypt and no phone signature on unseal
  (weaker: a spoofed phone could feed a chosen value); (b) AES key with a 5 s window (breaks "no
  validity window"); (c) seal the value under a key derived from a K signature over a fixed
  per-secret message (deterministic ECDSA is not guaranteed by Keystore: rejected unless proven);
  (d) two prompts (bad UX). Decide with a device prototype, not on paper.
- Storage in `noBackupFilesDir`, one Keystore AES-256-GCM key per secret, StrongBox preferred,
  `setInvalidatedByBiometricEnrollment(true)`, AAD = secret id || computer id.
- Sealing = the `input` screen with "Keep on this phone for build-box"; a list to delete.

## 13. Decision needed

**Ship `input` first (recommended), or go straight to `unseal`?** Everything else above follows
from the code that exists; that choice sets the 2.0 scope, whether the phone keeps any secret at
rest, and whether section 12 must be solved before release.
