# Design: grant one password-manager login to an agent (`sudostamp grant`), proposal

Status: approved for build, revision 4. Revision 2 took the owner's answers (section 10). Revision 3
moved the vault into its own process and corrected the server facts against Vaultwarden's source.
Revision 4 sets the build plan (section 9). The reader of granted items is a login service signed
in as the agent account (outside this repo). A secret that is not a website login goes through the
shipped `sudostamp input`, so this design adds no read path of its own.

## 1. Problem

An agent's login service (a separate computer that logs in to websites for an AI agent) reads
logins from a Bitwarden-compatible server. It uses its own account, and that account can only view
one organization collection, called "Agents" here. To give it a new site, the owner has to move or
share one item into that collection. Today that means opening the Bitwarden app and making about
five taps.

The goal is one prompt on the phone, behind a fingerprint, that grants exactly one item. The agent
host must not choose which item that is, must not describe it, and must never hold a credential
that could grant anything else.

## 2. Shape

```
login service --(paired v3, signed: host only)--> relay (blind) --> phone
phone (main process, the listener): toggle, Away, limiter, denylist(host) -> one Binder call
       ask(computer, host, T) to the :vault process; nothing else crosses (section 6.1)
phone (:vault): notification -> screen "<computer> asks for a login for <host>" -> owner taps Look up
       fingerprint 1 (CryptoObject = vault-session key) -> unwrap refresh token + user key
         (or, with no stored session or after 30 days: master password + 2FA code, section 6)
       phone refreshes its access token, syncs, decrypts, finds Login items whose URI matches <host>,
       shows real name/URI/username
       owner picks one -> denylist(item URIs) -> fingerprint 2 (CryptoObject = K signer)
       phone: org item  -> PUT /api/ciphers/<id>/collections  (adds Agents, keeps the rest)
              personal  -> PUT /api/ciphers/<id>/share        (re-encrypted with the org key, moved)
       phone re-syncs and checks the item decrypts under the org key and is in Agents
       :vault wipes every key, token and plaintext; returns  (id, sigK(...))  or FAILURE to main
```

The phone never uses anything the computer sends except `host`. The name, URI and username on the
screen come from the server's ciphertext, decrypted on the phone.

## 3. Pairing v3 dependency

A grant uses the computer authentication that `input` introduced: the host key H from pairing v3,
`secret-hello`/Np, and sigH over a transcript. That is already shipped (design/secrets.md 6.2), so
nothing new is needed in pairing. Two additions:
- **Per-computer capability, set on the phone.** "May ask for password-manager grants" is a toggle
  on the computer's page, off by default. A v2 pairing, or a computer without the toggle, gets
  FAILURE before anything is shown. The computer cannot set this flag. The login service pairs as
  its own computer, with its own K and H, so the screen names it.
- **No new trust in the relay.** The relay stays a blind pipe, because sigH covers `host` and Np,
  and sigK covers the answer.

## 4. Wire format (port 7777, after `secret-hello-v1`, same rules as 6.3 of secrets.md)

```
computer -> phone  grant-request-v1@sudostamp
                     string host   1..253 bytes, lowercase LDH labels, ASCII only (IDN as A-labels)
                     string sigH   ECDSA(H, T), T = tag-grant || K || Np || host
phone   -> computer SUCCESS string id     the cipher id now in Agents
                            string sigK   ECDSA(K, tag-grant-ans || T || id), behind the fingerprint
                  | FAILURE               one answer for every refusal (below)
```

Every refusal gets the same FAILURE: unknown or v2 computer, toggle off, rate-limited, denylisted,
no matching item, owner denied, timeout, wrong password, server error. The computer can't tell
whether the owner has an account at `host`. The connection waits at most `GRANT_TIMEOUT_MS`
(180 s: two fingerprints and a choice, or on a re-login day a master password and a 2FA code).
It is then refused.

## 5. Phone rules

- **Matching** has no public-suffix list. An item URI host `u` matches the request host `h` when
  `h == u`, or `h` ends with `"." + u`, after one leading `www.` is stripped from `u`. So a request
  for `co.uk` matches nothing saved under `amazon.co.uk`.
  - Only Login items match; cards, identities and notes never do.
  - Items with attachments or passkeys are refused (fail closed: re-encrypting them is out of scope).
  - Items with a TOTP seed are refused unless the owner ticks "allow" on that grant. The check is
    whether the field is present, so the seed is never decrypted to decide.
  - An item with any JSON field the client doesn't model is refused, and nothing is changed.
- **Denylist** is checked twice: against `host` before the screen, and against every URI of the
  chosen item before the fingerprint.
  - Built-in categories cover email and identity providers, banks, brokerages and payments,
    password managers, and government. The `.gov`/`.mil`/`gov.*` suffixes and labels such as
    `bank`, `vault` and `immigration` are included.
  - The vault server's own host is added at setup. The owner can add hosts on the phone, but the
    built-in list can't be removed.
  - The list ships as a data file with test vectors. The login service imports the same file, and a
    test on its side asserts the two are equal.
- **Fatigue**, the same as fill: a cooldown per (computer, host) of 10 minutes after a denial or
  timeout, and a cap of 6 grant asks per hour across all computers.
  - It is enforced by the existing `Limiter`, with grants counted alongside other requests. One
    request is pending at a time, across sudo, secrets and grants.
  - Three denials or timeouts from one computer within 24 hours turn that computer's grant toggle
    off. Only the owner turns it back on. A computer that keeps asking loses the right to ask,
    instead of training the owner to tap through fingerprint 1.
  - Away and pause refuse grants, as they refuse every other request.
  - The history row stores the time, the computer, the host and the outcome. It never stores the
    item name.
- **Least plaintext.** Matching decrypts only the name, username and URIs of Login items. Passwords,
  TOTP seeds, notes and custom fields are never decrypted for display. If the chosen item has an
  item key, a move re-wraps that key under the org key, and its fields are never decrypted. Only an
  item without an item key is decrypted in full, to be encrypted again under the org key.
- **Screen**: `FLAG_SECURE`, never over the lock screen. The password field has Autofill hints
  (the owner's own Bitwarden app can fill it), no personalised IME learning, and no copy.
  - The notification says only "<computer> asks for a login".
  - The candidate list shows each item's name, every URI, the username and whether it is personal
    or org-owned.

## 6. Session and key storage

The owner chose a stored session over typing the master password at every grant. A refresh token
alone can't decrypt anything, so skipping the password means the phone also keeps the **user key**
(the 64-byte key that unwraps the vault). This puts SudoStamp at the level of the Bitwarden app's
own biometric unlock, in an app that also runs a LAN listener. The rest of this section is about
keeping that key behind a fresh fingerprint and nowhere else.

**At rest** (app-private storage, excluded from backup and device transfer):
- Configuration: server URL, account email, org id, Agents collection id, random device id, and
  the time of the last full login.
- One blob, `vault-session`: the refresh token and the user key, encrypted as below. Nothing else.
  The master password and master key are never stored; they are zeroed as soon as the user key is
  unwrapped at login. The private key and the org key come back encrypted in every sync and are
  decrypted only inside a grant.

**The wrapping key** is an Android Keystore key, `vault-session-v1`:
- RSA-2048, purpose decrypt only, OAEP with SHA-256. StrongBox when the device has it, TEE
  otherwise; the setup screen says which.
  - Keystore RSA keys fix the MGF1 digest at SHA-1. The cipher is initialised with an explicit
    `OAEPParameterSpec("SHA-256", "MGF1", SHA1, …)`, never the provider default, and a test decrypts
    with the default to show it fails.
  - Why RSA and not ECDH: Keystore key agreement (`PURPOSE_AGREE_KEY`) starts at API 31, and the
    app supports API 30. StrongBox implements RSA-2048.
- `setUserAuthenticationRequired(true)` with `setUserAuthenticationParameters(0,
  AUTH_BIOMETRIC_STRONG)`: a timeout of 0 means every single decrypt needs its own BiometricPrompt
  with the operation as its CryptoObject. No device-PIN fallback, so a shoulder-surfed PIN unlocks
  nothing here.
- `setInvalidatedByBiometricEnrollment(true)` and `setUnlockedDeviceRequired(true)`. Adding a
  fingerprint, or removing the screen lock, destroys the key, and the next grant needs a full login.

**Blob format** (the standard KEM/DEM split, platform primitives only): a fresh AES-256-GCM key `k`,
wrapped with RSA-OAEP under the Keystore public key, then `AES-GCM(k, nonce, payload, aad)`, where
`aad = "sudostamp-vault-session-v1" || server URL || account id`. Why asymmetric: encrypting needs
only the public key and no fingerprint. So when the server hands out a new refresh token, or at a
re-login, the phone rewrites the blob without a third prompt. Vaultwarden issues a new refresh token
on every refresh (section 6.3), so this happens on every grant. Decrypting always needs the
fingerprint. `k` is zeroed right after use.

### 6.1 Process boundary

The vault client, the session store and the grant screen run in their own process, `:vault`
(`android:process`, nothing exported). The LAN listener, the relay client, HPKE and every frame
parser stay in the main process, which never holds a vault key, a token or an item name. Today one
process does both, and a stored full-vault key next to a network parser is the thing to avoid.

- **One call crosses**, over a bound service private to the app:
  `ask(computer id, host, T) -> FAILURE | (cipher id, sigK)`. The host is already validated in main,
  and `:vault` validates it again with the same parser. Nothing secret comes back: no key, no
  token, no item name, no username.
- **`:vault` signs the answer itself**, with K behind fingerprint 2. Keystore keys belong to the
  app, not the process, so `:vault` can use K, and main only forwards the bytes.
- **Its own screen.** The grant activity lives in `:vault`. It doesn't reuse `MainActivity`, which
  has `showWhenLocked` for sudo prompts. The grant screen never shows over the lock screen.
- **What it buys:** a memory-disclosure or confused-deputy bug in the listener, HPKE or the relay
  code can't read the vault key, because that key is never in that process. Android's SELinux
  policy denies ptrace and `/proc/<pid>/mem` between an app's own processes for untrusted apps
  (phase 5 checks this on a real device).
- **What it doesn't buy:** both processes share one UID and one data directory. Code execution in
  main can rewrite app files, and it can draw its own screens. Two things still hold:
  - The blob's AAD binds the server URL and the account id, so swapping the URL makes the blob fail
    to open, and no refresh token is sent anywhere.
  - A re-login shows the server URL and asks the owner to confirm it, so a swapped config becomes a
    visible question, not a silent phishing page.
  Code execution in main is a full compromise of the app, and section 6.4 says so.

### 6.2 In a grant

1. In main: the toggle, Away, the limiter and the host denylist pass. Then `ask` crosses to `:vault`.
2. In `:vault`: a notification, then a screen that names the computer and the host. Nothing is
   decrypted until the owner taps Look up.
3. Fingerprint 1 unwraps the blob: refresh token, access token, sync, then private key and org key.
4. The owner picks an item. The item denylist passes.
5. Fingerprint 2 signs the answer with K, as `input` does.

Every key, token and plaintext lives in `ByteArray`/`CharArray` and is zeroed in `finally` on
every path: success, deny, timeout or pause. Process death is the exception, and then the memory is
gone anyway. No key material is held between grants. Two fingerprints are deliberate: the first
shows vault item names on the screen, and the second commits one change.

**Re-login every 30 days.** After 30 days from the last full login, or on any of the cases below,
the blob is deleted and the next grant asks for the master password and a 2FA code:
- the blob's GCM tag or the user key's MAC fails (a swapped config, a password change, or a key
  rotation);
- the server rejects the refresh token;
- the Keystore key is gone.

30 days caps how long one stolen blob plus one coerced finger stays useful without the password. It
is a constant, not a setting.

**Forget vault** (a button on the vault setup screen, and automatic when the feature is turned
off) deletes the Keystore key, the blob and the configuration. It is local only and works offline.
Vaultwarden has no endpoint for one device to log itself out, so there is nothing to call. The
server's copy of the device row stays, and its refresh token is useless without the blob.

### 6.3 Server facts and revocation

Read from Vaultwarden's source (`main` at `dbd7829`, 2026-11-24). Phase 2 re-checks them against
the version the owner actually runs.
- **Refresh tokens:**
  - A refresh token is a JWT that wraps a per-device token. It expires 90 days after issue for
    mobile device types and 30 for others.
  - Every refresh issues a new JWT with a new expiry. The per-device token inside stays the same
    until the account's security stamp is reset.
  - The phone's own 30-day re-login is the stricter limit.
- **"Deauthorize sessions"** (`POST /api/accounts/security-stamp`, which needs the master password
  or a 2FA code):
  - It resets the security stamp, rotates every device's refresh token, deletes every device row,
    and pushes a logout.
  - A stored blob is dead after this, even if it is unwrapped later.
  - It logs out **all** of the owner's devices. Vaultwarden has no per-device revoke: `/api/devices`
    is list-only.
- **Key rotation** (a master password change with "rotate account encryption key") also resets the
  stamp and rotates refresh tokens. It is the only thing that retires a user key that may have been
  copied.
- **Client version:**
  - Every login must send `Bitwarden-Client-Version`.
  - Accounts on the new V2 encryption (a COSE-wrapped private key and a signing key pair) need a
    client of at least 2026.10.1. This client implements V1 only, so it sends a version below
    that.
  - The server then refuses a V2 account after the password check, and the client also refuses any
    EncString type other than 2 and 4. That is two independent fail-closed checks.

Lost phone, in SECURITY.md and linked from the setup screen:
1. Deauthorize sessions. This kills the stored session; every other device has to log in again.
2. Change the master password with key rotation.

### 6.4 Threat model

Stolen phone:
- **Locked:** the blob needs a Class 3 biometric match on this device for every use. The PIN alone
  does nothing. A coerced or spoofed finger can unwrap the user key, which is the whole vault, at
  the same bar as the Bitwarden app's biometric unlock. Revocation (above) limits the window.
- **Unlocked, mid-grant:** that grant's memory, including the user key.
- **Keystore extraction:** out of reach on StrongBox and TEE devices as far as the platform
  promises. On a device without StrongBox, a TEE compromise is in scope for the attacker. The setup
  screen shows which one protects the key.

A malicious or compromised login service:
- It can ask, at most 6 times an hour, with a 10-minute cooldown per denied host.
- It can choose a host, but not the item, the description, the collection or the org.
- It learns one cipher id per approved grant. It can't ask for denylisted categories, and it can't
  tell "no account" from "denied".
- Every ask still needs a tap and fingerprint 1 before anything is decrypted. A storm of asks is a
  fatigue attack on that fingerprint. The limiter caps it, and three denials in 24 hours switch
  the computer's toggle off (section 5).
- What remains: the owner approving a lookalike. That is mitigated by showing the item's real URIs
  and the ASCII host.

A compromised SudoStamp app (supply chain, or a bug):
- New compared with revision 1: such an app can wait for the next grant and copy the user key,
  which is the whole vault, with no master password typed.
- A bug in the LAN listener: contained by the process boundary (6.1). The listener's process never
  holds vault material. The user key exists only in `:vault`, between fingerprint 1 and `finally`.
- Code execution in either process, or a malicious build: the user key at the next grant. Only
  reproducible builds, the signing-key rules and the owner's revocation steps (6.3) answer that.
- SECURITY.md's "holds no secret it could leak" becomes: "with password-manager grants enabled,
  it holds a vault session key wrapped by a biometric-per-use Keystore key".
- The feature is off by default and has no effect until it is set up.

## 7. Library: a minimal client, platform primitives only

Chosen: about 600 lines of Kotlin, built only from platform primitives. It implements the published
Bitwarden client format; no new construction:
- V1 account encryption only (section 6.3): EncString types 2 and 4. Any other type, a signed
  public key or a security-state field is refused.
- PBKDF2-HMAC-SHA256 (`SecretKeyFactory`).
- HKDF-Expand (the HMAC composition already used for HPKE).
- EncString type 2: AES-256-CBC with HMAC-SHA256, encrypt-then-MAC, the MAC checked in constant
  time before decrypting.
- RSA-2048-OAEP-SHA1 (`Cipher`) to unwrap the org key.
- Item-level keys, when present, are re-wrapped rather than re-encrypting the fields.
- `HttpsURLConnection` with the system trust store only (user CAs are not trusted), and strict
  `org.json` parsing.

Tests:
- Vectors are produced by the official `bw` CLI against a throwaway server in a CI job, with a fake
  account. The client is then checked both ways: our encryption decrypted by `bw`, and `bw`'s by
  ours. This is the same independent-implementation rule `SshSig` and HPKE follow.
- Each guard gets a mutant.

Rejected: the official SDK (`bitwarden/sdk-internal`).
- **License:** it is GPL-3.0 or the Bitwarden SDK License. The SDK License forbids offering the
  application to third parties (section 3.1), and SudoStamp is distributed. Taking GPL-3.0 would
  relicense the shipped APK away from MIT.
- **It is a native Rust library per ABI.** That breaks the app's zero-runtime-dependency property
  and its verification metadata. (Size not measured.)
- **It is an internal SDK** whose compatibility with third-party servers isn't promised.

Rejected: Argon2id support. The Android platform has no Argon2, and adding it means a native
dependency. The KDF runs only at a full login (setup, and every 30 days), and it must be PBKDF2-SHA256.
Setup refuses an Argon2id account, or one under 600 000 iterations, and says why.

## 8. Computer side

`sudostamp grant <host>`: the exit codes match `input`. 0 means granted and the cipher id is on
stdout. 77 covers every refusal. 75 means unreachable or too old. 69 means not paired v3. 64 means
usage. It writes nothing secret, because nothing secret ever reaches it.

## 9. Phases (one engineer, AI-assisted, with review)

Each phase is its own merge request, stacked on this design.

| # | Work | Estimate |
|---|---|---|
| 0 | This design: review, then the owner's answers | done |
| 1 | Crypto core (KDF, EncString, org-key unwrap, re-encrypt or re-wrap), `bw`-generated vectors, mutants | 3 d |
| 1a | Pure phone rules: host parser, matching, denylist data file and vectors, `grant-request-v1` parser, fuzzing | 1.5 d |
| 1b | Session store: Keystore key (StrongBox, per-use biometric, enrollment invalidation), blob format, 30-day re-login, forget vault, wipe-on-MAC-failure; tests on the emulator and one StrongBox device | 1.5 d |
| 1c | Process split: `:vault` process, private bound service, grant activity, a test that main never loads a vault class or binds with any other call | 1 d |
| 2 | API client (prelogin, token with TOTP 2FA, refresh-token grant and re-seal, client-version header, V2 refusal, strict sync parse, collections, share, verify after write), fixtures, then a live test against a throwaway server running the owner's Vaultwarden version that checks section 6.3 | 3 d |
| 3 | Host side: `sudostamp grant` in `tools/`, shared vectors with the phone | 1.5 d |
| 4 | Screens: setup (server, email, org, collection), grant (candidates, refusals), toggles per computer with auto-off, Limiter, history, Material 3, TalkBack | 3 d |
| 5 | SECURITY.md delta, automated security scan, independent red team, emulator end-to-end, one real device (including the cross-process `/proc/<pid>/mem` check) | 2 d |
| 6 | Login-service side (outside this repo): call `grant` after "no item", denylist parity test | 1 d |
| | **Total** | **about 17 days** |

A release, Play upload and Play data-safety update (the app now talks to a user-chosen server) are
separate and each needs the owner's yes.

## 10. Decisions and what is left

The owner's answers to the first round:
1. Build it: yes.
2. KDF: the account uses PBKDF2-SHA256 at 600 000 iterations already. No Argon2.
3. Session: stored, as in section 6. This overrides revision 1's "log in every grant".
4. Ship it in the public Play build, off by default.
5. Items with a TOTP seed are refused by default, with a per-grant checkbox to allow one.
6. A personal item is moved into the org, not copied.
7. Timeout: 180 s per grant prompt.

Still to settle:
- Answer 3 asked for server-side revocation of this device. Vaultwarden can only revoke all of the
  owner's devices at once (6.3). Proposed: accept that as the lost-phone step and say so in
  SECURITY.md. The alternative is a second account just for grants, which adds an account and
  doesn't fit "move a personal item".
- The re-login period. Proposed: 30 days, fixed.
- Two fingerprints per grant (unwrap, then commit), as proposed in section 6. One prompt would mean
  holding the user key across the choice under a time-based key, which this design rejects.

Verified from source in revision 3 (6.3), to be re-checked live against the owner's version:
- refresh-token lifetime and renewal;
- what deauthorize sessions does;
- key rotation;
- no per-device revoke;
- the client-version gate;
- the share endpoint's checks: the item must be the user's own, and the request must carry the org
  id and at least one collection.

Still to verify in phase 2, live:
- item-level keys through the share endpoint;
- the post-write check that the item is in Agents;
- whether the owner's account is V1, which this client requires.

