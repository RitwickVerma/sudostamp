# Design: grant one password-manager login to an agent (`sudostamp grant`), proposal

Status: proposal, revision 2, with the owner's answers to the first round (section 10). No code.
Nothing here is built.

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
phone: limiter, denylist(host) -> screen "<computer> asks for a login for <host>"
       fingerprint 1 (CryptoObject = vault-session key) -> unwrap refresh token + user key
         (or, with no stored session or after 30 days: master password + 2FA code, section 6)
       phone refreshes its access token, syncs, decrypts, finds Login items whose URI matches <host>,
       shows real name/URI/username
       owner picks one -> denylist(item URIs) -> fingerprint 2 (CryptoObject = K signer)
       phone: org item  -> PUT /api/ciphers/<id>/collections  (adds Agents, keeps the rest)
              personal  -> PUT /api/ciphers/<id>/share        (re-encrypted with the org key, moved)
       phone re-syncs and checks the item decrypts under the org key and is in Agents
       phone wipes every key, token and plaintext; answers  sigK(cipher id)  or FAILURE
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
  - Items with a TOTP seed are refused unless the owner turns that on (open question 5).
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
  - The history row stores the time, the computer, the host and the outcome. It never stores the
    item name.
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
re-login, the phone rewrites the blob without a third prompt. Decrypting always needs the
fingerprint. `k` is zeroed right after use.

**In a grant:**
1. The limiter, the toggle and the host denylist pass, and the screen names the computer and the host.
2. Fingerprint 1 unwraps the blob: refresh token, access token, sync, then private key and org key.
3. The owner picks an item. The item denylist passes.
4. Fingerprint 2 signs the answer with K, as `input` does.

Every key, token and plaintext lives in `ByteArray`/`CharArray` and is zeroed in `finally` on
every path: success, deny, timeout or pause. Process death is the exception, and then the memory is
gone anyway. No key material is held between grants. Two fingerprints are deliberate: the first
shows vault item names on the screen, and the second commits one change.

**Re-login every 30 days.** After 30 days from the last full login, or on any of the cases below,
the blob is deleted and the next grant asks for the master password and a 2FA code:
- the MAC fails (a password change or a key rotation on the server);
- the server rejects the refresh token;
- the Keystore key is gone.

30 days caps how long one stolen blob plus one coerced finger stays useful without the password. It
is a constant, not a setting.

**Forget vault** (a button on the vault setup screen, and automatic when the feature is turned
off):
- It deletes the Keystore key, the blob and the configuration first. This works offline.
- Then, best effort, it asks the server to log the device out.
- The local wipe never waits on the network.

**Server-side revocation** is the owner's tool when the phone is lost. It is linked from the setup
screen and written into SECURITY.md:
1. "Deauthorize sessions" in the web vault invalidates every refresh token, so the blob is dead
   even if it is unwrapped later.
2. Then change the master password with "rotate account encryption key". The user key may have
   been in the thief's hands, and only a rotation retires it.
3. Then remove the device in the web vault's device list, where the server supports it.
(Phase 2 verifies which of these the target server implements; section 9.)

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
- Every ask still needs fingerprint 1 before anything is decrypted. A storm of asks is a fatigue
  attack on the first fingerprint, and the limiter is the control.
- What remains: the owner approving a lookalike. That is mitigated by showing the item's real URIs
  and the ASCII host.

A compromised SudoStamp app (supply chain, or a bug):
- New compared with revision 1: such an app can wait for the next grant and copy the user key,
  which is the whole vault, with no master password typed.
- The LAN listener is the exposed surface. Its parsers are memory-safe Kotlin and refuse before
  any vault code runs. The user key exists in memory only between fingerprint 1 and `finally`.
- SECURITY.md's "holds no secret it could leak" becomes: "with password-manager grants enabled,
  it holds a vault session key wrapped by a biometric-per-use Keystore key".
- The feature is off by default and has no effect until it is set up.

## 7. Library: a minimal client, platform primitives only

Chosen: about 600 lines of Kotlin, built only from platform primitives. It implements the published
Bitwarden client format; no new construction:
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

| # | Work | Estimate |
|---|---|---|
| 0 | This design: review, then the owner's answers | 0.5 d |
| 1 | Crypto core (KDF, EncString, org-key unwrap, re-encrypt or re-wrap), `bw`-generated vectors, mutants | 3 d |
| 1b | Session store: Keystore key (StrongBox, per-use biometric, enrollment invalidation), blob format, 30-day re-login, forget vault, wipe-on-MAC-failure; tests on the emulator and one StrongBox device | 1.5 d |
| 2 | API client (prelogin, token with TOTP 2FA, refresh-token grant and rotation, strict sync parse, collections, share, verify after write, device logout), fixtures, then a live test against a throwaway server that also checks deauthorize-sessions and key rotation | 3 d |
| 3 | Wire format (`grant-request-v1`, phone and `tools/grant.py`), shared vectors, parser fuzzing | 2 d |
| 4 | Screens: setup (server, email, org, collection), grant (candidates, refusals), toggle per computer, Limiter, history, Material 3, TalkBack | 2.5 d |
| 5 | SECURITY.md delta, automated security scan, independent red team, emulator end-to-end, one real device | 2 d |
| 6 | Login-service side (outside this repo): call `grant` after "no item", denylist parity test | 1 d |
| | **Total** | **about 15.5 days** |

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
- The re-login period. Proposed: 30 days, fixed.
- Two fingerprints per grant (unwrap, then commit), as proposed in section 6. One prompt would mean
  holding the user key across the choice under a time-based key, which this design rejects.

To verify in phase 2, against a throwaway server:
- item-level keys and the share endpoint;
- whether refresh tokens rotate;
- that deauthorize sessions kills a stored refresh token;
- key rotation;
- device logout;
- the post-write check that the item is in Agents.
