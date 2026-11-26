# Design: grant one password-manager login to an agent (`sudostamp grant`), proposal

Status: proposal for review. No code. Nothing here is built.

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
       owner types master password (Autofill allowed) + 2FA code -> phone logs in to the vault server
       phone syncs, decrypts, finds Login items whose URI matches <host>, shows real name/URI/username
       owner picks one -> denylist(item URIs) -> fingerprint (CryptoObject = K signer)
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
(180 s, because typing a master password and a 2FA code takes longer than a fingerprint). It is
then refused.

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

**Nothing about the vault account is stored at rest except configuration:** the server URL, the
account email, the org id, the Agents collection id, and a random device identifier.

Each grant logs in from scratch: prelogin, KDF, token request with the 2FA code, sync. The access
and refresh tokens, master key, user key, private key, org key and decrypted fields live only in
`ByteArray`/`CharArray` for the length of one grant. They are zeroed in `finally` on every path:
success, deny, timeout, pause, process death being the exception (memory is gone anyway).

Rejected: keeping the refresh token, Keystore-wrapped behind auth-per-use. It saves typing the
password and code. But the token alone can delete or re-share ciphers by id, and a grant still needs
the master password to decrypt names. So it adds an at-rest credential and saves only half the
typing. Trigger to revisit: more than about 4 grants a month.

Stolen phone:
- SudoStamp holds no vault credential, so the thief needs the master password and the second
  factor. That is the same bar as the owner's own Bitwarden app.
- An unlocked phone taken mid-grant exposes that one session's memory.

A malicious or compromised login service:
- It can ask, at most 6 times an hour, with a 10-minute cooldown per denied host.
- It can choose a host, but not the item, the description, the collection or the org.
- It learns one cipher id per approved grant. It can't ask for denylisted categories, and it can't
  tell "no account" from "denied".
- What remains: the owner approving a lookalike. That is mitigated by showing the item's real URIs
  and the ASCII host.

A compromised SudoStamp app (supply chain, or a bug):
- With the feature enabled, it sees the master password at each grant. That is no worse than any
  vault client on the phone, but it is new for SudoStamp.
- SECURITY.md's "holds no secret it could leak" must gain the exception "while a grant is open".
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
dependency. The account must use PBKDF2. Setup refuses an Argon2id account and says why (open
question 2).

## 8. Computer side

`sudostamp grant <host>`: the exit codes match `input`. 0 means granted and the cipher id is on
stdout. 77 covers every refusal. 75 means unreachable or too old. 69 means not paired v3. 64 means
usage. It writes nothing secret, because nothing secret ever reaches it.

## 9. Phases (one engineer, AI-assisted, with review)

| # | Work | Estimate |
|---|---|---|
| 0 | This design: review, then the owner's answers | 0.5 d |
| 1 | Crypto core (KDF, EncString, org-key unwrap, re-encrypt or re-wrap), `bw`-generated vectors, mutants | 3 d |
| 2 | API client (prelogin, token with TOTP 2FA, strict sync parse, collections, share, verify after write), fixtures, then a live test against a throwaway server | 2.5 d |
| 3 | Wire format (`grant-request-v1`, phone and `tools/grant.py`), shared vectors, parser fuzzing | 2 d |
| 4 | Screens: setup (server, email, org, collection), grant (candidates, refusals), toggle per computer, Limiter, history, Material 3, TalkBack | 2.5 d |
| 5 | SECURITY.md delta, automated security scan, independent red team, emulator end-to-end, one real device | 2 d |
| 6 | Login-service side (outside this repo): call `grant` after "no item", denylist parity test | 1 d |
| | **Total** | **about 13.5 days** |

A release, Play upload and Play data-safety update (the app now talks to a user-chosen server) are
separate and each needs the owner's yes.

## 10. Open questions for the owner

1. Build this at all? The alternative is the manual route: five taps in the Bitwarden app, no new
   code, and SudoStamp never sees a master password. Building costs about 2.5 weeks plus a new
   threat-model section. Recommendation: build it only if grants will happen more than a few times
   a month after the bulk move; otherwise keep the manual route.
2. Does the account use PBKDF2 or Argon2id? With Argon2id, either switch it to PBKDF2 (600 000
   iterations) or accept a native dependency. Recommendation: switch.
3. Should each grant ask for the master password and 2FA code, with nothing stored
   (recommended)? The alternative is a Keystore-stored refresh token.
4. Ship it in the public Play build, off by default (recommended, one codebase), or only in a
   sideloaded build flavor?
5. Should items that carry a TOTP seed be grantable? It lets the agent pass 2FA, which also means
   one less factor. Recommendation: refuse by default, with a per-grant checkbox.
6. A personal item is moved into the org: it leaves the personal vault and stays visible to the
   owner through the org. Is a move acceptable, rather than a copy? A copy means two items to
   rotate. Recommendation: move.
7. Is 180 s acceptable for one grant prompt?
