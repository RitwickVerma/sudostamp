# SudoStamp — design (YAGNI)

**Goal:** approve a `sudo` password prompt on a Linux host by touching the fingerprint
sensor on an Android phone, over the LAN only, with the fingerprint enforced by
hardware (not by app code).

## The whole point: custom code count

| layer | who provides it | custom? |
|---|---|---|
| PAM integration on the host | `pam_rssh` (Rust, MIT, maintained) | **NO** |
| Signature verification | `pam_rssh` | **NO** |
| Pairing (setup only) | the app's ssh-agent extensions `pair-commit/reveal/done-v2@sudostamp` and `tools/pair.py`: numeric comparison with a commitment, so the computer learns the key the phone made for it and the address to keep. Never on the sudo path: pam_rssh never sends them | setup tooling |
| Host installer | `tools/install.sh`: inserts one marked block into sudo's existing PAM stack (Arch, Debian, Fedora/RHEL, openSUSE; macOS/FreeBSD experimental). Runs at install time only, never at authentication | setup tooling |
| Reachability check | `tools/sudostamp-probe.sh`, run by `pam_exec` before pam_rssh: skips it unless the phone answers with this user's key within 4 s. Read-only; it can only make sudo fall to the password sooner | small, on the auth path |
| Fail-closed behaviour | `pam_rssh` (non-zero => PAM falls through) | **NO** |
| Transport | plain TCP: pam_rssh dials `host:port` itself (the `multisock` crate treats any address not starting with `/` as TCP) | **NO** |
| Crypto primitives | Android Keystore (ECDSA P-256, SHA256withECDSA) | **NO** |
| **The Android app** | this repo | **YES — and nothing else** |

No custom code **decides** anything on the privileged path. The app only ever *signs*;
verification happens in a third-party module that already existed and is tested. The two
`pam_exec` helpers in front of it can only *skip* a check (fall to the password sooner), never
grant one: their lines use `[success=ignore ignore=ignore default=1]`.

## Flow

```
sudo on the host
  |
  v
/etc/pam.d/sudo  ->  [probe: phone answers with this user's key within 4 s? else skip]
                     auth sufficient pam_rssh.so ssh_agent_addr=<phone>:7777 auth_key_file=/etc/authorized_keys/${user}.keys cue
  |
  v   (direct TCP, no bridge: pam_rssh connects to the phone itself)
Android app (listening on TCP 7777; serves only peers on the Wi-Fi/Ethernet subnet it was reached on)
  |
  v   (minimal ssh-agent protocol: 2 message types, plus pairing extensions)
Android app
  |  SSH2_AGENTC_SIGN_REQUEST  -> refuse unprompted unless: the key of a paired computer
  |                               AND exactly 32 bytes AND not rate-limited
  |  -> notification "Approve sudo on <computer>?" -> tap (opens the prompt for THAT request)
  |  -> BiometricPrompt (CryptoObject over that computer's key) -> fingerprint
  |  -> Keystore signs INSIDE THE TEE
  v
SSH2_AGENT_SIGN_RESPONSE  ->  pam_rssh verifies -> exit 0 -> sudo granted
```

## Why this is a HARD gate

The Keystore key is created with:

```java
.setUserAuthenticationRequired(true)
.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
```

`setUserAuthenticationParameters(0, ...)` means **timeout = 0 = a fresh biometric
is required for EVERY use.** The TEE refuses to produce a signature without it.
Software — including this app, including malware on the phone — cannot bypass it.
That is the difference from the `termux-fingerprint` approach, where the prompt is
only a request the app makes.

## Threat model

| threat | outcome |
|---|---|
| Malware on the phone tries to sign | **fails** — TEE demands biometric |
| Attacker on the LAN that never paired sends a sign request | **refused unprompted** — its key is not one the phone made |
| A paired computer's key is asked for | the prompt names that computer (flagged until one of its requests is approved); nothing is signed without the user's finger |
| Attacker wants a signature over something else (SSH login, `SSHSIG`) | **refused unprompted** — only 32-byte pam_rssh challenges are ever signed |
| Replay of a captured signature | **fails** — pam_rssh sends fresh data per request |
| MITM relays one computer's challenge into another's request | the challenge only verifies with the issuing computer's key, and asking for that key names that computer on the prompt |
| User cancels / times out / no finger | **no signature** -> pam_rssh fails -> PAM falls through to the password prompt |
| App crashes or phone offline | same — fail-closed, password still works |
| Attacker edits the allowed-keys file | mitigated by root-owned `auth_key_file` (pam_rssh's documented fix) |

## Non-goals (deliberate YAGNI)

- No TLS on the socket — the signature is the security, not the channel. Adding TLS
  would be more custom code for no gain.
- No attestation / certificate chain. Could be added later to prove the key is
  TEE-resident; not required for the guarantee, since the key cannot leave.
- One key per paired computer, and a list to remove them; no key rotation, no multi-phone,
  no accounts, no sync.
- No AndroidX and no third-party runtime dependencies — platform APIs only. (Gradle and AGP
  build it; JUnit is test-only and never ships.)
- Only two ssh-agent message types implemented for sudo (`REQUEST_IDENTITIES`,
  `SIGN_REQUEST`), plus the pairing extensions. Everything else replies with
  `SSH2_AGENT_FAILURE`.
- One client at a time: the listener serves connections serially, which is all pam_rssh needs.
  Each connection gets 30 s of non-approval time and 8 frames, so a stuck or hostile client
  cannot hold the listener (the clock counts time asleep: on a dozing phone a monotonic clock
  does not).

## Known limits (stated honestly)

- `INTERNET` is declared because any socket needs it, but only LAN peers are served: the
  listener drops, before reading, every client that is not inside the subnet of a Wi-Fi or
  Ethernet address the connection arrived on (so no mobile data, no VPN, no tethering).
- The phone must be reachable at a stable address for pam_rssh to dial it. Pairing hands the
  computer the phone's unique-local IPv6 address when the network has one (it survives DHCP
  changes); otherwise the IPv4 address, and a DHCP reservation is the simple answer.
- A foreground service is required for the listener to survive; Android may still
  kill it under extreme memory pressure. If that happens, `sudo` falls back to the
  password — degraded, never unsafe. It restarts on boot and on app update.
- While a request is pending (at most 60 s) the app holds a partial wake lock, so the
  timeout is real time on a dozing phone; pam_rssh sets no timeout of its own and would
  otherwise wait as long as the phone slept. Idle, it holds none.
- The notification cannot say *which* command is being authorised: pam_rssh sends
  only opaque signing data. We show the computer (by its key) + address + time, which is all
  that is knowable.
- pam_rssh has no socket timeout. The probe bounds a dead or silent phone at 4 s; something
  that answers the probe and then stalls pam_rssh can still hold sudo (SECURITY.md).

## Pairing, version 2

Written up in `app/src/main/java/com/ritwick/sudostamp/Pairing.kt`; the computer's side is
`tools/pair.py`, and both carry the same test vectors. In short: the phone makes a key for the
computer and commits to it, its nonce, the address it was dialled on and the address to keep;
the computer reveals its nonce; both derive a 6-digit code the person types into the computer.
The computer refuses unless the phone was dialled on the address the computer dialled (a relay's
address is not), and pins the key and the address. The phone records the computer as *new* until
one of its requests is approved; a second pairing attempt while the screen is open cancels the
pairing, finished or not. Version 1 (one key for all computers, no address binding) is refused.
