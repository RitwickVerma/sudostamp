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
| Key attestation (setup only) | `attest-v1@sudostamp` returns the Keystore's certificate chain for the key just made; `tools/attest.py` verifies it against Google's roots (embedded, pinned) with the system `openssl`. Never on the sudo path | setup tooling |
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
/etc/pam.d/sudo  ->  [probe: paused? phone answers with this user's key within 4 s? else skip]
                     auth sufficient pam_rssh.so ssh_agent_addr=<phone>:7777 auth_key_file=/etc/authorized_keys/${user}.keys cue
                     [hook: only reached when the phone path did not authenticate; tells the desktop]
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

## The desktop's two side channels (1.6)

The optional desktop app (docs/DESKTOP.md) lives entirely outside the authentication path. Two
things on the host serve it, both inside the probe, and both can only make the probe *skip* the
phone:

- **Events.** The probe sends one datagram (`asking`, `skipped`) to
  `/run/user/<uid>/sudostamp/events.sock`, and a hook line after pam_rssh sends `not-approved`
  when the phone path did not authenticate. The hook's PAM control is
  `[success=ignore ignore=ignore default=ignore]`, so it cannot change the stack's result. One
  file, three modes (`sudostamp-probe`, `... after`, `... check`), so the bundle and the packages
  carry the same single helper as before. The datagram carries the sudo's command line, which
  pam_rssh never gives the phone.
- **Pause.** The same probe reads `/run/user/<uid>/sudostamp/paused` before dialling the phone:
  empty is "until resumed", a future unix time is "until then". Paused, it exits 1, so sudo goes
  to the password and the phone sees nothing.

The directory belongs to the user, so both are made *as the user*. Under sudo, `pam_exec` already
runs the probe with the caller's real uid; from a root caller the probe drops first with `setpriv`.
Without `setpriv` (macOS, FreeBSD, which have no probe anyway) there are no events. Each helper is
killed at 250 ms (about 20 ms in practice) and every failure is ignored: the probe's exit status and its 4 s phone check are
exactly what they were. The 4 s check itself reports "offers none of the pinned keys" with its own
exit status (2) inside the script, only to choose the `skipped` reason.

`install.sh doctor --json` and `setup --json` are the same code as `doctor` and `setup` with another
presentation (a JSON object, JSON lines with the questions answered on stdin), so the app drives
the reviewed installer through `pkexec` and adds no privileged code of its own.

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
- Attestation is checked once, at pairing, and only for the key just made: never on the sudo path,
  and the phone serves it to nobody else (see *Pairing, version 2*). It proves the key is in the
  TEE or StrongBox; it is not what enforces the guarantee, the TEE is.
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
  timeout is real time on a dozing phone (the pam_rssh we build also times out, at 75 s, but a
  suspended phone would otherwise stall it that long). Idle, it holds none.
- The notification cannot say *which* command is being authorised: pam_rssh sends
  only opaque signing data. We show the computer (by its key) + address + time, which is all
  that is knowable.
- Upstream pam_rssh has no socket timeout. The probe bounds a dead or silent phone at 4 s, and
  the pam_rssh the installer builds has the timeouts of `tools/patches/pam_rssh-timeouts.patch`
  (connect 5 s, list 10 s, sign 75 s: it must exceed the app's 60 s `APPROVAL_TIMEOUT_MS`), so a
  peer that answers the probe and then stalls holds sudo for at most 75 s. That does not hold
  for a pam_rssh SudoStamp did not build (FreeBSD's port), and macOS and FreeBSD have no probe
  at all (OpenPAM cannot skip a line). The number is a coupling: change the app's approval window and
  the patch (and its pinned hash in `install.sh`) together.

## Pairing, version 2

Written up in `app/src/main/java/com/ritwick/sudostamp/Pairing.kt`; the computer's side is
`tools/pair.py`, and both carry the same test vectors. In short: the phone makes a key for the
computer and commits to it, its nonce, the address it was dialled on and the address to keep;
the computer reveals its nonce; both derive a 6-digit code the person types into the computer.
The computer refuses unless the phone was dialled on the address the computer dialled (a relay's
address is not), and pins the key and the address. The phone records the computer as *new* until
one of its requests is approved; a second pairing attempt while the screen is open cancels the
pairing, finished or not. Version 1 (one key for all computers, no address binding) is refused.

Attestation (1.5) rides on the same pairing without changing its messages or vectors. The key is
made with `setAttestationChallenge(H(tag, Np, D, S))` (the phone's nonce and the two addresses,
all known before the key exists), so the Keystore signs a chain that names this pairing. After
`pair-done` the computer sends `attest-v1@sudostamp`; the phone holds the chain only in the
session, and serves it only to the pairing's own address while the arming lasts. The computer
recomputes the challenge, verifies the chain to a pinned Google root, and compares the leaf's EC
point with the SSH key. Outcomes: attested (StrongBox or TEE), not checkable (warn and go on, or
refuse with `--require-attestation`), or a genuine chain that disagrees (refuse). The result is
kept in `/etc/authorized_keys/<user>.attestation`, beside the key file because pam_rssh reads
every line of that one, and shown by `install.sh status`. A phone that cannot attest, or an app
before 1.5, makes the key without a challenge and the computer says `NOT hardware-attested`.
