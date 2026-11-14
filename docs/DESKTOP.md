# SudoStamp on the desktop — design

Status: accepted for 1.6.0. Scope: Linux desktops (KDE Plasma, GNOME with the AppIndicator
extension, any StatusNotifierItem host). macOS and FreeBSD keep the command line only.

## Why

The phone side has a screen; the computer side has none. Today a person at the computer cannot
see, without a terminal: whether the phone will be asked at all (paired, reachable, holding the
right key), what is waiting on the phone right now, why sudo fell back to the password, or how to
pause the phone path for a while. Setup and repair need a terminal and the exact commands.

## Non-negotiable: nothing on the authentication path changes trust

- `sudostamp-desktop` (the app) is a **per-user, unprivileged** program. It holds no key, is not in
  the PAM stack, and cannot approve anything. Killing it, or never installing it, changes nothing
  about what sudo accepts.
- The only PAM-side changes are **notifications out of the probe** (fire-and-forget, after dropping
  to the user, killed at 250 ms) and **a pause flag the probe honours**. Both can only make the
  probe *skip* the phone, i.e. go to the password. Neither can make anything authenticate.
- Every privileged action the app offers runs the existing, reviewed installer through `pkexec`
  (`pkexec /usr/bin/sudostamp <subcommand>`), with polkit's own admin prompt. The app adds no new
  privileged code.

## The five features

1. **Tray status.** One icon, four states, updated cheaply:
   - *Ready*: the pinned phone answers `REQUEST_IDENTITIES` with this user's pinned key.
   - *Phone away*: no answer within 4 s (sudo will use the password). Not an error.
   - *Paused*: the pause flag is set (feature 3).
   - *Needs attention*: `doctor --json` reports a FAIL (no PAM block, broken module, bad key file…).
   Checks: at start, on menu open, after every sudo event, and every 5 minutes otherwise (each
   check wakes the phone's listener for one accept; 5 minutes keeps that negligible). The phone
   address comes from the SudoStamp block in `/etc/pam.d/sudo` and the pinned key from
   `/etc/authorized_keys/$USER.keys`; both are world-readable, so no privilege is needed.
2. **Live sudo notifications, with the command.** When sudo is about to ask the phone, the desktop
   says so, *naming the command*, which the phone itself can never show (pam_rssh sends only an
   opaque challenge): "`sudo pacman -Syu` is waiting for your phone (60 s)". Outcomes:
   - *approved*: the sudo process has started its command (a child appears in
     `/proc/<sudo-pid>/task/*/children`, world-readable). The notification turns into "Approved".
   - *not approved*: the after-hook fires (pam_rssh failed: denied, timed out, phone gone):
     "Not approved on the phone: sudo is asking for your password".
   - *skipped*: the probe found the phone away or paused: "Phone not reachable: password".
3. **Pause on this computer.** Tray toggle: *Pause until resumed* / *for 1 hour*. While paused the
   probe exits non-zero before dialling the phone, so sudo goes straight to the password (and the
   phone sees nothing). The flag lives in the user's `$XDG_RUNTIME_DIR` (tmpfs: a reboot or logout
   resumes). Anyone running as the user can set it: the only effect is "use the password".
4. **Pairing and repair window.** A small window (egui) that lists phones found on the network
   (`pair.py discover`, unprivileged), runs `pkexec /usr/bin/sudostamp setup --phone <addr> --json`,
   shows the 6-digit code entry when the installer asks for it, and shows the result including the
   key's attestation. One reviewed privileged path: the installer itself.
5. **Health centre.** The same window's other tab renders `sudostamp doctor --json` as a
   checklist; each failing check offers its fix (a `pkexec` command, or "Pair again" which opens
   feature 4). It also lists the last 100 sudo events this desktop saw (feature 2), kept in
   `$XDG_STATE_HOME/sudostamp/history.jsonl`, the computer-side counterpart of the phone's history.

## Interfaces (both sides build against exactly these)

### Event socket
- Path: `$XDG_RUNTIME_DIR/sudostamp/events.sock`, a `SOCK_DGRAM` Unix socket created by the app
  (directory mode 0700). Absent socket = no app = nothing happens.
- Sender: the probe and its after-hook, **after dropping to the target user**
  (`setpriv --reuid=<uid> --regid=<gid> --init-groups` from util-linux). WHY: the path is under a
  user-controlled directory. Sent as root, a symlink there would let the user aim a root-sent
  datagram (with a command line the user wrote) at a root daemon's socket, such as journald's
  native socket, and forge its input. Sent as the user, it can reach only what the user could.
  No `setpriv` (macOS/FreeBSD) → no events.
- Budget: each helper (the flag check, the send) is killed at 250 ms, so the desktop adds at most
  half a second to a sudo (about 20 ms on a desktop); every failure is ignored and the probe's exit
  code never depends on it. (The first draft said 100 ms: a loaded machine needs that just to start
  python, so it was a target, not a cap.)
- Payload: one UTF-8 JSON object per datagram, at most 2048 bytes, fields:
  `{"v":1,"event":"asking"|"skipped"|"not-approved","sudo_pid":<int>,"tty":"<PAM_TTY or empty>",
  "command":"<sudo's argv joined by spaces, control chars replaced by '?', cut to 512 chars>",
  "reason":"<skipped only: 'away'|'paused'|'wrong-key'>","phone":"<addr>","ts":<unix seconds>}`.
  The app treats every field as untrusted (any process of the user can send datagrams here):
  it validates types and lengths, renders as plain text, and never acts on an event beyond
  displaying it.
- `sudo_pid` is the probe's `$PPID`: `pam_exec` forks the probe from inside sudo's own process.
  `command` comes from `/proc/$PPID/cmdline`, which is world-readable, so the dropped sender reads
  it without privilege (on a `hidepid` /proc it is empty, and the notification says "sudo").
- The after-hook is the line right after `pam_rssh`. It runs whenever the phone path did not
  authenticate, which includes the probe having skipped `pam_rssh`. The app correlates by
  `sudo_pid`: after a `skipped` it ignores the `not-approved` for the same pid.
- The after-hook's PAM control is `[success=ignore ignore=ignore default=ignore]`: whatever it
  returns, the stack's result is unchanged.

### Pause flag
- Path: `$XDG_RUNTIME_DIR/sudostamp/paused` for the target user, i.e.
  `/run/user/<uid>/sudostamp/paused`. Content: empty = until resumed, or a decimal unix time =
  paused until then. The probe checks it **as the user** (the same dropped helper), never following
  a path as root. Unreadable, malformed or in the past = not paused.

### `install.sh doctor --json`
- Same checks as `doctor`, unchanged exit codes (0/1/2). Output: one JSON object
  `{"v":1,"checks":[{"id":"<stable id>","status":"ok"|"warn"|"fail","text":"<what>","fix":"<command or empty>"}…],"exit":<code>}`.
  Stable ids: `platform pam-block pam-rssh helper-<name> local-reader pinned-key phone user`.
- Runs without root for everything a user can read; checks that need root report `warn` with
  text "needs root" instead of failing. Read-only, as `doctor` is today.

### `install.sh setup --json`
- Machine-readable progress on stdout, one JSON object per line; human text goes to stderr.
  Events: `{"v":1,"step":"<name>","status":"start"|"ok"|"fail","text":"…"}`, plus
  `{"v":1,"ask":"code","text":"Type the 6-digit code the phone shows (check it names <label>)"}`
  then the caller writes the code and a newline to stdin, and
  `{"v":1,"ask":"confirm","text":"…"}` answered with `yes`/`no`, and a final
  `{"v":1,"done":true|false,"attestation":"<line>","phone":"<addr>","text":"…"}`.
- Same code path as interactive setup; `--json` changes presentation only.

### Implementation notes (where the plumbing pins down what the text above leaves open)
- **Who runs the probe.** `pam_exec` runs its command with the caller's *real* uid unless given
  `seteuid`, and under sudo the real uid is the user's. So under sudo the probe (and the hook) is
  **already the user, with no privilege**: measured on dash (Debian) and bash (Arch), a helper under
  sudo shows `Uid: 1000 1000 1000 1000` (real, effective, saved and filesystem), so no path in the
  user's directory can make root send or read anything. The helpers then run as they are. Only a root caller
  (`pam_check.py`, `su`, `pam_exec seteuid`) takes the `setpriv` drop. Either way the path under
  `/run/user/<uid>` is only ever touched by the user's uid; any other uid, or no `setpriv`: no events
  and no pause. The word `after` is the first argument of the hook line:
  `auth [success=ignore ignore=ignore default=ignore] pam_exec.so quiet /usr/local/sbin/sudostamp-probe after phone=<addr> keys=<dir>`;
  `check` (for `doctor`) is the phone check alone, with no flag and no event.
- **`command`** starts with sudo's own `argv[0]` (`sudo pacman -Syu`), as `/proc/<pid>/cmdline` has
  it; an empty argument shows as two spaces. When 512 characters of multi-byte text would pass 2048
  bytes, the command is cut further until the datagram fits.
- **`skipped`/`wrong-key`** is sent when the phone answers but offers none of the pinned keys;
  `away` for everything else (nothing answers, a refused connection, a garbled answer).
- **Pause flag.** Empty means empty after white space is stripped (`echo > paused` pauses). More
  than 32 bytes, a non-digit, more than 12 digits, a time not in the future, a directory or a FIFO:
  not paused. A symlink is followed, as the user. The probe exits 1 without dialling the phone and
  sends `skipped`/`paused`; the hook then adds `not-approved` for the same pid, as for any skip.
- **`doctor --json` ids.** The stable ids above, plus `helper-probe` and `helper-is-local` (for
  `helper-<name>`), and three the text did not list: `pam-foreign` (pam_rssh lines SudoStamp did not
  write), `sudoers` (sudo authenticating as root, or "needs root" when the sudoers files cannot be
  read) and `scratch-pam` (a leftover test service). `user` is also reported `ok` (with the user's
  name). An id can appear twice when one check finds two things. Plain `doctor` makes the same
  "needs root" warning, so the two always agree; for a non-root plain `doctor` that is a new exit 2.
  `pinned-key` and the others never need root: their files are world-readable.
- **`setup --json`.** `--phone` is required (the app lists phones itself): without it, `done:false`.
  Steps are `pairing`, `install`, `test` and `apply`, each `start` then `ok`; a failure is one
  `fail` for the step that was running, then `done:false` with the reason in `text` (nothing
  follows `done`). `ask:"confirm"` is asked for the same questions the interactive run asks (an
  older SudoStamp stack to migrate, a temporary Rust toolchain). The `test` step needs the person
  to approve on the phone: its start text says so.

## Explicitly NOT doing (YAGNI)

- No daemon on the authentication path, no privileged helper, no polkit policy of our own.
- No command approval *on the computer*: the phone stays the only authority.
- No settings beyond pause; no multi-phone management (one pinned phone per user, as today).
- No macOS/Windows/FreeBSD desktop: no host to test on.
- No prebuilt binary in the GitLab Release yet: the AUR builds from source, others use
  `cargo install --locked`. A signed reproducible binary can come later if asked for.

## Supply chain for the desktop app

The phone app has zero runtime dependencies; the desktop app cannot (D-Bus, windowing, GL). It is
kept off the authentication path for exactly that reason, and its dependency tree is held small and
checked: `Cargo.lock` committed, `rust-toolchain.toml` pinned, `cargo deny` (advisories, licenses,
bans, sources: crates.io only) in CI, `default-features = false` everywhere, and the crate set is
`ksni`, `zbus` (notifications), `eframe`/`egui` (window), `serde`/`serde_json`.
