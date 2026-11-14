# sudostamp-desktop

SudoStamp on the desktop: what the phone cannot show, at the computer where sudo runs.
Design and interfaces: [docs/DESKTOP.md](../docs/DESKTOP.md).

- **Tray icon** with four states: Ready, Phone away, Paused, Needs attention. Checked at start, when
  the menu opens, after each sudo and every 5 minutes: the phone's live answer (an ssh-agent
  `REQUEST_IDENTITIES`, 4 s) against the key pinned for you, plus `sudostamp doctor --json`.
- **Notifications that name the command**: "`sudo pacman -Syu` is waiting for your phone", replaced
  by Approved, Not approved (the password) or Phone not reachable (the password). The phone never
  learns the command: pam_rssh sends it only a challenge.
- **Pause** on this computer, until resumed or for an hour: sudo goes straight to the password and
  the phone is not contacted. It lives in `/run/user/<uid>`, so it ends at logout or reboot.
- **A window** (`sudostamp-desktop window`): Health (doctor's checks, a Fix button for each, and the
  last 100 sudo events) and Pair a phone (discovery, the 6-digit code, the key's attestation).

## What it is not

- **Not on the authentication path.** It holds no key, is not in the PAM stack and cannot approve
  anything: the phone is the only authority. If it is not running, sudo behaves exactly as without
  it (the probe's events go nowhere and are ignored).
- **Not privileged.** It runs as you. Repairs and pairing run the `sudostamp` installer through
  `pkexec`, behind polkit's own administrator prompt, and only an installer owned by root and
  writable by no one else.
- **Not a source of truth about approvals.** "Approved" means sudo started a command after asking
  the phone, read from `/proc`, which is all an unprivileged program can see.

## Build and run

Needs Rust 1.100 (pinned in `rust-toolchain.toml`) and the host side installed (`sudostamp`, for
`doctor --json`, `setup --json` and the probe that sends the events).

```sh
cargo build --release --locked
target/release/sudostamp-desktop            # tray + notifications (what autostart runs)
target/release/sudostamp-desktop window     # the window
```

Against a checkout instead of the package: `SUDOSTAMP_INSTALLER=$PWD/../tools/install.sh`.
Arch: the AUR package `sudostamp-desktop` installs the binary, the menu entry and an autostart
entry for every user. GNOME shows tray icons only with the AppIndicator extension
(`gnome-shell-extension-appindicator`); KDE, Xfce, Cinnamon and most others need nothing.

## Develop

```sh
cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings
cargo test --locked                       # the agent test uses ../tools/test/mock_agent.py if python3 is there
SUDOSTAMP_REQUIRE_MOCK=1 cargo test --locked --test agent   # and fails instead of skipping without it
cargo deny check                          # advisories, licences, duplicates, crates.io only
```

The pure modules (`event`, `pam`, `keys`, `agent`, `pause`, `doctor`, `setup`, `history`, `track`,
`state`, `engine`) do no I/O of their own and carry the tests; the edges (`listener`, `notify`,
`tray`, `window`, `exec`, `daemon`) are thin. `#![forbid(unsafe_code)]`.

Dependencies, each justified in `Cargo.toml`: `ksni` (tray), `zbus` (notifications, called
directly), `eframe`/`egui` without default features (the window), `serde`/`serde_json`.
