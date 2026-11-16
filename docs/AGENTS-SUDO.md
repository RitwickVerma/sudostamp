# sudo for agents — `sudostamp ask`

SudoStamp 1.6 gives programs that act for you (Hermes, Claude Code, OpenCode, a cron job) one
sanctioned way to run something as root. You still approve each run with your finger, but now
the approval says what it is for.

```sh
sudostamp ask --agent hermes --why "rebuild pam_rssh with the timeout patch" --script fix.sh
sudostamp ask --why "read the unit's log" -- journalctl -u sshd -n 50
ssh edith sudostamp ask --agent hermes --why "..." --script - < fix.sh      # from another machine
sudostamp ask --check                                                      # would one be answered now?
```

## What it does, in order

1. **Readiness, before asking anything.** SudoStamp must be set up on this computer, not paused,
   and the phone must answer with your pinned key within 4 s (the probe's own check). Otherwise
   it exits **75** with the reason. Nothing is asked, so an agent never waits on a prompt that
   cannot arrive, and you never get a request you can't answer.
2. **One approval per run.** It runs
   `sudo -k -- /usr/local/sbin/sudostamp-run <sha256> <agent> -- <why>` with the script on
   stdin. `-k` ignores any cached sudo, so a run never rides on an earlier approval.
3. **No password prompt.** sudo runs in a new session with no controlling terminal. If the phone
   denies or times out, sudo falls through to the password as always, finds no terminal, and fails
   at once: exit **77**, nothing ran. No hung run waiting on a password nobody is there to type.
4. **The runner checks before running.** `sudostamp-run` (root) says `waiting`, and only then
   does `ask` send the script on stdin. An approval that lands after `ask` gave up finds nothing,
   and nothing runs. The runner reads at most 1 MiB, checks it against the hash in its own command line, and refuses with exit **65**,
   running nothing, if they differ. It keeps a root-only copy in `/var/lib/sudostamp/runs/` (the
   newest 200, each headed with agent, reason, hash and user). It then runs the script with bash in
   a clean environment: no pagers, `TERM=dumb`, cwd `/`, stdin closed.
5. **The result.** The script's own exit status and output (stdout carries only the script's
   output: sudo prints PAM messages such as the approval cue on stdout, and `ask` moves them to
   stderr) (streamed, or one JSON object with
   `--json`: `ok`, `stage`, `exit`, `reason`, `sha256`, `stdout`, `stderr`).

| Exit | Meaning | Anything ran? |
|---|---|---|
| the script's | it ran | yes |
| 64 | bad usage (no `--why`, bad agent name, run as root) | no |
| 70 | the runner refused the script (hash, size) | no |
| 75 | not ready: not set up, paused, phone away or holding another key, or sudo would not ask at all (a `NOPASSWD` rule) | no, and nothing was asked |
| 77 | not approved: denied, timed out, or this user may not sudo | no |
| 124 | asked to stop after `--timeout` | partly; a script that ignores the stop may still be running |

A script can exit with any number, 75 and 77 included, so in plain mode `ask` also says on stderr
`ran; the script exited N` whenever the script ran. Programs should use `--json`: its `stage` says
whether anything ran.

## Where the description shows

The hash, the agent and the reason are in **sudo's own command line**, so every place that already
shows or records sudo shows them, with no new channel to trust:

- **sudo's log**, which `journalctl` shows: `COMMAND=/usr/local/sbin/sudostamp-run <sha> hermes -- rebuild ...`.
- **The desktop app** (`sudostamp-desktop`): the notification and history read
  `hermes: rebuild pam_rssh (script a3f9c2d1e0b7a44c…)`.
- **The phone (1.6)**: the probe already connects to the phone right before pam_rssh does. When the
  phone offers your key and the sudo is an agent's run, the probe sends that command line on the
  connection as the extension `context-v1@sudostamp`, and the approval screen shows *hermes:
  rebuild pam_rssh, SHA-256 a3f9 c2d1 e0b7 a44c …*, reported by the computer's address. Not in the
  notification. An ordinary sudo is never described to the phone: its command line can hold a
  password. A phone older than 1.6 answers FAILURE and the approval looks as before. Nothing
  about the probe's result depends on the answer.

## What the description is and is not

It is **advisory**. pam_rssh signs an opaque challenge, so the phone's signature does not cover the
text, and the probe runs as you. A program already running as you could tell the phone one thing
and run another. The phone says so under the description, and if two different descriptions arrive
for one request it shows a warning instead of either. Binding the text into the signature would
mean changing what pam_rssh signs, a fork of the module on the authentication path, which this
project does not do.

What it does guarantee:

- **The script that runs is the one whose hash you saw.** That holds on the desktop, in sudo's log
  and on the phone, unless something running as you is lying to all three at once. The runner
  refuses any other bytes.
- **Each run is its own approval** (`-k`), every one is in the phone's history, and there is a
  root-only copy of what ran.
- **The description cannot make anything easier to approve.** Approval still needs a fresh finger
  on the phone, and nothing in SudoStamp reads the description to decide anything.

What else approves, or counts:

- **A fingerprint reader on the computer.** Where the installer found one, sudo at the desk tries
  it first (15 s) and over SSH never: an `ask` started from a local session can be approved by a
  finger on that reader, which shows no description. Approve agents from the phone; ignore the
  reader unless you started the request yourself.
- **A NOPASSWD rule** would make sudo skip PAM, the phone included: `ask` checks (`sudo -n -l`) and
  refuses with 75 rather than run anything nobody approved.
- **pam_faillock** (Fedora, RHEL): a denied or timed-out `ask` falls through to the password, finds no
  terminal and fails, which faillock counts as a failed attempt. Denying an agent several times in a
  row can lock the account's password for the faillock interval.

## For agent authors

- Batch your work: one script with every read and write is one tap. Ten `ask`s are ten taps.
- Read before escalating: most of `/etc`, `/usr/share`, `journalctl` and `systemctl` need no root.
- Exit 75 means "not now". Don't retry in a loop: tell the person what the reason says.
- Never pipe a password, and never use `sudo -S`. Never write sudoers `NOPASSWD` rules for yourself.
  A `NOPASSWD` rule for the user would make sudo, and so `ask`, skip the phone entirely.
- `--timeout` stops `ask` waiting. sudo relays the stop to the script, but a root process that
  ignores signals keeps running: give long jobs their own `timeout` inside the script.
- Keep the reason short and true: it is what the person reads before touching the sensor.
