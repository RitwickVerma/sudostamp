# Contributing

Issues and merge requests are welcome. Security problems go through [SECURITY.md](SECURITY.md),
not public issues.

The bar every change must clear: **measured, not assumed.** This project's worst bugs were all
invisible to reading the code and obvious minutes after pointing a real request at a real phone
([docs/STATUS.md](docs/STATUS.md) has the list). So:

- `tools/verify.sh` passes (unit tests, the independent OpenSSH/`cryptography` check, build, APK
  sanity). Any change to `SshSig` or `AgentProtocol` must keep `tools/verify_ssh_sig.py` green —
  structure tests alone pass on bytes no SSH implementation accepts.
- A change to the listener or the approval flow is run against a device:
  `tools/reuse_connection_test.py` (no finger) and `tools/simulate_pam_rssh.py` (one approval).
- The commit message says what was verified and how.
- Run `scripts/setup-dev.sh` once: it installs the pre-commit hook that runs the secret scan on
  staged changes (CI scans the whole tree, and gitleaks the whole history).

Deliberate choices, not oversights — please do not "fix" these without discussing first: no
runtime dependencies (no AndroidX), `minSdk 30`, no TLS on the socket, one client at a time, the
password fallback in the PAM stack. [AGENTS.md](AGENTS.md) explains each.

By contributing you agree to license your work under the project's MIT licence. This project is
developed with AI assistance under human direction; disclose AI-generated contributions as such.
