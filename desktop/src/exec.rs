//! Running other programs: the installer's `doctor --json`, phone discovery, and (only through
//! pkexec) the installer's privileged subcommands. The one place this program starts a process.
//!
//! Nothing privileged is ever run except as `pkexec <installer> <args>`; polkit asks for the
//! administrator's password itself. The installer is the one reviewed privileged program.

use crate::doctor::{self, Report};
use crate::paths::Env;
use crate::setup::{self, Phone};
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const DOCTOR_TIMEOUT: Duration = Duration::from_secs(20);
const DISCOVER_TIMEOUT: Duration = Duration::from_secs(15);
/// The longest a privileged repair may run (the installer may build pam_rssh).
const REPAIR_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_OUTPUT: usize = 256 * 1024;
const MAX_LINE: usize = 8 * 1024;

/// `spawn`, again on "text file busy" (ETXTBSY): a program written a moment ago can still be open
/// for writing in a child that another thread forked and has not yet exec'd. Tests write their fake
/// installers in parallel and met it one run in six; a real installer could too, right after an update.
fn spawn(cmd: &mut Command) -> io::Result<Child> {
    for _ in 0..20 {
        match cmd.spawn() {
            Err(e) if e.raw_os_error() == Some(26) => thread::sleep(Duration::from_millis(10)),
            r => return r,
        }
    }
    cmd.spawn()
}

/// Run to completion (or stop at the timeout), collecting stdout and stderr apart, each up to
/// `max` bytes: a parser reads stdout alone (a locale warning on stderr must not spoil the JSON).
/// Returns the exit status (`None` = timed out, killed or signalled), stdout and stderr.
type Captured = (Option<i32>, Vec<u8>, Vec<u8>);

fn capture(cmd: Command, timeout: Duration, max: usize) -> io::Result<Captured> {
    capture_with(cmd, None, timeout, max)
}

/// `capture`, with `input` written to the program's stdin (then closed): how a secret reaches
/// a program without being on its command line, which every user can read.
fn capture_with(
    mut cmd: Command,
    input: Option<&[u8]>,
    timeout: Duration,
    max: usize,
) -> io::Result<Captured> {
    let mut child = spawn(
        cmd.stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()),
    )?;
    if let (Some(data), Some(mut stdin)) = (input, child.stdin.take()) {
        // A few bytes into a fresh pipe: this cannot block. A program that exited first is
        // its own failure, reported by its status.
        let _ = stdin.write_all(data);
    }
    let bufs = [
        Arc::new(Mutex::new(Vec::new())),
        Arc::new(Mutex::new(Vec::new())),
    ];
    let (done_tx, done_rx) = mpsc::channel();
    let streams: [Option<Box<dyn Read + Send>>; 2] = [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    ];
    for (stream, buf) in streams.into_iter().zip(bufs.iter()) {
        let Some(mut stream) = stream else { continue };
        let (out, done_tx) = (Arc::clone(buf), done_tx.clone());
        thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            while let Ok(n) = stream.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                if let Ok(mut o) = out.lock() {
                    let room = max.saturating_sub(o.len());
                    o.extend_from_slice(&chunk[..n.min(room)]);
                }
            }
            let _ = done_tx.send(());
        });
    }
    drop(done_tx);
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s.code();
        }
        if start.elapsed() > timeout {
            // A pkexec'd program runs as root: we may not be allowed to kill it, and then waiting
            // would hang this thread for as long as it runs. Give up on it instead.
            if child.kill().is_ok() {
                let _ = child.wait();
            }
            break None;
        }
        thread::sleep(Duration::from_millis(20));
    };
    // Let the readers drain what the process wrote; a grandchild holding the pipe open must not
    // hold us (a second is plenty for a closed process).
    let until = Instant::now() + Duration::from_secs(1);
    while done_rx
        .recv_timeout(until.saturating_duration_since(Instant::now()))
        .is_ok()
    {}
    let take = |b: &Arc<Mutex<Vec<u8>>>| b.lock().map(|o| o.clone()).unwrap_or_default();
    Ok((status, take(&bufs[0]), take(&bufs[1])))
}

/// `doctor --json`, unprivileged. Its exit code (0/1/2) is the report's business, not ours.
pub fn doctor(installer: &Path) -> Result<Report, String> {
    let mut cmd = Command::new(installer);
    cmd.args(["doctor", "--json"]);
    let (status, out, _) = capture(cmd, DOCTOR_TIMEOUT, MAX_OUTPUT)
        .map_err(|e| format!("cannot run {}: {e}", installer.display()))?;
    if status.is_none() {
        return Err("doctor did not finish in time".into());
    }
    doctor::parse(&String::from_utf8_lossy(&out))
}

/// `pair.py discover`, unprivileged: phones whose "Pair a computer" screen is open, and, given
/// the secret of this window's QR code (`qr`, sent on stdin), which of them scanned it. Exit 1
/// only means none were found.
pub fn discover(pair_py: &Path, qr: Option<&str>) -> Result<Vec<Phone>, String> {
    discover_hooks(pair_py, qr, crate::paths::TEST_HOOKS)
}

/// By absolute path, never from PATH: a `python3` earlier in the user's PATH would be handed the
/// QR secret, and its "qr" answer starts the pkexec setup with no click.
const PYTHON3: &str = "/usr/bin/python3";

fn discover_cmd(pair_py: &Path, qr: Option<&str>) -> Command {
    let mut cmd = Command::new(PYTHON3);
    cmd.arg("-I")
        .arg(pair_py)
        .args(["discover", "--timeout", "3"]);
    if qr.is_some() {
        cmd.arg("--qr-stdin");
    }
    cmd
}

/// pair.py must be root-owned all the way up, like the installer (`root_owned`): it reads the
/// secret, and a copy the user can change is anything of the user's. Only `TEST_HOOKS` runs
/// another (a checkout's, a test's stand-in).
fn discover_hooks(pair_py: &Path, qr: Option<&str>, hooks: bool) -> Result<Vec<Phone>, String> {
    let real = fs::canonicalize(pair_py).map_err(|e| format!("{}: {e}", pair_py.display()))?;
    if !hooks && !root_owned(&real) {
        return Err(format!(
            "{} is not owned by root (or it or a directory above it can be written by others): refusing to hand it the pairing secret",
            real.display()
        ));
    }
    let cmd = discover_cmd(&real, qr);
    let input = qr.map(|s| format!("{s}\n").into_bytes());
    let (status, out, _) = capture_with(cmd, input.as_deref(), DISCOVER_TIMEOUT, MAX_OUTPUT)
        .map_err(|e| format!("cannot run {PYTHON3}: {e}"))?;
    match status {
        Some(0 | 1) => Ok(setup::parse_discover(&String::from_utf8_lossy(&out))),
        Some(c) => Err(format!("discovery failed (exit {c})")),
        None => Err("discovery did not finish in time".into()),
    }
}

/// Root-owned and not writable by anyone else: the file and EVERY directory above it (a
/// root-owned directory inside a user-writable one can be renamed away). What is safe to hand to
/// pkexec: a path the user (or anything running as the user) can change between the polkit prompt
/// and the exec would turn one administrator approval into a root shell. `p` is canonical.
fn root_owned(p: &Path) -> bool {
    let ok = |p: &Path| fs::metadata(p).is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0);
    p.ancestors().all(|a| a.as_os_str().is_empty() || ok(a))
}

/// pkexec by absolute path, never from PATH: a `pkexec` earlier in the user's PATH would show its
/// own "administrator password" prompt. It must be root's and setuid.
const PKEXEC: &str = "/usr/bin/pkexec";

/// The pkexec stand-in for tests (a stub that runs the installer unprivileged). Compiled out of a
/// release build: an environment variable must never be able to switch off the root-owned check.
fn pkexec_stub(env: Env, hooks: bool) -> Option<String> {
    if hooks { env("SUDOSTAMP_PKEXEC") } else { None }
}

/// The command line for a privileged installer run: `/usr/bin/pkexec <resolved installer> <args>`.
/// The installer must be `/usr/bin/sudostamp` (another only under `TEST_HOOKS`) and root-owned
/// all the way up (only the test stub skips that).
pub fn privileged(installer: &Path, args: &[String], env: Env) -> Result<Command, String> {
    privileged_hooks(installer, args, env, crate::paths::TEST_HOOKS)
}

fn privileged_hooks(
    installer: &Path,
    args: &[String],
    env: Env,
    hooks: bool,
) -> Result<Command, String> {
    let stub = pkexec_stub(env, hooks);
    if !hooks && installer != Path::new(crate::paths::SYSTEM_INSTALLER) {
        return Err(format!(
            "{} is not {}: refusing to run it with administrator rights",
            installer.display(),
            crate::paths::SYSTEM_INSTALLER
        ));
    }
    let real = fs::canonicalize(installer).map_err(|e| format!("{}: {e}", installer.display()))?;
    if stub.is_none() && !root_owned(&real) {
        return Err(format!(
            "{} is not owned by root (or it or a directory above it can be written by others): refusing to run it with administrator rights",
            real.display()
        ));
    }
    if stub.is_none()
        && !fs::metadata(PKEXEC)
            .is_ok_and(|m| m.uid() == 0 && m.mode() & 0o4000 != 0 && m.mode() & 0o022 == 0)
    {
        return Err(format!(
            "{PKEXEC} is missing or not root's setuid program: install polkit"
        ));
    }
    let mut cmd = Command::new(stub.unwrap_or_else(|| PKEXEC.into()));
    cmd.arg(real).args(args);
    Ok(cmd)
}

/// `doctor --json` through pkexec, for the checks only root can make. Read-only. Blocking: call
/// from a thread.
pub fn root_doctor(installer: &Path, env: Env) -> Result<Report, String> {
    let cmd = privileged(installer, &["doctor".into(), "--json".into()], env)?;
    let (status, out, _) = capture(cmd, DOCTOR_TIMEOUT * 6, MAX_OUTPUT)
        .map_err(|e| format!("cannot run pkexec: {e}"))?;
    match status {
        Some(126) => Err("The administrator prompt was dismissed or refused.".into()),
        None => Err("doctor did not finish in time".into()),
        _ => doctor::parse(&String::from_utf8_lossy(&out)),
    }
}

/// A repair (`apply`/`stage`) through pkexec. Blocking: call from a thread.
pub fn repair(installer: &Path, args: &[String], env: Env) -> Result<String, String> {
    let cmd = privileged(installer, args, env)?;
    let (status, mut out, err) =
        capture(cmd, REPAIR_TIMEOUT, MAX_OUTPUT).map_err(|e| format!("cannot run pkexec: {e}"))?;
    out.extend_from_slice(&err);
    let all = String::from_utf8_lossy(&out);
    let mut tail: Vec<&str> = all.lines().rev().take(6).collect();
    tail.reverse();
    let text = crate::text::clean(&tail.join(" / "), 600);
    match status {
        Some(0) => Ok(text),
        Some(126) => Err("The administrator prompt was dismissed or refused.".into()),
        Some(c) => Err(format!("exit {c}: {text}")),
        None => Err("stopped before it finished".into()),
    }
}

pub enum SetupMsg {
    Line(String),
    Exit(Option<i32>),
}

/// A running `pkexec <installer> setup --phone <addr> --json [--qr]`.
pub struct SetupProc {
    /// `None` once stopped: the reaping happens on a thread of its own.
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    pub rx: Receiver<SetupMsg>,
}

/// One line, bounded: a longer one is cut to `MAX_LINE + 1` bytes (the state machine ignores it)
/// and the rest of it skipped in small reads, never buffered.
fn read_line<R: BufRead>(r: &mut R) -> Option<String> {
    let mut buf = Vec::new();
    let n = r
        .by_ref()
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', &mut buf)
        .ok()?;
    if n == 0 {
        return None;
    }
    if buf.len() > MAX_LINE {
        let mut sink = Vec::new();
        loop {
            sink.clear();
            let n = r
                .by_ref()
                .take(4096)
                .read_until(b'\n', &mut sink)
                .unwrap_or(0);
            if n == 0 || sink.ends_with(b"\n") {
                break;
            }
        }
    }
    Some(String::from_utf8_lossy(&buf).trim_end().to_string())
}

impl SetupProc {
    /// With `qr` (the secret of the code the phone scanned), pairing needs no typed code: the
    /// secret goes to the installer as its first line of stdin.
    pub fn start(
        installer: &Path,
        phone: &Phone,
        qr: Option<&str>,
        env: Env,
    ) -> Result<Self, String> {
        let mut args = vec![
            "setup".to_string(),
            "--phone".into(),
            phone.addr.to_string(),
            "--json".into(),
        ];
        if qr.is_some() {
            args.push("--qr".into());
        }
        let mut child = spawn(
            privileged(installer, &args, env)?
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null()),
        )
        .map_err(|e| format!("cannot run pkexec: {e}"))?;
        let mut stdin = child.stdin.take();
        if let (Some(secret), Some(s)) = (qr, stdin.as_mut()) {
            // Read by the installer only after polkit's prompt, from the pipe's buffer.
            let _ = s
                .write_all(format!("{secret}\n").as_bytes())
                .and_then(|()| s.flush());
        }
        let mut out = io::BufReader::new(child.stdout.take().ok_or("no stdout")?);
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            while let Some(line) = read_line(&mut out) {
                if tx.send(SetupMsg::Line(line)).is_err() {
                    return;
                }
            }
            let _ = tx.send(SetupMsg::Exit(None));
        });
        Ok(SetupProc {
            child: Some(child),
            stdin,
            rx,
        })
    }

    pub fn send(&mut self, text: &str) -> io::Result<()> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        stdin.write_all(text.as_bytes())?;
        stdin.flush()
    }

    /// The exit status once the process is over (this reaps it): `Some(None)` = killed by a signal.
    pub fn exit_code(&mut self) -> Option<Option<i32>> {
        self.child
            .as_mut()
            .and_then(|c| c.try_wait().ok().flatten())
            .map(|s| s.code())
    }

    /// Never blocks the caller (the window's UI thread). Closing stdin first is what ends a setup
    /// waiting for the code or a yes/no (it reads EOF and stops); the kill may be refused, the
    /// installer running as root through pkexec, so the wait happens on a thread of its own.
    pub fn stop(&mut self) {
        self.stdin = None;
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            thread::spawn(move || {
                let _ = c.wait();
            });
        }
    }
}

impl Drop for SetupProc {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn script(name: &str, body: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sudostamp-exec-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let p = d.join("inst");
        fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn doctor_output_is_parsed_whatever_the_exit_code() {
        let p = script(
            "doc",
            r#"echo '{"v":1,"checks":[{"id":"phone","status":"fail","text":"x","fix":""}],"exit":1}'; exit 1"#,
        );
        let r = doctor(&p).unwrap();
        assert_eq!(r.checks.len(), 1);
        let bad = script("docbad", "echo usage: sudostamp; exit 2");
        assert!(doctor(&bad).is_err());
        assert!(doctor(Path::new("/nonexistent/installer")).is_err());
    }

    #[test]
    fn a_hung_program_is_killed() {
        let p = script("hang", "sleep 60");
        let t = Instant::now();
        let (status, _, _) = capture(Command::new(&p), Duration::from_millis(300), 1024).unwrap();
        assert_eq!(status, None);
        assert!(t.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn output_is_bounded() {
        let p = script("flood", "yes | head -c 5000000");
        let (status, out, _) = capture(Command::new(&p), Duration::from_secs(20), 1000).unwrap();
        assert_eq!(status, Some(0));
        assert_eq!(out.len(), 1000);
    }

    #[test]
    fn privileged_runs_refuse_a_user_owned_installer() {
        // Group-writable, so it is refused whoever runs the test: CI runs as root, where a file
        // "of the user's" is root's.
        let p = script("owned", "true");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o775)).unwrap();
        let e = privileged(&p, &["apply".into()], &no_env).unwrap_err();
        assert!(e.contains("not owned by root"), "{e}");
        let stub = |k: &str| (k == "SUDOSTAMP_PKEXEC").then(|| "/usr/bin/env".to_string());
        let cmd = privileged(&p, &["apply".into()], &stub).unwrap();
        assert_eq!(cmd.get_program(), "/usr/bin/env");
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args[0].ends_with("/inst") && args[1] == "apply", "{args:?}");
    }

    #[test]
    fn a_root_owned_system_binary_is_accepted() {
        // pkexec by its absolute path, never from PATH; where polkit is not installed (a CI
        // image), the refusal names it instead.
        match privileged(Path::new("/usr/bin/env"), &[], &no_env) {
            Ok(cmd) => assert_eq!(cmd.get_program(), PKEXEC),
            Err(e) => assert!(
                e.contains(PKEXEC) && !Path::new(PKEXEC).exists() || e.contains("setuid"),
                "{e}"
            ),
        }
        assert!(privileged(Path::new("/nonexistent"), &[], &no_env).is_err());
    }

    #[test]
    fn a_root_owned_file_in_a_writable_directory_is_refused() {
        // /tmp is root's but world-writable (sticky): a file under it could be swapped by renaming
        // what is above it, whoever owns the file.
        let d = std::env::temp_dir().join(format!("sudostamp-anc-{}", std::process::id()));
        fs::create_dir_all(&d).unwrap();
        let e = privileged(&d, &[], &no_env).unwrap_err();
        assert!(e.contains("not owned by root"), "{e}");
        assert!(!root_owned(&fs::canonicalize(&d).unwrap()));
        assert!(root_owned(Path::new("/usr/bin")));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn doctor_reads_stdout_only() {
        let p = script(
            "docnoise",
            r#"echo 'bash: warning: setlocale: LC_ALL: cannot change locale' >&2
echo '{"v":1,"checks":[{"id":"phone","status":"ok","text":"x","fix":""}],"exit":0}'"#,
        );
        assert_eq!(doctor(&p).unwrap().checks.len(), 1);
    }

    #[test]
    fn setup_lines_and_answers_flow_through_a_stub_pkexec() {
        // The "installer" asks for a code, reads it, and finishes: the whole protocol, with the
        // stub standing in for pkexec so nothing privileged runs.
        let p = script(
            "setup",
            r#"echo '{"v":1,"step":"pair","status":"start","text":"Pairing"}'
echo '{"v":1,"ask":"code","text":"Type the code"}'
read code
echo "{\"v\":1,\"done\":true,\"attestation\":\"a\",\"phone\":\"1.2.3.4:7777\",\"text\":\"got $code\"}""#,
        );
        let stub = |k: &str| (k == "SUDOSTAMP_PKEXEC").then(|| "/usr/bin/env".to_string());
        let phone = Phone {
            addr: "1.2.3.4:7777".parse().unwrap(),
            name: "t".into(),
            scanned: false,
        };
        let mut run = SetupProc::start(&p, &phone, None, &stub).unwrap();
        let mut st = setup::Setup::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut sent = false;
        while st.done.is_none() && Instant::now() < deadline {
            if let Ok(SetupMsg::Line(l)) = run.rx.recv_timeout(Duration::from_millis(100)) {
                st.feed(&l);
            }
            if !sent && let Some(a) = st.answer_code("123456") {
                run.send(&a).unwrap();
                sent = true;
            }
        }
        let d = st.done.expect("the stub installer finished");
        assert!(
            d.ok && d.text == "got 123456" && d.phone == "1.2.3.4:7777",
            "{d:?}"
        );
    }

    #[test]
    fn by_qr_the_secret_goes_on_stdin_never_on_the_command_line() {
        // The "installer" reports its arguments and the first line of its stdin.
        let p = script(
            "setupqr",
            r#"read s
echo "{\"v\":1,\"done\":true,\"attestation\":\"\",\"phone\":\"$*\",\"text\":\"$s\"}""#,
        );
        let stub = |k: &str| (k == "SUDOSTAMP_PKEXEC").then(|| "/usr/bin/env".to_string());
        let phone = Phone {
            addr: "1.2.3.4:7777".parse().unwrap(),
            name: "t".into(),
            scanned: true,
        };
        // The protocol's public test vector (QrPairingTest.kt).
        let vector = "ZGVmZ2hpamtsbW5vcHFycw";
        let run = SetupProc::start(&p, &phone, Some(vector), &stub).unwrap();
        let mut st = setup::Setup::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while st.done.is_none() && Instant::now() < deadline {
            if let Ok(SetupMsg::Line(l)) = run.rx.recv_timeout(Duration::from_millis(100)) {
                st.feed(&l);
            }
        }
        let d = st.done.expect("the stub installer finished");
        assert_eq!(d.text, vector);
        assert_eq!(d.phone, "setup --phone 1.2.3.4:7777 --json --qr");
        assert!(!d.phone.contains(vector));
    }

    #[test]
    fn discovery_hands_the_secret_over_on_stdin() {
        // A stand-in pair.py: python3 -I runs it, so it must be Python.
        let d = std::env::temp_dir().join(format!("sudostamp-disc-{}", std::process::id()));
        fs::create_dir_all(&d).unwrap();
        let py = d.join("pair.py");
        fs::write(
            &py,
            "import sys\nassert sys.argv[1:] == ['discover', '--timeout', '3', '--qr-stdin']\n\
             s = sys.stdin.readline().strip()\n\
             print('192.168.1.20:7777\\tPixel\\t' + ('qr' if s == 'SECRET' else 'no'))\n",
        )
        .unwrap();
        if Command::new(PYTHON3).arg("-V").output().is_err() {
            return; // no python3 in this test environment: nothing to run it with
        }
        let p = discover(&py, Some("SECRET")).unwrap();
        assert_eq!(p.len(), 1);
        assert!(p[0].scanned);
        assert!(!discover(&py, Some("OTHER")).unwrap()[0].scanned);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn discovery_runs_python_by_absolute_path() {
        // A `python3` earlier in the user's PATH would read the QR secret.
        let cmd = discover_cmd(Path::new("/usr/lib/sudostamp/pair.py"), Some("S"));
        assert_eq!(cmd.get_program(), "/usr/bin/python3");
    }

    #[test]
    fn outside_tests_discovery_refuses_a_pair_py_not_owned_by_root() {
        // Under the temp directory (the user's, or a world-writable /tmp under CI's root): the
        // file could be anybody's program, and it is handed the QR secret.
        let d = std::env::temp_dir().join(format!("sudostamp-discown-{}", std::process::id()));
        fs::create_dir_all(&d).unwrap();
        let py = d.join("pair.py");
        fs::write(&py, "print('203.0.113.9:7777\\tPixel\\tqr')\n").unwrap();
        let r = discover_hooks(&py, Some("SECRET"), false);
        fs::remove_dir_all(&d).unwrap();
        let e = r.expect_err("a user's pair.py is refused");
        assert!(e.contains("not owned by root"), "{e}");
        // A root-owned file passes that check (what python then makes of it is another matter).
        if let Err(e) = discover_hooks(Path::new("/usr/bin/true"), None, false) {
            assert!(!e.contains("not owned by root"), "{e}");
        }
    }

    #[test]
    fn outside_tests_pkexec_runs_only_the_packaged_installer() {
        // A root-owned binary is not therefore the installer: `/usr/bin/env apply` as root is
        // not what the polkit prompt was for. And the stub is ignored, so the checks stay on.
        let stub = |k: &str| (k == "SUDOSTAMP_PKEXEC").then(|| "/usr/bin/env".to_string());
        assert_eq!(pkexec_stub(&stub, false), None);
        let e = privileged_hooks(Path::new("/usr/bin/env"), &["apply".into()], &stub, false)
            .unwrap_err();
        assert!(e.contains(crate::paths::SYSTEM_INSTALLER), "{e}");
        let p = script("ownedrel", "true");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(privileged_hooks(&p, &["apply".into()], &stub, false).is_err());
    }

    #[test]
    fn long_lines_are_cut_not_buffered() {
        let data = format!("{}\nshort\n", "x".repeat(MAX_LINE * 3));
        let mut r = io::BufReader::new(data.as_bytes());
        assert_eq!(read_line(&mut r).unwrap().len(), MAX_LINE + 1);
        assert_eq!(read_line(&mut r).unwrap(), "short");
        assert_eq!(read_line(&mut r), None);
    }
}
