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

/// Run to completion (or kill at the timeout), collecting stdout and stderr up to `max` bytes.
/// Returns the exit status (`None` = killed or signalled) and the output.
fn capture(mut cmd: Command, timeout: Duration, max: usize) -> io::Result<(Option<i32>, Vec<u8>)> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let out = Arc::new(Mutex::new(Vec::new()));
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
    for mut stream in streams.into_iter().flatten() {
        let (out, done_tx) = (Arc::clone(&out), done_tx.clone());
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stream.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if let Ok(mut o) = out.lock() {
                    let room = max.saturating_sub(o.len());
                    o.extend_from_slice(&buf[..n.min(room)]);
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
            let _ = child.kill();
            let _ = child.wait();
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
    let bytes = out.lock().map(|o| o.clone()).unwrap_or_default();
    Ok((status, bytes))
}

/// `doctor --json`, unprivileged. Its exit code (0/1/2) is the report's business, not ours.
pub fn doctor(installer: &Path) -> Result<Report, String> {
    let mut cmd = Command::new(installer);
    cmd.args(["doctor", "--json"]);
    let (status, out) = capture(cmd, DOCTOR_TIMEOUT, MAX_OUTPUT)
        .map_err(|e| format!("cannot run {}: {e}", installer.display()))?;
    if status.is_none() {
        return Err("doctor did not finish in time".into());
    }
    doctor::parse(&String::from_utf8_lossy(&out))
}

/// `pair.py discover`, unprivileged: phones whose "Pair a computer" screen is open. Exit 1 only
/// means none were found.
pub fn discover(pair_py: &Path) -> Result<Vec<Phone>, String> {
    let mut cmd = Command::new("python3");
    cmd.arg("-I")
        .arg(pair_py)
        .args(["discover", "--timeout", "3"]);
    let (status, out) = capture(cmd, DISCOVER_TIMEOUT, MAX_OUTPUT)
        .map_err(|e| format!("cannot run python3: {e}"))?;
    match status {
        Some(0 | 1) => Ok(setup::parse_discover(&String::from_utf8_lossy(&out))),
        Some(c) => Err(format!("discovery failed (exit {c})")),
        None => Err("discovery did not finish in time".into()),
    }
}

/// Root-owned and not writable by anyone else, itself and its directory: what is safe to hand to
/// pkexec. A path the user (or anything running as the user) can rewrite between the polkit prompt
/// and the exec would turn one administrator approval into a root shell.
fn root_owned(p: &Path) -> bool {
    let ok = |p: &Path| fs::metadata(p).is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0);
    ok(p) && p.parent().is_some_and(ok)
}

/// The command line for a privileged installer run: `pkexec <resolved installer> <args>`.
/// `SUDOSTAMP_PKEXEC` replaces pkexec for tests (a stub that runs the installer unprivileged);
/// without it the installer must be root-owned.
pub fn privileged(installer: &Path, args: &[String], env: Env) -> Result<Command, String> {
    let stub = env("SUDOSTAMP_PKEXEC");
    let real = fs::canonicalize(installer).map_err(|e| format!("{}: {e}", installer.display()))?;
    if stub.is_none() && !root_owned(&real) {
        return Err(format!(
            "{} is not owned by root (or others can write it): refusing to run it with administrator rights",
            real.display()
        ));
    }
    let mut cmd = Command::new(stub.unwrap_or_else(|| "pkexec".into()));
    cmd.arg(real).args(args);
    Ok(cmd)
}

/// A repair (`apply`/`stage`) through pkexec. Blocking: call from a thread.
pub fn repair(installer: &Path, args: &[String], env: Env) -> Result<String, String> {
    let cmd = privileged(installer, args, env)?;
    let (status, out) =
        capture(cmd, REPAIR_TIMEOUT, MAX_OUTPUT).map_err(|e| format!("cannot run pkexec: {e}"))?;
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

/// A running `pkexec <installer> setup --phone <addr> --json`.
pub struct SetupProc {
    child: Child,
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
    pub fn start(installer: &Path, phone: &Phone, env: Env) -> Result<Self, String> {
        let args = [
            "setup".to_string(),
            "--phone".into(),
            phone.addr.to_string(),
            "--json".into(),
        ];
        let mut child = privileged(installer, &args, env)?
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("cannot run pkexec: {e}"))?;
        let stdin = child.stdin.take();
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
        Ok(SetupProc { child, stdin, rx })
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
        self.child.try_wait().ok().flatten().map(|s| s.code())
    }

    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
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
        let (status, _) = capture(Command::new(&p), Duration::from_millis(300), 1024).unwrap();
        assert_eq!(status, None);
        assert!(t.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn output_is_bounded() {
        let p = script("flood", "yes | head -c 5000000");
        let (status, out) = capture(Command::new(&p), Duration::from_secs(20), 1000).unwrap();
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
        let cmd = privileged(Path::new("/usr/bin/env"), &[], &no_env).unwrap();
        assert_eq!(cmd.get_program(), "pkexec");
        assert!(privileged(Path::new("/nonexistent"), &[], &no_env).is_err());
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
        };
        let mut run = SetupProc::start(&p, &phone, &stub).unwrap();
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
    fn long_lines_are_cut_not_buffered() {
        let data = format!("{}\nshort\n", "x".repeat(MAX_LINE * 3));
        let mut r = io::BufReader::new(data.as_bytes());
        assert_eq!(read_line(&mut r).unwrap().len(), MAX_LINE + 1);
        assert_eq!(read_line(&mut r).unwrap(), "short");
        assert_eq!(read_line(&mut r), None);
    }
}
