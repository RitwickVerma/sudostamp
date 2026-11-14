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
use std::os::unix::fs::DirBuilderExt;
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

fn open_window(child: &mut Option<Child>) {
    if let Some(c) = child
        && matches!(c.try_wait(), Ok(None))
    {
        return; // already open
    }
    *child = std::env::current_exe().ok().and_then(|exe| {
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
    let Some(runtime) = paths::runtime_dir(env) else {
        eprintln!("sudostamp-desktop: XDG_RUNTIME_DIR is not set: no login session, nothing to do");
        return 1;
    };
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
        let tx = tx.clone();
        thread::spawn(move || listener::serve(&sock, |e| tx.send(Msg::Event(e)).is_ok()));
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
