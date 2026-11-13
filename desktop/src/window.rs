//! The window (egui): "Health" (the doctor checklist, a Fix button per failing check, and the last
//! sudo events this desktop saw) and "Pair a phone". It runs as its own process (`sudostamp-desktop
//! window`) so the tray process never loads a GL stack, and a window crash cannot take the tray down.
//!
//! Unprivileged. Anything that needs root goes through `exec::privileged` (pkexec, polkit's own
//! prompt) and only runs the reviewed installer: `setup --phone <addr> --json`, or an `apply`/`stage`
//! fix from `doctor::plan_fix`.

use crate::doctor::{self, Fix, Level, Report};
use crate::exec::{self, SetupMsg, SetupProc};
use crate::history::{self, Entry};
use crate::paths::{self, Env};
use crate::setup::{self, Phone, Prompt, Setup, StepStatus};
use eframe::egui::{self, Color32, RichText};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const GREEN: Color32 = Color32::from_rgb(0x4A, 0xDE, 0x80);
const AMBER: Color32 = Color32::from_rgb(0xFB, 0xBF, 0x24);
const RED: Color32 = Color32::from_rgb(0xF8, 0x71, 0x71);
const GREY: Color32 = Color32::from_rgb(0x9C, 0xA3, 0xAF);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Health,
    Pair,
}

/// What a background thread reports back.
enum Done {
    Doctor(Result<Report, String>),
    Discover(Result<Vec<Phone>, String>),
    Repair(Result<String, String>),
}

struct App {
    tab: Tab,
    installer: Option<PathBuf>,
    pair_script: Option<PathBuf>,
    history_path: Option<PathBuf>,
    /// `SUDOSTAMP_PKEXEC`: tests only (see `exec::privileged`).
    pkexec_stub: Option<String>,
    ctx: egui::Context,
    tx: Sender<Done>,
    rx: Receiver<Done>,

    doctor: Option<Result<Report, String>>,
    doctor_busy: bool,
    repair_busy: bool,
    repair_note: Option<Result<String, String>>,
    history: Vec<Entry>,
    history_read: Option<SystemTime>,

    phones: Vec<Phone>,
    discovering: bool,
    discover_error: Option<String>,
    discovered_once: bool,
    manual: String,
    code: String,
    run: Option<SetupProc>,
    setup: Setup,
    pairing: Option<Phone>,
    pair_error: Option<String>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// "just now", "5 min ago", "3 h ago", "2 d ago": no time zone needed.
pub fn ago(now: u64, then: u64) -> String {
    let s = now.saturating_sub(then);
    match s {
        0..=59 => "just now".into(),
        60..=3599 => format!("{} min ago", s / 60),
        3600..=86_399 => format!("{} h ago", s / 3600),
        _ => format!("{} d ago", s / 86_400),
    }
}

impl App {
    fn env_for_exec(&self) -> impl Fn(&str) -> Option<String> + use<> {
        let stub = self.pkexec_stub.clone();
        move |k| {
            if k == "SUDOSTAMP_PKEXEC" {
                stub.clone()
            } else {
                None
            }
        }
    }

    fn spawn<F: FnOnce() -> Done + Send + 'static>(&self, f: F) {
        let (tx, ctx) = (self.tx.clone(), self.ctx.clone());
        thread::spawn(move || {
            let _ = tx.send(f());
            ctx.request_repaint();
        });
    }

    fn refresh_doctor(&mut self) {
        let Some(installer) = self.installer.clone() else {
            self.doctor = Some(Err(
                "The SudoStamp installer is not installed (no /usr/bin/sudostamp).".into(),
            ));
            return;
        };
        if self.doctor_busy {
            return;
        }
        self.doctor_busy = true;
        self.spawn(move || Done::Doctor(exec::doctor(&installer)));
    }

    fn refresh_history(&mut self) {
        if let Some(p) = &self.history_path {
            self.history = history::read(p);
        }
        self.history_read = Some(SystemTime::now());
    }

    fn find_phones(&mut self) {
        let Some(script) = self.pair_script.clone() else {
            self.discovered_once = true;
            self.discover_error =
                Some("pair.py was not found: enter the phone's address below.".into());
            return;
        };
        if self.discovering {
            return;
        }
        self.discovering = true;
        self.discovered_once = true;
        self.discover_error = None;
        self.spawn(move || Done::Discover(exec::discover(&script)));
    }

    fn start_pairing(&mut self, phone: Phone) {
        let Some(installer) = self.installer.clone() else {
            self.pair_error = Some("The SudoStamp installer is not installed.".into());
            return;
        };
        self.pair_error = None;
        self.setup = Setup::new();
        self.code.clear();
        match SetupProc::start(&installer, &phone, &self.env_for_exec()) {
            Ok(run) => {
                self.run = Some(run);
                self.pairing = Some(phone);
            }
            Err(e) => self.pair_error = Some(e),
        }
    }

    fn run_fix(&mut self, args: Vec<String>) {
        let Some(installer) = self.installer.clone() else {
            return;
        };
        if self.repair_busy {
            return;
        }
        self.repair_busy = true;
        self.repair_note = None;
        let env = self.env_for_exec();
        self.spawn(move || Done::Repair(exec::repair(&installer, &args, &env)));
    }

    fn poll(&mut self) {
        while let Ok(d) = self.rx.try_recv() {
            match d {
                Done::Doctor(r) => {
                    self.doctor_busy = false;
                    self.doctor = Some(r);
                }
                Done::Discover(r) => {
                    self.discovering = false;
                    match r {
                        Ok(p) => self.phones = p,
                        Err(e) => self.discover_error = Some(e),
                    }
                }
                Done::Repair(r) => {
                    self.repair_busy = false;
                    self.repair_note = Some(r);
                    self.refresh_doctor();
                }
            }
        }
        let mut ended = None;
        if let Some(run) = &mut self.run {
            while let Ok(msg) = run.rx.try_recv() {
                match msg {
                    SetupMsg::Line(l) => self.setup.feed(&l),
                    SetupMsg::Exit(_) => {
                        // stdout closed: the exit status follows within a moment.
                        let mut code = None;
                        for _ in 0..25 {
                            if let Some(c) = run.exit_code() {
                                code = c;
                                break;
                            }
                            thread::sleep(Duration::from_millis(20));
                        }
                        ended = Some(code);
                    }
                }
            }
        }
        if let Some(code) = ended {
            self.setup.finished(code);
        }
        if self.setup.done.is_some() {
            self.run = None; // the process is over (or no longer matters): reap it
        }
    }

    fn health_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Health");
            if ui
                .add_enabled(!self.doctor_busy, egui::Button::new("Check again"))
                .clicked()
            {
                self.refresh_doctor();
                self.refresh_history();
            }
            if self.doctor_busy {
                ui.spinner();
            }
        });
        ui.add_space(4.0);
        let mut go_pair: Option<Option<std::net::SocketAddr>> = None;
        let mut fix: Option<Vec<String>> = None;
        match self.doctor.clone() {
            None => {
                ui.label("Checking…");
            }
            Some(Err(e)) => {
                ui.colored_label(AMBER, format!("The health check is not available: {e}"));
                ui.weak("Older installers have no `doctor --json`: update the sudostamp package.");
            }
            Some(Ok(report)) => {
                for check in &report.checks {
                    ui.horizontal_top(|ui| {
                        let (tag, colour) = match check.level {
                            Level::Ok => ("OK  ", GREEN),
                            Level::Warn => ("WARN", AMBER),
                            Level::Fail => ("FAIL", RED),
                        };
                        ui.label(RichText::new(tag).monospace().color(colour));
                        ui.vertical(|ui| {
                            ui.add(egui::Label::new(&check.text).wrap());
                            // A warning with a fix gets its button too: the one every upgrade shows
                            // ("a block from an older version") is fixed by `apply`.
                            let actionable = check.level == Level::Fail
                                || (check.level == Level::Warn && !check.fix.is_empty());
                            if actionable {
                                match doctor::plan_fix(&check.fix) {
                                    Fix::Installer(args) => {
                                        let label = format!("Fix: sudostamp {}", args.join(" "));
                                        if ui
                                            .add_enabled(
                                                !self.repair_busy,
                                                egui::Button::new(label),
                                            )
                                            .clicked()
                                        {
                                            fix = Some(args);
                                        }
                                    }
                                    Fix::Pair(addr) => {
                                        if !check.fix.is_empty() {
                                            ui.weak(&check.fix);
                                        }
                                        if ui.button("Pair again").clicked() {
                                            go_pair = Some(addr);
                                        }
                                    }
                                    Fix::Show(cmd) => {
                                        // Wrapped, with Copy under it: a long command beside the
                                        // button pushed the button past the window's edge.
                                        ui.add(
                                            egui::Label::new(RichText::new(&cmd).monospace())
                                                .selectable(true)
                                                .wrap(),
                                        );
                                        if ui.small_button("Copy").clicked() {
                                            ui.ctx().copy_text(cmd.clone());
                                        }
                                    }
                                }
                            }
                        });
                    });
                }
            }
        }
        if self.repair_busy {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Waiting for the administrator prompt and the installer…");
            });
        }
        match &self.repair_note {
            Some(Ok(t)) => {
                ui.colored_label(GREEN, format!("Fixed. {t}"));
            }
            Some(Err(e)) => {
                ui.colored_label(RED, format!("The fix did not complete: {e}"));
            }
            None => {}
        }
        if let Some(addr) = go_pair {
            self.tab = Tab::Pair;
            if let Some(a) = addr {
                self.manual = a.to_string();
            }
        }
        if let Some(args) = fix {
            self.run_fix(args);
        }

        ui.add_space(8.0);
        ui.separator();
        ui.heading("Recent sudo on this computer");
        if self.history.is_empty() {
            ui.weak("Nothing yet. Each sudo that asks the phone (or skips it) shows up here.");
        }
        let t = now();
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for e in self.history.iter().rev() {
                    ui.horizontal_wrapped(|ui| {
                        ui.weak(ago(t, e.ts));
                        let colour = match e.outcome {
                            history::Outcome::Approved => GREEN,
                            history::Outcome::NotApproved | history::Outcome::SkippedWrongKey => {
                                RED
                            }
                            _ => GREY,
                        };
                        ui.colored_label(colour, e.outcome.label());
                        ui.add(
                            egui::Label::new(RichText::new(&e.command).monospace())
                                .selectable(true),
                        );
                    });
                }
            });
    }

    fn pair_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Pair a phone");
        ui.add_space(4.0);
        if self.pairing.is_some() || self.setup.done.is_some() {
            self.progress_ui(ui);
            return;
        }
        ui.add(
            egui::Label::new(
                "Open SudoStamp on the phone and tap \"Pair a computer\". Then pick the phone here. \
                 An administrator prompt follows: the installer changes sudo's PAM setup, so \
                 it runs through polkit, not through this window.",
            )
            .wrap(),
        );
        ui.add_space(6.0);
        if !self.discovered_once {
            self.find_phones();
        }
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!self.discovering, egui::Button::new("Find phones"))
                .clicked()
            {
                self.find_phones();
            }
            if self.discovering {
                ui.spinner();
                ui.label("Looking on the network…");
            }
        });
        if let Some(e) = &self.discover_error {
            ui.colored_label(AMBER, e);
        }
        if !self.discovering
            && self.discovered_once
            && self.phones.is_empty()
            && self.discover_error.is_none()
        {
            ui.weak("No phone found. Is its \"Pair a computer\" screen open, on the same network?");
        }
        let mut chosen = None;
        for p in &self.phones {
            if ui
                .button(format!("Pair with {}  ({})", p.name, p.addr))
                .clicked()
            {
                chosen = Some(p.clone());
            }
        }
        ui.add_space(8.0);
        let label = ui.label("Or type the phone's address (shown on its pairing screen):");
        ui.horizontal(|ui| {
            // Named by its label, for screen readers (accesskit) and AT-SPI tools.
            ui.add(egui::TextEdit::singleline(&mut self.manual).hint_text("192.168.1.20:7777"))
                .labelled_by(label.id);
            let addr = setup::manual_address(&self.manual);
            if ui
                .add_enabled(addr.is_some(), egui::Button::new("Pair"))
                .clicked()
            {
                chosen = addr.map(|addr| Phone {
                    addr,
                    name: "the phone".into(),
                });
            }
        });
        if let Some(e) = &self.pair_error {
            ui.colored_label(RED, e);
        }
        if let Some(p) = chosen {
            self.start_pairing(p);
        }
    }

    fn progress_ui(&mut self, ui: &mut egui::Ui) {
        if let Some(p) = &self.pairing {
            ui.label(format!("Pairing with {} ({})", p.name, p.addr));
        }
        ui.add_space(4.0);
        for s in &self.setup.steps {
            ui.horizontal_top(|ui| {
                let (tag, colour) = match s.status {
                    StepStatus::Running => ("... ", GREY),
                    StepStatus::Ok => ("OK  ", GREEN),
                    StepStatus::Failed => ("FAIL", RED),
                };
                ui.label(RichText::new(tag).monospace().color(colour));
                ui.add(egui::Label::new(if s.text.is_empty() { &s.name } else { &s.text }).wrap());
            });
        }
        let mut reply: Option<String> = None;
        match self.setup.prompt.clone() {
            Some(Prompt::Code(text)) => {
                ui.add_space(6.0);
                let label = ui.add(egui::Label::new(RichText::new(text).strong()).wrap());
                ui.horizontal(|ui| {
                    let r = ui
                        .add(
                            egui::TextEdit::singleline(&mut self.code)
                                .char_limit(6)
                                .desired_width(90.0)
                                .hint_text("123456"),
                        )
                        .labelled_by(label.id);
                    // The only thing to do here is type the code: be ready for it.
                    if self.code.is_empty() && !r.has_focus() {
                        r.request_focus();
                    }
                    let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    let ready = self.code.trim().len() == 6;
                    let clicked = ui
                        .add_enabled(ready, egui::Button::new("Send code"))
                        .clicked();
                    if (clicked || (enter && ready))
                        && let Some(line) = self.setup.answer_code(&self.code)
                    {
                        reply = Some(line);
                        self.code.clear();
                    }
                });
            }
            Some(Prompt::Confirm(text)) => {
                ui.add_space(6.0);
                ui.add(egui::Label::new(RichText::new(text).strong()).wrap());
                ui.horizontal(|ui| {
                    if ui.button("Yes").clicked() {
                        reply = self.setup.answer_confirm(true);
                    }
                    if ui.button("No").clicked() {
                        reply = self.setup.answer_confirm(false);
                    }
                });
            }
            None => {}
        }
        if let Some(line) = reply
            && let Some(run) = &mut self.run
            && run.send(&line).is_err()
        {
            self.pair_error = Some("Lost the installer while answering it.".into());
        }
        let mut close = false;
        if let Some(d) = &self.setup.done {
            ui.add_space(8.0);
            ui.separator();
            if d.ok {
                ui.colored_label(GREEN, "Paired.");
            } else {
                ui.colored_label(RED, "Not paired.");
            }
            if !d.text.is_empty() {
                ui.add(egui::Label::new(&d.text).wrap());
            }
            if d.ok && !d.attestation.is_empty() {
                ui.label(RichText::new("Key attestation").strong());
                ui.add(egui::Label::new(&d.attestation).wrap().selectable(true));
            }
            if d.ok && !d.phone.is_empty() {
                ui.weak(format!("Phone: {}", d.phone));
            }
            close = ui.button("Close").clicked();
        } else if ui.button("Cancel").clicked() {
            if let Some(run) = &mut self.run {
                run.stop();
            }
            self.setup.finished(None);
        }
        if close {
            self.run = None;
            self.pairing = None;
            self.setup = Setup::new();
            self.refresh_doctor();
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll();
        // The history file is written by the tray process: re-read it every few seconds.
        if self
            .history_read
            .is_none_or(|t| t.elapsed().unwrap_or_default() > Duration::from_secs(3))
        {
            self.refresh_history();
        }
        let busy = self.doctor_busy || self.discovering || self.repair_busy || self.run.is_some();
        ui.ctx()
            .request_repaint_after(Duration::from_millis(if busy { 100 } else { 1500 }));
        egui::CentralPanel::default_margins().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Health, "Health");
                ui.selectable_value(&mut self.tab, Tab::Pair, "Pair a phone");
            });
            ui.separator();
            match self.tab {
                Tab::Health => self.health_ui(ui),
                Tab::Pair => self.pair_ui(ui),
            }
        });
    }
}

pub fn run(env: Env) -> i32 {
    let installer = paths::installer(env, Path::new(paths::SYSTEM_INSTALLER).exists());
    let pair_script = paths::pair_script(env, installer.as_deref(), &|p| p.exists());
    let history_path = paths::state_dir(env).map(|d| paths::history_file(&d));
    let pkexec_stub = env("SUDOSTAMP_PKEXEC");
    let start_on_pair = env("SUDOSTAMP_WINDOW_TAB").as_deref() == Some("pair");
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("SudoStamp")
            .with_app_id("sudostamp-desktop")
            .with_inner_size([600.0, 700.0])
            .with_min_inner_size([440.0, 420.0]),
        ..Default::default()
    };
    let result = eframe::run_native(
        "SudoStamp",
        options,
        Box::new(move |cc| {
            let (tx, rx) = mpsc::channel();
            let mut app = App {
                tab: if start_on_pair {
                    Tab::Pair
                } else {
                    Tab::Health
                },
                installer,
                pair_script,
                history_path,
                pkexec_stub,
                ctx: cc.egui_ctx.clone(),
                tx,
                rx,
                doctor: None,
                doctor_busy: false,
                repair_busy: false,
                repair_note: None,
                history: Vec::new(),
                history_read: None,
                phones: Vec::new(),
                discovering: false,
                discover_error: None,
                discovered_once: false,
                manual: String::new(),
                code: String::new(),
                run: None,
                setup: Setup::new(),
                pairing: None,
                pair_error: None,
            };
            app.refresh_doctor();
            app.refresh_history();
            Ok(Box::new(app))
        }),
    );
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("sudostamp-desktop: window failed: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ago;

    #[test]
    fn relative_times() {
        assert_eq!(ago(1000, 1000), "just now");
        assert_eq!(ago(1000, 2000), "just now"); // a clock step back is not negative
        assert_eq!(ago(1059, 1000), "just now");
        assert_eq!(ago(1060, 1000), "1 min ago");
        assert_eq!(ago(1000 + 3599, 1000), "59 min ago");
        assert_eq!(ago(1000 + 3600, 1000), "1 h ago");
        assert_eq!(ago(1000 + 86_400 * 3, 1000), "3 d ago");
    }
}
