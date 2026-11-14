//! The window (egui): "Health" (where this computer stands, what to fix, the last sudo requests)
//! and "Pair a phone". It runs as its own process (`sudostamp-desktop window`) so the tray process
//! never loads a GL stack, and a window crash cannot take the tray down.
//!
//! Unprivileged. Anything that needs root goes through `exec::privileged` (pkexec, polkit's own
//! prompt) and only runs the reviewed installer: `setup --phone <addr> --json`, or an `apply`/`stage`
//! fix from `doctor::plan_fix`.
//!
//! The look is the phone app's (`Ui.kt`): a near-black ground, cards with a hairline outline, one
//! green accent, amber and red only for meaning, the system's sans serif. Same product, same face.

use crate::doctor::{self, Check, Fix, Level, Report};
use crate::exec::{self, SetupMsg, SetupProc};
use crate::history::{self, Entry, Outcome};
use crate::paths::{self, Env};
use crate::setup::{self, Phone, Prompt, Setup, StepStatus};
use eframe::egui::{
    self, Align, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Layout,
    Margin, Pos2, RichText, Sense, Stroke, TextStyle, TextureHandle, Vec2, vec2,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------- the phone app's palette (Ui.kt)
const BG: Color32 = Color32::from_rgb(0x0B, 0x0D, 0x12);
const SURFACE: Color32 = Color32::from_rgb(0x14, 0x18, 0x21);
const SURFACE_HI: Color32 = Color32::from_rgb(0x1C, 0x22, 0x30);
const OUTLINE: Color32 = Color32::from_rgb(0x25, 0x2C, 0x3B);
const FG: Color32 = Color32::from_rgb(0xE7, 0xED, 0xF7);
const MUTED: Color32 = Color32::from_rgb(0x8A, 0x97, 0xAD);
const FAINT: Color32 = Color32::from_rgb(0x5B, 0x65, 0x77);
/// MUTED is the phone's caption grey; desktop paragraphs are longer and read better a step lighter.
const SOFT: Color32 = Color32::from_rgb(0xA3, 0xAF, 0xC2);
const OUTLINE_HI: Color32 = Color32::from_rgb(0x33, 0x3C, 0x50);
const ACCENT: Color32 = Color32::from_rgb(0x4A, 0xDE, 0x80);
const WARN: Color32 = Color32::from_rgb(0xFB, 0xBF, 0x24);
const DANGER: Color32 = Color32::from_rgb(0xF8, 0x71, 0x71);
const ON_ACCENT: Color32 = Color32::from_rgb(0x06, 0x21, 0x0F);

/// The colour's 15% tint, for the ground behind it (Ui.kt's `*_DIM`).
fn dim(c: Color32) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), 0x26)
}

/// The fingerprint mark (Material Symbols "fingerprint", Apache-2.0, see NOTICE) as a 128x128
/// alpha mask, tinted when drawn: egui cannot draw SVG without pulling in an SVG renderer.
/// Made from `data/icons/sudostamp-desktop.svg` with
/// `magick -background none -density 600 <svg> -resize 128x128 -gravity center -extent 128x128
///  -alpha extract -depth 8 gray:data/mark-128.a8`.
const MARK: &[u8; 128 * 128] = include_bytes!("../data/mark-128.a8");

/// The medium weight, when the system has one (titles, buttons).
const MEDIUM: &str = "medium";

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
    mark: TextureHandle,

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

// ---------------------------------------------------------------- what the checks mean, in words

/// A check's name for people: doctor's ids are stable, its first words are not titles.
fn check_title(c: &Check) -> String {
    let t = match c.id.as_str() {
        "platform" => "Platform",
        "user" => "Account",
        "pam-block" => "sudo's PAM setup",
        "pam-rssh" => "pam_rssh module",
        "helper-probe" => "Phone check helper",
        "helper-is-local" => "Remote-session gate",
        "local-reader" => "Fingerprint reader",
        "pinned-key" => "Pinned key",
        "phone" => "Phone",
        "sudoers" => "sudoers",
        "pam-foreign" => "Other pam_rssh lines",
        "scratch-pam" => "Leftover test service",
        _ => "",
    };
    if t.is_empty() {
        c.id.replace('-', " ")
    } else {
        t.to_string()
    }
}

/// doctor's text without its `name: ` lead (the title says that already).
fn check_detail(c: &Check) -> &str {
    match c.text.split_once(": ") {
        Some((lead, rest)) if lead.len() <= 40 && !rest.is_empty() => rest,
        _ => &c.text,
    }
}

/// A check a person (or one button) can act on: a failure, or a warning whose fix is a run of the
/// installer or a new pairing. Everything else that is not OK is a note: worth knowing, nothing to
/// press (e.g. "needs root to read the sudoers files").
fn actionable(c: &Check) -> bool {
    match c.level {
        Level::Ok => false,
        Level::Fail => true,
        Level::Warn => {
            !c.fix.is_empty()
                && matches!(doctor::plan_fix(&c.fix), Fix::Installer(_) | Fix::Pair(_))
        }
    }
}

/// Where the computer stands, from doctor's report: one headline for the top of the window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Standing {
    Checking,
    Unavailable,
    Ready,
    PhoneAway,
    Update,
    Attention,
}

fn standing(doctor: Option<&Result<Report, String>>) -> Standing {
    let Some(r) = doctor else {
        return Standing::Checking;
    };
    let Ok(r) = r else {
        return Standing::Unavailable;
    };
    let fails = |phone: bool| {
        r.checks
            .iter()
            .any(|c| c.level == Level::Fail && (c.id == "phone") == phone)
    };
    if fails(false) {
        Standing::Attention
    } else if fails(true) {
        Standing::PhoneAway
    } else if r.checks.iter().any(actionable) {
        Standing::Update
    } else {
        Standing::Ready
    }
}

/// The one installer run that fixes every actionable row, when they all ask for the same one
/// (an upgrade: "older block", "unpatched pam_rssh", "helper differs" are all `apply`).
fn common_fix(r: &Report) -> Option<Vec<String>> {
    let mut found: Option<Vec<String>> = None;
    for c in r.checks.iter().filter(|c| actionable(c)) {
        match doctor::plan_fix(&c.fix) {
            Fix::Installer(a) => match &found {
                None => found = Some(a),
                Some(f) if *f == a => {}
                Some(_) => return None,
            },
            // A failure the installer run does not cover: no single button.
            Fix::Pair(_) | Fix::Show(_) => return None,
        }
    }
    found
}

// ---------------------------------------------------------------- the design system, desktop side

fn install_look(ctx: &egui::Context) {
    // The system's sans serif (KDE ships Noto Sans) in place of egui's own; egui's stay as the
    // fallback, so a machine without these fonts still draws every glyph.
    let mut fonts = FontDefinitions::default();
    let read = |names: &[&str]| {
        names.iter().find_map(|p| {
            std::fs::metadata(p)
                .ok()
                .filter(|m| m.is_file() && m.len() < 32 << 20)
                .and_then(|_| std::fs::read(p).ok())
        })
    };
    let regular = read(&[
        "/usr/share/fonts/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/google-noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/google-noto-vf/NotoSans[wght].ttf",
    ]);
    let medium = read(&[
        "/usr/share/fonts/noto/NotoSans-Medium.ttf",
        "/usr/share/fonts/truetype/noto/NotoSans-Medium.ttf",
        "/usr/share/fonts/google-noto/NotoSans-Medium.ttf",
    ]);
    let prop = fonts
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    if let Some(bytes) = regular {
        fonts
            .font_data
            .insert("sys-regular".into(), Arc::new(FontData::from_owned(bytes)));
        if let Some(f) = fonts.families.get_mut(&FontFamily::Proportional) {
            f.insert(0, "sys-regular".into());
        }
    }
    let mut med = Vec::new();
    if let Some(bytes) = medium {
        fonts
            .font_data
            .insert("sys-medium".into(), Arc::new(FontData::from_owned(bytes)));
        med.push("sys-medium".to_string());
    }
    med.extend(
        fonts
            .families
            .get(&FontFamily::Proportional)
            .cloned()
            .unwrap_or(prop),
    );
    fonts.families.insert(FontFamily::Name(MEDIUM.into()), med);
    ctx.set_fonts(fonts);

    let mut v = egui::Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = SURFACE;
    v.extreme_bg_color = BG; // text boxes
    v.faint_bg_color = SURFACE_HI;
    v.override_text_color = Some(FG);
    v.hyperlink_color = ACCENT;
    v.selection.bg_fill = dim(ACCENT);
    v.selection.stroke = Stroke::new(1.0, ACCENT);
    v.window_corner_radius = CornerRadius::same(16);
    let r = CornerRadius::same(12);
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, OUTLINE);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, FG);
    v.widgets.inactive.bg_fill = SURFACE_HI;
    v.widgets.inactive.weak_bg_fill = SURFACE_HI;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, OUTLINE);
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, FG);
    v.widgets.inactive.corner_radius = r;
    v.widgets.hovered.bg_fill = Color32::from_rgb(0x24, 0x2B, 0x3B);
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(0x24, 0x2B, 0x3B);
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, Color32::from_rgb(0x35, 0x3F, 0x54));
    v.widgets.hovered.fg_stroke = Stroke::new(1.0, FG);
    v.widgets.hovered.corner_radius = r;
    v.widgets.active.bg_fill = Color32::from_rgb(0x2A, 0x33, 0x46);
    v.widgets.active.weak_bg_fill = Color32::from_rgb(0x2A, 0x33, 0x46);
    v.widgets.active.bg_stroke = Stroke::new(1.0, ACCENT);
    v.widgets.active.fg_stroke = Stroke::new(1.0, FG);
    v.widgets.active.corner_radius = r;
    v.widgets.open = v.widgets.active;
    ctx.set_visuals(v);

    ctx.all_styles_mut(|s| {
        use TextStyle::{Body, Button, Heading, Monospace, Small};
        let p = |size| FontId::new(size, FontFamily::Proportional);
        s.text_styles
            .insert(Heading, FontId::new(22.0, FontFamily::Name(MEDIUM.into())));
        s.text_styles.insert(Body, p(14.5));
        s.text_styles
            .insert(Button, FontId::new(14.5, FontFamily::Name(MEDIUM.into())));
        s.text_styles.insert(Small, p(12.5));
        s.text_styles
            .insert(Monospace, FontId::new(13.0, FontFamily::Monospace));
        s.spacing.item_spacing = vec2(8.0, 6.0);
        s.spacing.button_padding = vec2(16.0, 8.0);
        s.spacing.interact_size.y = 34.0;
        s.spacing.text_edit_width = 260.0;
        s.spacing.scroll = egui::style::ScrollStyle::thin();
    });
}

fn medium(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(MEDIUM.into()))
}

fn title(text: impl Into<String>, size: f32) -> RichText {
    RichText::new(text).font(medium(size)).color(FG)
}

fn muted(text: impl Into<String>) -> RichText {
    RichText::new(text).color(SOFT)
}

/// A small upper-case section label (Ui.kt's OVERLINE).
fn overline(ui: &mut egui::Ui, text: &str) {
    ui.label(
        RichText::new(text.to_uppercase())
            .font(medium(11.5))
            .color(MUTED)
            .extra_letter_spacing(1.2),
    );
}

/// A card: rounded surface with a hairline outline (Ui.kt's `card`).
fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, OUTLINE))
        .corner_radius(CornerRadius::same(18))
        .inner_margin(Margin::symmetric(20, 18))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// A card that wants attention: the same, outlined in `c` on its tint.
fn accent_card<R>(ui: &mut egui::Ui, c: Color32, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.5, c))
        .corner_radius(CornerRadius::same(18))
        .inner_margin(Margin::symmetric(20, 18))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

fn hairline(ui: &mut egui::Ui) {
    ui.add_space(4.0);
    let w = ui.available_width();
    let (r, _) = ui.allocate_exact_size(vec2(w, 1.0), Sense::hover());
    ui.painter().rect_filled(r, 0.0, OUTLINE);
    ui.add_space(4.0);
}

fn primary(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).font(medium(14.5)).color(ON_ACCENT))
        .fill(ACCENT)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(12))
        .min_size(vec2(0.0, 38.0))
}

fn secondary(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).font(medium(14.5)).color(FG))
        .fill(SURFACE_HI)
        .stroke(Stroke::new(1.0, OUTLINE_HI))
        .corner_radius(CornerRadius::same(12))
        .min_size(vec2(0.0, 38.0))
}

fn ghost(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).font(medium(13.5)).color(MUTED))
        .frame(false)
        .min_size(vec2(0.0, 30.0))
}

/// A command to copy: one line in mono on the ground colour, cut with "…" rather than wrapped
/// (a path broken at its hyphen cannot be checked by eye); egui shows it whole on hover, Copy takes
/// it whole.
fn command_block(ui: &mut egui::Ui, cmd: &str) {
    ui.add_space(6.0);
    egui::Frame::new()
        .fill(BG)
        .stroke(Stroke::new(1.0, OUTLINE))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin {
            left: 12,
            right: 6,
            top: 4,
            bottom: 4,
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .add(ghost("Copy"))
                    .on_hover_text("Copy the command")
                    .clicked()
                {
                    ui.ctx().copy_text(cmd.to_string());
                }
                ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                    ui.add(egui::Label::new(RichText::new(cmd).monospace().color(FG)).truncate());
                });
            });
        });
}

#[derive(Clone, Copy)]
enum Glyph {
    Check,
    Cross,
    Bang,
    Dash,
    Pause,
    Info,
}

/// A status disc: the colour's tint, and a glyph drawn in the colour (decorative: the text next
/// to it says the same, so screen readers miss nothing).
fn disc(ui: &mut egui::Ui, glyph: Glyph, c: Color32, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let p = ui.painter();
    let o = rect.center();
    let r = size / 2.0;
    p.circle_filled(o, r, dim(c));
    p.circle_stroke(o, r - 0.5, Stroke::new(1.0, c.gamma_multiply(0.35)));
    let s = Stroke::new((size / 11.0).max(1.6), c);
    let at = |x: f32, y: f32| Pos2::new(o.x + x * r, o.y + y * r);
    match glyph {
        Glyph::Check => {
            p.line_segment([at(-0.42, 0.02), at(-0.12, 0.32)], s);
            p.line_segment([at(-0.12, 0.32), at(0.44, -0.30)], s);
        }
        Glyph::Cross => {
            p.line_segment([at(-0.32, -0.32), at(0.32, 0.32)], s);
            p.line_segment([at(0.32, -0.32), at(-0.32, 0.32)], s);
        }
        Glyph::Bang => {
            p.line_segment([at(0.0, -0.42), at(0.0, 0.12)], s);
            p.circle_filled(at(0.0, 0.38), s.width * 0.65, c);
        }
        Glyph::Dash => {
            p.line_segment([at(-0.34, 0.0), at(0.34, 0.0)], s);
        }
        Glyph::Info => {
            p.circle_filled(at(0.0, -0.36), s.width * 0.65, c);
            p.line_segment([at(0.0, -0.08), at(0.0, 0.40)], s);
        }
        Glyph::Pause => {
            p.line_segment([at(-0.16, -0.32), at(-0.16, 0.32)], s);
            p.line_segment([at(0.16, -0.32), at(0.16, 0.32)], s);
        }
    }
}

/// A rounded pill: short label on its colour's tint (Ui.kt's `tag`).
fn pill(ui: &mut egui::Ui, text: &str, c: Color32) {
    egui::Frame::new()
        .fill(dim(c))
        .corner_radius(CornerRadius::same(100))
        .inner_margin(Margin::symmetric(10, 3))
        .show(ui, |ui| {
            ui.label(RichText::new(text).font(medium(12.0)).color(c));
        });
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
                Some("Phone discovery is not available here: type the address below.".into());
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

    /// The fingerprint mark at `size`, in `c`.
    fn mark(&self, ui: &mut egui::Ui, size: f32, c: Color32) {
        ui.add(
            egui::Image::new(&self.mark)
                .tint(c)
                .fit_to_exact_size(Vec2::splat(size)),
        );
    }

    // ------------------------------------------------------------------------------ header

    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            self.mark(ui, 28.0, ACCENT);
            ui.label(title("SudoStamp", 18.0));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(12.0);
                // A segmented control: the two tabs on one track.
                egui::Frame::new()
                    .fill(SURFACE)
                    .stroke(Stroke::new(1.0, OUTLINE))
                    .corner_radius(CornerRadius::same(12))
                    .inner_margin(Margin::same(3))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 2.0;
                            for (tab, name) in
                                [(Tab::Health, "Health"), (Tab::Pair, "Pair a phone")]
                            {
                                let on = self.tab == tab;
                                let b = egui::Button::selectable(
                                    on,
                                    RichText::new(name).font(medium(13.5)).color(if on {
                                        FG
                                    } else {
                                        MUTED
                                    }),
                                )
                                .fill(if on {
                                    Color32::from_rgb(0x2A, 0x32, 0x44)
                                } else {
                                    Color32::TRANSPARENT
                                })
                                .stroke(if on {
                                    Stroke::new(1.0, OUTLINE_HI)
                                } else {
                                    Stroke::NONE
                                })
                                .corner_radius(CornerRadius::same(9))
                                .min_size(vec2(0.0, 30.0));
                                if ui.add(b).clicked() {
                                    self.tab = tab;
                                }
                            }
                        });
                    });
            });
        });
    }

    // ------------------------------------------------------------------------------ health

    fn hero(&mut self, ui: &mut egui::Ui) {
        let st = standing(self.doctor.as_ref());
        let report: Option<Report> = self.doctor.clone().and_then(Result::ok);
        let report = report.as_ref();
        let to_fix = report.map_or(0, |r| r.checks.iter().filter(|c| actionable(c)).count());
        let (c, head, sub): (Color32, &str, String) = match st {
            Standing::Checking => (
                MUTED,
                "Checking…",
                "Asking the installer and the phone.".into(),
            ),
            Standing::Unavailable => (
                WARN,
                "Health check unavailable",
                match self.doctor.as_ref() {
                    Some(Err(e)) => format!(
                        "{e} An older installer has no `doctor --json`: update the sudostamp package."
                    ),
                    _ => String::new(),
                },
            ),
            Standing::Ready => (
                ACCENT,
                "Ready",
                "sudo on this computer asks your phone, and your fingerprint approves it.".into(),
            ),
            Standing::PhoneAway => (
                WARN,
                "Phone not reachable",
                "sudo asks for your password until the phone answers again (same Wi-Fi, app open \
                 or listening)."
                    .into(),
            ),
            Standing::Update => (
                WARN,
                "Update needed",
                format!(
                    "SudoStamp works, but {} {} out of date. One step fixes {}, with your \
                     administrator password.",
                    to_fix,
                    if to_fix == 1 {
                        "part of it is"
                    } else {
                        "parts of it are"
                    },
                    if to_fix == 1 { "it" } else { "them all" }
                ),
            ),
            Standing::Attention => (
                DANGER,
                "Needs attention",
                "sudo still works with your password. Fix what is below to use your phone again."
                    .into(),
            ),
        };
        card(ui, |ui| {
            ui.horizontal(|ui| {
                // The mark on a disc of its colour's tint: the window's one large, calm signal.
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(68.0), Sense::hover());
                ui.painter().circle_filled(rect.center(), 34.0, dim(c));
                ui.painter().circle_stroke(
                    rect.center(),
                    33.5,
                    Stroke::new(1.0, c.gamma_multiply(0.35)),
                );
                let inner = egui::Rect::from_center_size(rect.center(), Vec2::splat(40.0));
                egui::Image::new(&self.mark).tint(c).paint_at(ui, inner);
                ui.add_space(12.0);
                ui.vertical(|ui| {
                    ui.add_space(2.0);
                    ui.label(title(head, 22.0));
                    ui.add_space(2.0);
                    ui.add(egui::Label::new(muted(sub)).wrap());
                });
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if let Some(r) = report
                    && st == Standing::Update
                    && let Some(args) = common_fix(r)
                {
                    let b = ui
                        .add_enabled(!self.repair_busy, primary("Update now"))
                        .on_hover_text(format!("Runs: pkexec sudostamp {}", args.join(" ")));
                    if b.clicked() {
                        self.run_fix(args);
                    }
                }
                let again = ui
                    .add_enabled(!self.doctor_busy, secondary("Check again"))
                    .clicked();
                if again {
                    self.refresh_doctor();
                    self.refresh_history();
                }
                if self.doctor_busy {
                    ui.spinner();
                }
            });
            if self.repair_busy {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(muted(
                        "Waiting for the administrator prompt and the installer…",
                    ));
                });
            }
            match &self.repair_note {
                Some(Ok(_)) => {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        disc(ui, Glyph::Check, ACCENT, 18.0);
                        ui.label(RichText::new("Done. Checked again below.").color(ACCENT));
                    });
                }
                Some(Err(e)) => {
                    ui.add_space(4.0);
                    ui.horizontal_top(|ui| {
                        disc(ui, Glyph::Cross, DANGER, 18.0);
                        ui.add(
                            egui::Label::new(RichText::new(format!("Not done: {e}")).color(DANGER))
                                .wrap(),
                        );
                    });
                }
                None => {}
            }
        });
    }

    fn checks(&mut self, ui: &mut egui::Ui) {
        let Some(Ok(report)) = self.doctor.clone() else {
            return;
        };
        let shared = common_fix(&report);
        let problems: Vec<&Check> = report.checks.iter().filter(|c| actionable(c)).collect();
        let notes: Vec<&Check> = report
            .checks
            .iter()
            .filter(|c| c.level != Level::Ok && !actionable(c))
            .collect();
        let fine: Vec<&Check> = report
            .checks
            .iter()
            .filter(|c| c.level == Level::Ok)
            .collect();
        let mut go_pair: Option<Option<std::net::SocketAddr>> = None;
        let mut fix: Option<Vec<String>> = None;

        if !problems.is_empty() {
            ui.add_space(12.0);
            card(ui, |ui| {
                overline(
                    ui,
                    if shared.is_some() {
                        "What the update fixes"
                    } else {
                        "To fix"
                    },
                );
                ui.add_space(6.0);
                for (i, c) in problems.iter().enumerate() {
                    if i > 0 {
                        hairline(ui);
                    }
                    let colour = if c.level == Level::Fail { DANGER } else { WARN };
                    let glyph = if c.level == Level::Fail {
                        Glyph::Cross
                    } else {
                        Glyph::Bang
                    };
                    ui.horizontal_top(|ui| {
                        disc(ui, glyph, colour, 26.0);
                        ui.add_space(4.0);
                        ui.vertical(|ui| {
                            ui.label(title(check_title(c), 14.5));
                            ui.add(egui::Label::new(muted(check_detail(c))).wrap());
                            match doctor::plan_fix(&c.fix) {
                                // One button for all of them sits in the card above.
                                Fix::Installer(_) if shared.is_some() => {}
                                Fix::Installer(args) => {
                                    ui.add_space(4.0);
                                    if ui
                                        .add_enabled(!self.repair_busy, secondary("Fix"))
                                        .on_hover_text(format!(
                                            "Runs: pkexec sudostamp {}",
                                            args.join(" ")
                                        ))
                                        .clicked()
                                    {
                                        fix = Some(args);
                                    }
                                }
                                Fix::Pair(addr) => {
                                    ui.add_space(4.0);
                                    if ui.add(secondary("Pair again")).clicked() {
                                        go_pair = Some(addr);
                                    }
                                }
                                Fix::Show(cmd) => command_block(ui, &cmd),
                            }
                        });
                    });
                }
            });
        }

        if !notes.is_empty() {
            ui.add_space(12.0);
            card(ui, |ui| {
                overline(ui, "Good to know");
                ui.add_space(6.0);
                for (i, c) in notes.iter().enumerate() {
                    if i > 0 {
                        hairline(ui);
                    }
                    ui.horizontal_top(|ui| {
                        disc(ui, Glyph::Info, MUTED, 26.0);
                        ui.add_space(4.0);
                        ui.vertical(|ui| {
                            ui.label(title(check_title(c), 14.5));
                            ui.add(egui::Label::new(muted(check_detail(c))).wrap());
                            if let Fix::Show(cmd) = doctor::plan_fix(&c.fix) {
                                command_block(ui, &cmd);
                            }
                        });
                    });
                }
            });
        }

        if !fine.is_empty() {
            ui.add_space(10.0);
            card(ui, |ui| {
                egui::CollapsingHeader::new(
                    RichText::new(format!("{} checks passed", fine.len()))
                        .font(medium(14.0))
                        .color(MUTED),
                )
                .id_salt("passed")
                .default_open(problems.is_empty())
                .show(ui, |ui| {
                    for c in &fine {
                        ui.add_space(2.0);
                        ui.horizontal_top(|ui| {
                            disc(ui, Glyph::Check, ACCENT, 20.0);
                            ui.vertical(|ui| {
                                ui.label(title(check_title(c), 13.5));
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(check_detail(c)).size(12.5).color(MUTED),
                                    )
                                    .wrap(),
                                );
                            });
                        });
                    }
                });
            });
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
    }

    fn activity(&self, ui: &mut egui::Ui) {
        ui.add_space(10.0);
        card(ui, |ui| {
            overline(ui, "Recent sudo on this computer");
            ui.add_space(4.0);
            if self.history.is_empty() {
                ui.add_space(6.0);
                ui.vertical_centered(|ui| {
                    self.mark(ui, 30.0, FAINT);
                    ui.label(muted("No sudo yet."));
                    ui.label(
                        RichText::new("Each one that asks your phone (or skips it) shows up here.")
                            .size(12.5)
                            .color(FAINT),
                    );
                });
                ui.add_space(6.0);
                return;
            }
            let t = now();
            for (i, e) in self.history.iter().rev().take(30).enumerate() {
                if i > 0 {
                    hairline(ui);
                }
                let (glyph, c) = match e.outcome {
                    Outcome::Approved => (Glyph::Check, ACCENT),
                    Outcome::NotApproved => (Glyph::Cross, DANGER),
                    Outcome::SkippedWrongKey => (Glyph::Bang, DANGER),
                    Outcome::SkippedPaused => (Glyph::Pause, WARN),
                    Outcome::SkippedAway => (Glyph::Dash, MUTED),
                };
                ui.horizontal(|ui| {
                    disc(ui, glyph, c, 26.0);
                    ui.add_space(4.0);
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        // The time on the right, where a column of them can be scanned; the
                        // command takes what is left and is cut with "…" (egui shows it whole on
                        // hover).
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(RichText::new(ago(t, e.ts)).size(12.5).color(MUTED));
                            ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                                let cmd = if e.command.is_empty() {
                                    "sudo"
                                } else {
                                    &e.command
                                };
                                ui.add(
                                    egui::Label::new(RichText::new(cmd).monospace().color(FG))
                                        .truncate(),
                                );
                            });
                        });
                        ui.label(RichText::new(e.outcome.label()).size(12.5).color(c));
                    });
                });
            }
        });
    }

    fn health_ui(&mut self, ui: &mut egui::Ui) {
        self.hero(ui);
        self.checks(ui);
        self.activity(ui);
    }

    // ------------------------------------------------------------------------------ pair

    fn step_label(ui: &mut egui::Ui, n: &str, text: &str) {
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(24.0), Sense::hover());
            ui.painter().circle_filled(rect.center(), 12.0, ACCENT);
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                n,
                medium(13.0),
                ON_ACCENT,
            );
            ui.label(title(text, 16.0));
        });
    }

    fn pair_ui(&mut self, ui: &mut egui::Ui) {
        if self.pairing.is_some() || self.setup.done.is_some() {
            self.progress_ui(ui);
            return;
        }
        if !self.discovered_once {
            self.find_phones();
        }
        card(ui, |ui| {
            Self::step_label(ui, "1", "On the phone");
            ui.add(
                egui::Label::new(muted(
                    "Open SudoStamp and tap Pair a computer. Keep that screen open until this \
                     computer says it is done.",
                ))
                .wrap(),
            );
        });
        ui.add_space(10.0);
        let mut chosen = None;
        card(ui, |ui| {
            ui.horizontal(|ui| {
                Self::step_label(ui, "2", "Pick the phone");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if self.discovering {
                        ui.spinner();
                    } else if ui.add(ghost("Search again")).clicked() {
                        self.find_phones();
                    }
                });
            });
            ui.add_space(4.0);
            if self.discovering && self.phones.is_empty() {
                ui.label(muted("Looking on your network…"));
            }
            if let Some(e) = &self.discover_error {
                ui.label(RichText::new(e).color(WARN));
            }
            if !self.discovering
                && self.discovered_once
                && self.phones.is_empty()
                && self.discover_error.is_none()
            {
                ui.add(
                    egui::Label::new(muted(
                        "No phone found. Is its Pair a computer screen open, on the same network?",
                    ))
                    .wrap(),
                );
            }
            for p in &self.phones {
                // A phone: one row you can press, like a list item on the phone.
                let resp = egui::Frame::new()
                    .fill(SURFACE_HI)
                    .stroke(Stroke::new(1.0, OUTLINE))
                    .corner_radius(CornerRadius::same(14))
                    .inner_margin(Margin::symmetric(14, 10))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            let (r, _) = ui.allocate_exact_size(vec2(22.0, 32.0), Sense::hover());
                            ui.painter().rect_stroke(
                                r.shrink(2.0),
                                CornerRadius::same(5),
                                Stroke::new(1.8, ACCENT),
                                egui::StrokeKind::Inside,
                            );
                            ui.painter().line_segment(
                                [
                                    Pos2::new(r.center().x - 3.0, r.bottom() - 6.0),
                                    Pos2::new(r.center().x + 3.0, r.bottom() - 6.0),
                                ],
                                Stroke::new(1.6, ACCENT),
                            );
                            ui.add_space(4.0);
                            ui.vertical(|ui| {
                                ui.label(title(&p.name, 14.5));
                                ui.label(
                                    RichText::new(p.addr.to_string()).monospace().color(MUTED),
                                );
                            });
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                // The row is the button; this says so (one style for "Pair").
                                egui::Frame::new()
                                    .fill(ACCENT)
                                    .corner_radius(CornerRadius::same(10))
                                    .inner_margin(Margin::symmetric(14, 6))
                                    .show(ui, |ui| {
                                        ui.label(title("Pair", 13.5).color(ON_ACCENT));
                                    });
                            });
                        });
                    })
                    .response
                    .interact(Sense::click())
                    .on_hover_cursor(egui::CursorIcon::PointingHand);
                if resp.clicked() {
                    chosen = Some(p.clone());
                }
                ui.add_space(4.0);
            }
            hairline(ui);
            let label = ui.label(muted(
                "Not listed? Type the address its pairing screen shows:",
            ));
            ui.horizontal(|ui| {
                // Named by its label, for screen readers (accesskit) and AT-SPI tools.
                ui.add(
                    egui::TextEdit::singleline(&mut self.manual)
                        .hint_text(RichText::new("e.g. 192.168.1.20:7777").color(FAINT))
                        .font(TextStyle::Monospace)
                        .margin(Margin::symmetric(10, 8)),
                )
                .labelled_by(label.id);
                let addr = setup::manual_address(&self.manual);
                if ui.add_enabled(addr.is_some(), secondary("Pair")).clicked() {
                    chosen = addr.map(|addr| Phone {
                        addr,
                        name: "the phone".into(),
                    });
                }
            });
            ui.add_space(10.0);
            ui.horizontal_top(|ui| {
                disc(ui, Glyph::Info, MUTED, 20.0);
                ui.add(
                    egui::Label::new(muted(
                        "Your administrator password comes next: pairing changes how sudo signs \
                         you in, so the installer asks through polkit, never through this window.",
                    ))
                    .wrap(),
                );
            });
        });
        if let Some(e) = &self.pair_error {
            ui.add_space(6.0);
            ui.label(RichText::new(e).color(DANGER));
        }
        if let Some(p) = chosen {
            self.start_pairing(p);
        }
    }

    fn steps(&self, ui: &mut egui::Ui) {
        for st in &self.setup.steps {
            ui.horizontal_top(|ui| {
                match st.status {
                    StepStatus::Running => {
                        // A spinner on a track, the size of the discs, so the column stays even.
                        let (rect, _) = ui.allocate_exact_size(Vec2::splat(22.0), Sense::hover());
                        ui.painter().circle_filled(rect.center(), 11.0, dim(ACCENT));
                        ui.put(
                            rect.shrink(3.0),
                            egui::Spinner::new().size(16.0).color(ACCENT),
                        );
                    }
                    StepStatus::Ok => disc(ui, Glyph::Check, ACCENT, 22.0),
                    StepStatus::Failed => disc(ui, Glyph::Cross, DANGER, 22.0),
                }
                ui.add_space(2.0);
                let text = if st.text.is_empty() {
                    &st.name
                } else {
                    &st.text
                };
                let c = match st.status {
                    StepStatus::Running => FG,
                    StepStatus::Ok => SOFT,
                    StepStatus::Failed => DANGER,
                };
                ui.add(egui::Label::new(RichText::new(text).color(c)).wrap());
            });
            ui.add_space(3.0);
        }
    }

    fn progress_ui(&mut self, ui: &mut egui::Ui) {
        let mut reply: Option<String> = None;
        let mut close = false;
        let finished_ok = self.setup.done.as_ref().is_some_and(|d| d.ok);
        if !finished_ok {
            card(ui, |ui| {
                if let Some(p) = &self.pairing {
                    overline(ui, "Pairing");
                    ui.label(title(&p.name, 18.0));
                    ui.label(RichText::new(p.addr.to_string()).monospace().color(MUTED));
                    ui.add_space(10.0);
                }
                self.steps(ui);
                if self.setup.steps.is_empty() && self.setup.done.is_none() {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(muted("Waiting for the administrator prompt…"));
                    });
                }
            });
        }

        match self.setup.prompt.clone() {
            Some(Prompt::Code(text)) => {
                ui.add_space(10.0);
                accent_card(ui, ACCENT, |ui| {
                    overline(ui, "On the phone");
                    let label = ui.add(egui::Label::new(title(text, 15.0)).wrap());
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        let r = ui
                            .add(
                                egui::TextEdit::singleline(&mut self.code)
                                    .char_limit(6)
                                    .font(FontId::new(28.0, FontFamily::Monospace))
                                    .desired_width(150.0)
                                    .margin(Margin::symmetric(14, 8))
                                    .hint_text(
                                        RichText::new("······")
                                            .font(FontId::new(28.0, FontFamily::Monospace))
                                            .color(FAINT),
                                    ),
                            )
                            .labelled_by(label.id);
                        self.code.retain(|ch| ch.is_ascii_digit());
                        // The only thing to do here is type the code: be ready for it.
                        if self.code.is_empty() && !r.has_focus() {
                            r.request_focus();
                        }
                        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        let ready = self.code.len() == 6;
                        let clicked = ui
                            .add_enabled(ready, primary("Confirm").min_size(vec2(0.0, 50.0)))
                            .clicked();
                        if (clicked || (enter && ready))
                            && let Some(line) = self.setup.answer_code(&self.code)
                        {
                            reply = Some(line);
                            self.code.clear();
                        }
                    });
                });
            }
            Some(Prompt::Confirm(text)) => {
                ui.add_space(10.0);
                accent_card(ui, WARN, |ui| {
                    overline(ui, "One question");
                    ui.add(egui::Label::new(title(text, 15.0)).wrap());
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.add(primary("Yes, continue")).clicked() {
                            reply = self.setup.answer_confirm(true);
                        }
                        if ui.add(secondary("No, stop")).clicked() {
                            reply = self.setup.answer_confirm(false);
                        }
                    });
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

        if let Some(d) = self.setup.done.clone() {
            if !d.ok {
                ui.add_space(12.0);
            }
            let c = if d.ok { ACCENT } else { DANGER };
            accent_card(ui, c, |ui| {
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(60.0), Sense::hover());
                    ui.painter().circle_filled(rect.center(), 30.0, dim(c));
                    ui.painter().circle_stroke(
                        rect.center(),
                        29.5,
                        Stroke::new(1.0, c.gamma_multiply(0.35)),
                    );
                    if d.ok {
                        let inner = egui::Rect::from_center_size(rect.center(), Vec2::splat(36.0));
                        egui::Image::new(&self.mark).tint(c).paint_at(ui, inner);
                    } else {
                        let o = rect.center();
                        let s = Stroke::new(3.0, c);
                        ui.painter()
                            .line_segment([o + vec2(-9.0, -9.0), o + vec2(9.0, 9.0)], s);
                        ui.painter()
                            .line_segment([o + vec2(9.0, -9.0), o + vec2(-9.0, 9.0)], s);
                    }
                    ui.add_space(10.0);
                    ui.vertical(|ui| {
                        ui.label(title(if d.ok { "Paired" } else { "Not paired" }, 24.0));
                        if let Some(p) = &self.pairing {
                            ui.label(
                                RichText::new(format!("{}  ·  {}", p.name, p.addr)).color(MUTED),
                            );
                        }
                    });
                });
                if !d.text.is_empty() {
                    ui.add_space(8.0);
                    ui.add(egui::Label::new(title(&d.text, 15.0)).wrap());
                }
                if d.ok && !d.attestation.is_empty() {
                    ui.add_space(6.0);
                    hairline(ui);
                    let a = d.attestation.to_ascii_lowercase();
                    let hw = (a.contains("strongbox") || a.contains("tee"))
                        && !a.contains("not hardware");
                    ui.horizontal(|ui| {
                        if hw {
                            pill(ui, "Hardware-backed", ACCENT);
                        } else {
                            pill(ui, "Not proven hardware-backed", WARN);
                        }
                    });
                    ui.add_space(2.0);
                    ui.add(
                        egui::Label::new(muted(&d.attestation))
                            .wrap()
                            .selectable(true),
                    );
                }
                ui.add_space(12.0);
                close = ui
                    .add(primary(if d.ok { "Done" } else { "Back" }).min_size(vec2(0.0, 44.0)))
                    .clicked();
            });
            if d.ok && !self.setup.steps.is_empty() {
                ui.add_space(12.0);
                card(ui, |ui| {
                    egui::CollapsingHeader::new(
                        RichText::new(format!("What happened ({} steps)", self.setup.steps.len()))
                            .font(medium(14.0))
                            .color(MUTED),
                    )
                    .id_salt("what-happened")
                    .default_open(false)
                    .show(ui, |ui| self.steps(ui));
                });
            }
        } else {
            ui.add_space(8.0);
            if ui.add(ghost("Cancel pairing")).clicked() {
                if let Some(run) = &mut self.run {
                    run.stop();
                }
                self.setup.finished(None);
            }
        }
        if close {
            self.run = None;
            self.pairing = None;
            self.setup = Setup::new();
            // Paired: back to Health, which now checks the new setup. Not paired: pick again.
            if finished_ok {
                self.tab = Tab::Health;
            }
            self.refresh_doctor();
        }
        if let Some(e) = &self.pair_error {
            ui.add_space(6.0);
            ui.label(RichText::new(e).color(DANGER));
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
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BG).inner_margin(Margin {
                left: 22,
                right: 10,
                top: 18,
                bottom: 0,
            }))
            .show(ui, |ui| {
                self.header(ui);
                ui.add_space(14.0);
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        // A gutter on the right, so the scroll bar never sits on a card's edge.
                        egui::Frame::new()
                            .inner_margin(Margin {
                                left: 0,
                                right: 12,
                                top: 0,
                                bottom: 24,
                            })
                            .show(ui, |ui| match self.tab {
                                Tab::Health => self.health_ui(ui),
                                Tab::Pair => self.pair_ui(ui),
                            });
                    });
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
            .with_inner_size([560.0, 780.0])
            .with_min_inner_size([460.0, 520.0]),
        ..Default::default()
    };
    let result = eframe::run_native(
        "SudoStamp",
        options,
        Box::new(move |cc| {
            install_look(&cc.egui_ctx);
            let mark = cc.egui_ctx.load_texture(
                "mark",
                egui::ColorImage::from_rgba_unmultiplied(
                    [128, 128],
                    &MARK
                        .iter()
                        .flat_map(|&a| [255, 255, 255, a])
                        .collect::<Vec<u8>>(),
                ),
                egui::TextureOptions {
                    mipmap_mode: Some(egui::TextureFilter::Linear),
                    ..egui::TextureOptions::LINEAR
                },
            );
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
                mark,
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
    use super::*;

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

    fn check(id: &str, level: Level, text: &str, fix: &str) -> Check {
        Check {
            id: id.into(),
            level,
            text: text.into(),
            fix: fix.into(),
        }
    }

    fn report(checks: Vec<Check>) -> Result<Report, String> {
        Ok(Report { checks, exit: 0 })
    }

    const APPLY: &str = "sudo sudostamp apply --phone 192.168.1.5:7777";

    #[test]
    fn standing_puts_real_failures_first_and_a_missing_phone_after() {
        assert_eq!(standing(None), Standing::Checking);
        assert_eq!(standing(Some(&Err("x".into()))), Standing::Unavailable);
        let ok = check("platform", Level::Ok, "platform: arch", "");
        assert_eq!(standing(Some(&report(vec![ok.clone()]))), Standing::Ready);
        let away = check("phone", Level::Fail, "phone: nothing answers", "");
        assert_eq!(
            standing(Some(&report(vec![ok.clone(), away.clone()]))),
            Standing::PhoneAway
        );
        let old = check("pam-block", Level::Warn, "PAM block: older", APPLY);
        assert_eq!(
            standing(Some(&report(vec![ok.clone(), old.clone()]))),
            Standing::Update
        );
        let bad = check(
            "pinned-key",
            Level::Fail,
            "pinned key: writable",
            "sudo chown root x",
        );
        assert_eq!(
            standing(Some(&report(vec![away, old, bad]))),
            Standing::Attention
        );
        // A warning with nothing to run (needs root) does not make the computer out of date.
        let note = check(
            "sudoers",
            Level::Warn,
            "sudoers: needs root",
            "sudo sudostamp doctor",
        );
        assert_eq!(
            standing(Some(&report(vec![ok, note.clone()]))),
            Standing::Ready
        );
        assert!(!actionable(&note));
    }

    #[test]
    fn one_button_only_when_every_fix_is_the_same_run() {
        let a = check("pam-block", Level::Warn, "x", APPLY);
        let b = check(
            "pam-rssh",
            Level::Warn,
            "y",
            &format!("{APPLY}   (builds the module)"),
        );
        let note = check("sudoers", Level::Warn, "z", "sudo sudostamp doctor");
        let r = report(vec![a.clone(), b, note]).unwrap();
        assert_eq!(
            common_fix(&r),
            Some(vec![
                "apply".into(),
                "--phone".into(),
                "192.168.1.5:7777".into()
            ])
        );
        let other = check("helper-probe", Level::Warn, "w", "sudo sudostamp stage");
        assert_eq!(common_fix(&report(vec![a.clone(), other]).unwrap()), None);
        let repair = check("pinned-key", Level::Fail, "k", "sudo sudostamp setup");
        assert_eq!(common_fix(&report(vec![a, repair]).unwrap()), None);
    }

    #[test]
    fn titles_and_details_read_as_words() {
        let c = check(
            "pam-rssh",
            Level::Warn,
            "pam_rssh: loads, but is NOT patched",
            "",
        );
        assert_eq!(
            (check_title(&c).as_str(), check_detail(&c)),
            ("pam_rssh module", "loads, but is NOT patched")
        );
        let c = check(
            "helper-probe",
            Level::Warn,
            "helper /usr/local/sbin/x differs",
            "",
        );
        assert_eq!(check_detail(&c), "helper /usr/local/sbin/x differs");
        let c = check("new-thing", Level::Ok, "new thing: fine", "");
        assert_eq!(check_title(&c), "new thing");
    }

    #[test]
    fn the_mark_is_the_glyph() {
        // Enough ink to be the fingerprint, and not a filled square.
        let ink = MARK.iter().filter(|&&a| a > 128).count();
        assert!((2000..8000).contains(&ink), "{ink}");
    }
}
