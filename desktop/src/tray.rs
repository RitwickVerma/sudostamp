//! The tray icon (StatusNotifierItem): one icon, four states, and the menu. Menu clicks only send a
//! `Cmd` to the daemon's loop; nothing here acts on its own.

use crate::state::{State, Verdict};
use crate::text::{clean, escape_markup};
use ksni::menu::{MenuItem, StandardItem};
use ksni::{Status, ToolTip, Tray};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmd {
    /// Pause the phone path for this many seconds; `None` = until resumed.
    Pause(Option<u64>),
    Resume,
    OpenWindow,
    Quit,
    /// The menu was opened: look at the phone again, so the status is fresh.
    MenuOpened,
}

pub type CmdSink = Arc<dyn Fn(Cmd) + Send + Sync>;

/// The four icon files, compiled in. Written to the runtime directory at start so the icon is the
/// same installed or not (see `daemon::write_icons`); the package also installs them for the
/// application menu and the window.
pub const ICONS: [(&str, &str); 4] = [
    (
        "sudostamp-desktop-ready",
        include_str!("../data/icons/sudostamp-desktop-ready.svg"),
    ),
    (
        "sudostamp-desktop-away",
        include_str!("../data/icons/sudostamp-desktop-away.svg"),
    ),
    (
        "sudostamp-desktop-paused",
        include_str!("../data/icons/sudostamp-desktop-paused.svg"),
    ),
    (
        "sudostamp-desktop-attention",
        include_str!("../data/icons/sudostamp-desktop-attention.svg"),
    ),
];

pub struct SudoTray {
    pub verdict: Verdict,
    pub paused: bool,
    pub icon_dir: String,
    pub send: CmdSink,
}

impl SudoTray {
    fn item(&self, label: &str, enabled: bool, cmd: Cmd) -> MenuItem<Self> {
        StandardItem {
            label: label.into(),
            enabled,
            activate: Box::new({
                let send = Arc::clone(&self.send);
                move |_: &mut Self| send(cmd)
            }),
            ..Default::default()
        }
        .into()
    }

    fn line(text: String) -> MenuItem<Self> {
        StandardItem {
            label: text,
            enabled: false,
            ..Default::default()
        }
        .into()
    }
}

impl Tray for SudoTray {
    fn id(&self) -> String {
        "sudostamp-desktop".into()
    }

    fn title(&self) -> String {
        "SudoStamp".into()
    }

    fn status(&self) -> Status {
        if self.verdict.state == State::NeedsAttention {
            Status::NeedsAttention
        } else {
            Status::Active
        }
    }

    fn icon_name(&self) -> String {
        self.verdict.state.icon().into()
    }

    fn attention_icon_name(&self) -> String {
        State::NeedsAttention.icon().into()
    }

    fn icon_theme_path(&self) -> String {
        self.icon_dir.clone()
    }

    fn tool_tip(&self) -> ToolTip {
        ToolTip {
            icon_name: self.verdict.state.icon().into(),
            icon_pixmap: Vec::new(),
            title: format!("SudoStamp: {}", self.verdict.state.label()),
            description: escape_markup(&self.verdict.detail),
        }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        (self.send)(Cmd::OpenWindow);
    }

    fn menu_about_to_show(&mut self) {
        (self.send)(Cmd::MenuOpened);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        vec![
            Self::line(format!("SudoStamp: {}", self.verdict.state.label())),
            Self::line(clean(&self.verdict.detail, 90)),
            MenuItem::Separator,
            self.item("Pause until resumed", !self.paused, Cmd::Pause(None)),
            self.item("Pause for 1 hour", !self.paused, Cmd::Pause(Some(3600))),
            self.item("Resume", self.paused, Cmd::Resume),
            MenuItem::Separator,
            self.item("Open SudoStamp", true, Cmd::OpenWindow),
            self.item("Quit", true, Cmd::Quit),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn tray(state: State, paused: bool) -> (SudoTray, Arc<Mutex<Vec<Cmd>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = Arc::clone(&seen);
        let t = SudoTray {
            verdict: Verdict {
                state,
                detail: "detail".into(),
            },
            paused,
            icon_dir: "/tmp/icons".into(),
            send: Arc::new(move |c| s.lock().unwrap().push(c)),
        };
        (t, seen)
    }

    fn labels(t: &SudoTray) -> Vec<(String, bool)> {
        t.menu()
            .into_iter()
            .filter_map(|m| match m {
                MenuItem::Standard(s) => Some((s.label, s.enabled)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn the_menu_has_what_the_design_lists() {
        let (t, _) = tray(State::Ready, false);
        let l = labels(&t);
        let names: Vec<&str> = l.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "SudoStamp: Ready",
                "detail",
                "Pause until resumed",
                "Pause for 1 hour",
                "Resume",
                "Open SudoStamp",
                "Quit"
            ]
        );
        assert!(!l[0].1 && !l[1].1, "the status lines are not buttons");
        assert!(l[2].1 && l[3].1 && !l[4].1, "Resume only when paused");
        let (p, _) = tray(State::Paused, true);
        let l = labels(&p);
        assert!(!l[2].1 && !l[3].1 && l[4].1);
    }

    #[test]
    fn every_state_has_its_own_icon_and_the_attention_one_is_flagged() {
        let (a, _) = tray(State::Ready, false);
        let (b, _) = tray(State::NeedsAttention, false);
        assert_ne!(a.icon_name(), b.icon_name());
        assert_eq!(a.status(), Status::Active);
        assert_eq!(b.status(), Status::NeedsAttention);
        for s in [
            State::Ready,
            State::Away,
            State::Paused,
            State::NeedsAttention,
        ] {
            assert!(
                ICONS
                    .iter()
                    .any(|(n, svg)| *n == s.icon() && svg.contains("<path")),
                "{s:?}"
            );
        }
    }

    #[test]
    fn clicks_send_commands() {
        let (mut t, seen) = tray(State::Ready, false);
        t.activate(0, 0);
        t.menu_about_to_show();
        for m in t.menu() {
            if let MenuItem::Standard(s) = m {
                (s.activate)(&mut t);
            }
        }
        let got = seen.lock().unwrap().clone();
        assert_eq!(
            got,
            [
                Cmd::OpenWindow,
                Cmd::MenuOpened,
                Cmd::Pause(None),
                Cmd::Pause(Some(3600)),
                Cmd::Resume,
                Cmd::OpenWindow,
                Cmd::Quit
            ]
        );
    }

    #[test]
    fn the_tooltip_is_not_a_markup_hole() {
        let (mut t, _) = tray(State::Away, false);
        t.verdict.detail = "<b>x</b>".into();
        assert_eq!(t.tool_tip().description, "&lt;b&gt;x&lt;/b&gt;");
        assert_eq!(t.tool_tip().title, "SudoStamp: Phone away");
    }
}
