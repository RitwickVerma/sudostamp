//! Desktop notifications over `org.freedesktop.Notifications`, called directly through zbus
//! (no notify-rust: one fewer dependency tree). Asking -> Approved / Not approved / Phone not
//! reachable replaces the same notification, one per sudo process.

use crate::engine::{Notice, NoticeKind};
use crate::event::Reason;
use crate::text::escape_markup;
use std::collections::HashMap;
use std::sync::mpsc::Receiver;
use zbus::blocking::Connection;
use zbus::zvariant::Value;

const DEST: &str = "org.freedesktop.Notifications";
const PATH: &str = "/org/freedesktop/Notifications";
/// sudo waits this long for the phone: the asking bubble lives exactly as long.
const ASK_MS: i32 = 60_000;
const VERDICT_MS: i32 = 6_000;
const MAX_TRACKED: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub struct Text {
    pub summary: String,
    pub body: String,
    pub expire_ms: i32,
}

/// What to say. The command is somebody's text: shown, never interpreted, so markup in it is
/// escaped (bodies accept a subset of HTML, including links).
pub fn texts(n: &Notice) -> Text {
    let cmd = escape_markup(&n.command);
    let (summary, body, expire_ms) = match n.kind {
        NoticeKind::Asking => (
            "Approve on your phone".to_string(),
            format!("<b>{cmd}</b> is waiting for your phone (60 s)"),
            ASK_MS,
        ),
        NoticeKind::Approved => (
            "Approved".into(),
            format!("<b>{cmd}</b> was approved on the phone"),
            VERDICT_MS,
        ),
        NoticeKind::NotApproved => (
            "Not approved on the phone".into(),
            format!("<b>{cmd}</b>: sudo is asking for your password"),
            VERDICT_MS,
        ),
        NoticeKind::Skipped(Reason::Paused) => (
            "SudoStamp is paused".into(),
            format!("<b>{cmd}</b>: sudo is asking for your password"),
            VERDICT_MS,
        ),
        NoticeKind::Skipped(Reason::Away | Reason::WrongKey) => (
            "Phone not reachable".into(),
            format!("<b>{cmd}</b>: sudo is asking for your password"),
            VERDICT_MS,
        ),
        NoticeKind::Close => (String::new(), String::new(), 0),
    };
    Text {
        summary,
        body,
        expire_ms,
    }
}

pub struct Notifier {
    conn: Option<Connection>,
    /// sudo pid -> the notification's id, so the next word on that sudo replaces it.
    ids: HashMap<u32, u32>,
}

impl Notifier {
    pub fn new() -> Self {
        Notifier {
            conn: None,
            ids: HashMap::new(),
        }
    }

    fn conn(&mut self) -> zbus::Result<&Connection> {
        if self.conn.is_none() {
            self.conn = Some(Connection::session()?);
        }
        self.conn
            .as_ref()
            .ok_or_else(|| zbus::Error::Failure("no session bus".into()))
    }

    pub fn show(&mut self, n: &Notice) -> zbus::Result<()> {
        if self.ids.len() >= MAX_TRACKED {
            self.ids.clear();
        }
        let previous = self.ids.remove(&n.key);
        if n.kind == NoticeKind::Close {
            if let Some(id) = previous {
                self.conn()?.call_method(
                    Some(DEST),
                    PATH,
                    Some(DEST),
                    "CloseNotification",
                    &(id,),
                )?;
            }
            return Ok(());
        }
        let t = texts(n);
        let mut hints: HashMap<&str, Value<'_>> = HashMap::new();
        hints.insert("urgency", Value::U8(1));
        hints.insert("desktop-entry", Value::from("sudostamp-desktop"));
        // Verdicts need not pile up in the notification history; the app's own list keeps them.
        hints.insert("transient", Value::Bool(n.kind != NoticeKind::Asking));
        let reply = self.conn()?.call_method(
            Some(DEST),
            PATH,
            Some(DEST),
            "Notify",
            &(
                "SudoStamp",
                previous.unwrap_or(0),
                "sudostamp-desktop",
                t.summary.as_str(),
                t.body.as_str(),
                Vec::<&str>::new(),
                hints,
                t.expire_ms,
            ),
        )?;
        let id: u32 = reply.body().deserialize()?;
        // The asking bubble is replaced by its verdict; the verdict is final.
        if n.kind == NoticeKind::Asking {
            self.ids.insert(n.key, id);
        }
        Ok(())
    }
}

impl Default for Notifier {
    fn default() -> Self {
        Self::new()
    }
}

/// The notification thread: a hung notification server must never stall the tray or the socket.
pub fn run(rx: &Receiver<Notice>) {
    let mut notifier = Notifier::new();
    while let Ok(n) = rx.recv() {
        if let Err(e) = notifier.show(&n) {
            eprintln!("sudostamp-desktop: notification failed: {e}");
            notifier.conn = None; // reconnect next time (the bus may have restarted)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(kind: NoticeKind, cmd: &str) -> Notice {
        Notice {
            key: 1,
            kind,
            command: cmd.into(),
        }
    }

    #[test]
    fn asking_names_the_command_and_the_sixty_seconds() {
        let t = texts(&n(NoticeKind::Asking, "sudo pacman -Syu"));
        assert_eq!(
            t.body,
            "<b>sudo pacman -Syu</b> is waiting for your phone (60 s)"
        );
        assert_eq!(t.expire_ms, 60_000);
    }

    #[test]
    fn the_outcomes_say_what_to_do_next() {
        assert_eq!(
            texts(&n(NoticeKind::Approved, "sudo ls")).summary,
            "Approved"
        );
        let no = texts(&n(NoticeKind::NotApproved, "sudo ls"));
        assert_eq!(no.summary, "Not approved on the phone");
        assert!(no.body.contains("password"));
        for r in [Reason::Away, Reason::WrongKey] {
            assert_eq!(
                texts(&n(NoticeKind::Skipped(r), "sudo ls")).summary,
                "Phone not reachable"
            );
        }
        assert_eq!(
            texts(&n(NoticeKind::Skipped(Reason::Paused), "sudo ls")).summary,
            "SudoStamp is paused"
        );
    }

    #[test]
    fn a_hostile_command_cannot_inject_markup() {
        let t = texts(&n(
            NoticeKind::Asking,
            r#"sudo <a href="http://evil">click</a> & <img src=x>"#,
        ));
        assert!(!t.body.contains("<a "), "{}", t.body);
        assert!(!t.body.contains("<img"), "{}", t.body);
        assert!(t.body.contains("&lt;a href=&quot;http://evil&quot;&gt;"));
        assert_eq!(t.body.matches("<b>").count(), 1);
    }
}
