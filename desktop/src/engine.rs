//! What the desktop does with an event, as pure bookkeeping: events and clock ticks in, actions
//! out (show this notice, write this history line, check the phone again). The daemon performs the
//! actions; nothing here touches the desktop, so the correlation rules are tested directly.

use crate::event::{Event, Kind, Reason};
use crate::history::{Entry, Outcome};
use crate::track::{Poll, Tracker};
use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;

/// sudo's own wait for the phone is 60 s (75 s hard limit in pam_rssh's patch). After this with no
/// word, the process is gone or the events were lost: stop tracking.
const GIVE_UP: u64 = 90;
const MAX_PENDING: usize = 16;
/// A `skipped` pid is remembered this long so the after-hook's `not-approved` for it is ignored.
const SKIP_MEMORY: u64 = 120;
const MAX_SKIPPED: usize = 64;
/// Any process of the user can write datagrams: past this many per window, drop the rest.
const RATE_WINDOW: u64 = 10;
const RATE_MAX: usize = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoticeKind {
    Asking,
    Approved,
    NotApproved,
    Skipped(Reason),
    /// Take the asking notification down without a verdict (sudo ended, or we gave up).
    Close,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    /// The sudo pid: one notification per sudo, replaced as it progresses.
    pub key: u32,
    pub kind: NoticeKind,
    /// The command as sent (cleaned); "sudo" when the sender could not read it.
    pub command: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Notify(Notice),
    Record(Entry),
    /// Look at the phone again (after every sudo event, debounced by the daemon).
    Recheck,
}

struct Pending {
    tracker: Tracker,
    command: String,
    since: u64,
}

pub struct Engine {
    proc_root: PathBuf,
    pending: BTreeMap<u32, Pending>,
    skipped: BTreeMap<u32, u64>,
    accepted: VecDeque<u64>,
}

fn shown(command: &str) -> String {
    if command.is_empty() {
        "sudo".into()
    } else {
        command.to_string()
    }
}

fn skip_outcome(r: Reason) -> Outcome {
    match r {
        Reason::Away => Outcome::SkippedAway,
        Reason::Paused => Outcome::SkippedPaused,
        Reason::WrongKey => Outcome::SkippedWrongKey,
    }
}

impl Engine {
    pub fn new(proc_root: PathBuf) -> Self {
        Engine {
            proc_root,
            pending: BTreeMap::new(),
            skipped: BTreeMap::new(),
            accepted: VecDeque::new(),
        }
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    fn rate_ok(&mut self, now: u64) -> bool {
        while self
            .accepted
            .front()
            .is_some_and(|t| now.saturating_sub(*t) >= RATE_WINDOW)
        {
            self.accepted.pop_front();
        }
        if self.accepted.len() >= RATE_MAX {
            return false;
        }
        self.accepted.push_back(now);
        true
    }

    fn record(now: u64, outcome: Outcome, command: &str) -> Action {
        Action::Record(Entry {
            ts: now,
            outcome,
            command: command.to_string(),
        })
    }

    pub fn on_event(&mut self, e: &Event, now: u64) -> Vec<Action> {
        if !self.rate_ok(now) {
            return Vec::new();
        }
        let pid = e.sudo_pid;
        let mut out = Vec::new();
        match e.kind {
            Kind::Asking => {
                if self.pending.contains_key(&pid) {
                    return vec![Action::Recheck];
                }
                if self.pending.len() >= MAX_PENDING {
                    let oldest = self
                        .pending
                        .iter()
                        .min_by_key(|(_, p)| p.since)
                        .map(|(k, _)| *k);
                    if let Some(k) = oldest
                        && let Some(p) = self.pending.remove(&k)
                    {
                        out.push(Action::Notify(Notice {
                            key: k,
                            kind: NoticeKind::Close,
                            command: p.command,
                        }));
                    }
                }
                let command = shown(&e.command);
                self.pending.insert(
                    pid,
                    Pending {
                        tracker: Tracker::new(&self.proc_root, pid),
                        command: command.clone(),
                        since: now,
                    },
                );
                out.push(Action::Notify(Notice {
                    key: pid,
                    kind: NoticeKind::Asking,
                    command,
                }));
            }
            Kind::Skipped(r) => {
                let command = self
                    .pending
                    .remove(&pid)
                    .map_or_else(|| shown(&e.command), |p| p.command);
                self.skipped.retain(|_, until| *until > now);
                if self.skipped.len() >= MAX_SKIPPED {
                    self.skipped.clear();
                }
                self.skipped.insert(pid, now + SKIP_MEMORY);
                out.push(Action::Notify(Notice {
                    key: pid,
                    kind: NoticeKind::Skipped(r),
                    command: command.clone(),
                }));
                out.push(Self::record(now, skip_outcome(r), &command));
            }
            Kind::NotApproved => {
                // The after-hook also runs when the probe skipped the phone: that sudo already
                // got its "phone not reachable" and is not a second story.
                if self.skipped.get(&pid).is_some_and(|until| *until > now) {
                    return vec![Action::Recheck];
                }
                let command = self
                    .pending
                    .remove(&pid)
                    .map_or_else(|| shown(&e.command), |p| p.command);
                out.push(Action::Notify(Notice {
                    key: pid,
                    kind: NoticeKind::NotApproved,
                    command: command.clone(),
                }));
                out.push(Self::record(now, Outcome::NotApproved, &command));
            }
        }
        out.push(Action::Recheck);
        out
    }

    /// Poll the sudo processes being waited on. Call about every 100 ms while `pending() > 0`.
    pub fn tick(&mut self, now: u64) -> Vec<Action> {
        let mut out = Vec::new();
        let mut done = Vec::new();
        for (pid, p) in &mut self.pending {
            match p.tracker.poll(&self.proc_root) {
                Poll::Approved => {
                    out.push(Action::Notify(Notice {
                        key: *pid,
                        kind: NoticeKind::Approved,
                        command: p.command.clone(),
                    }));
                    out.push(Self::record(now, Outcome::Approved, &p.command));
                    out.push(Action::Recheck);
                    done.push(*pid);
                }
                Poll::Gone => {
                    out.push(Action::Notify(Notice {
                        key: *pid,
                        kind: NoticeKind::Close,
                        command: p.command.clone(),
                    }));
                    done.push(*pid);
                }
                Poll::Waiting if now.saturating_sub(p.since) > GIVE_UP => {
                    out.push(Action::Notify(Notice {
                        key: *pid,
                        kind: NoticeKind::Close,
                        command: p.command.clone(),
                    }));
                    done.push(*pid);
                }
                Poll::Waiting => {}
            }
        }
        for pid in done {
            self.pending.remove(&pid);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::track::fake::Proc;

    fn ev(kind: Kind, pid: u32, command: &str) -> Event {
        Event {
            kind,
            sudo_pid: pid,
            tty: String::new(),
            command: command.into(),
            phone: String::new(),
            ts: 0,
        }
    }

    fn notices(a: &[Action]) -> Vec<NoticeKind> {
        a.iter()
            .filter_map(|a| {
                if let Action::Notify(n) = a {
                    Some(n.kind)
                } else {
                    None
                }
            })
            .collect()
    }

    fn records(a: &[Action]) -> Vec<Outcome> {
        a.iter()
            .filter_map(|a| {
                if let Action::Record(e) = a {
                    Some(e.outcome)
                } else {
                    None
                }
            })
            .collect()
    }

    #[test]
    fn asking_then_approved_when_the_command_starts() {
        let p = Proc::new("eng-ok");
        p.proc(100, &[101]);
        p.cmdline(101, &["sudostamp-probe"]);
        let mut e = Engine::new(p.root().into());
        let a = e.on_event(&ev(Kind::Asking, 100, "sudo pacman -Syu"), 1000);
        assert_eq!(notices(&a), vec![NoticeKind::Asking]);
        assert!(a.contains(&Action::Recheck));
        assert!(records(&a).is_empty(), "asking is not an outcome");
        assert_eq!(e.pending(), 1);
        assert!(e.tick(1001).is_empty());
        p.proc(100, &[101, 150]);
        p.cmdline(150, &["pacman", "-Syu"]);
        let a = e.tick(1002);
        assert_eq!(notices(&a), vec![NoticeKind::Approved]);
        assert_eq!(records(&a), vec![Outcome::Approved]);
        match &a[0] {
            Action::Notify(n) => assert_eq!((n.key, n.command.as_str()), (100, "sudo pacman -Syu")),
            other => panic!("{other:?}"),
        }
        assert_eq!(e.pending(), 0);
        assert!(e.tick(1003).is_empty(), "reported once");
    }

    #[test]
    fn not_approved_uses_the_command_from_asking() {
        let p = Proc::new("eng-no");
        let mut e = Engine::new(p.root().into());
        e.on_event(&ev(Kind::Asking, 100, "sudo ls"), 1000);
        let a = e.on_event(&ev(Kind::NotApproved, 100, ""), 1010);
        assert_eq!(notices(&a), vec![NoticeKind::NotApproved]);
        assert_eq!(records(&a), vec![Outcome::NotApproved]);
        if let Action::Notify(n) = &a[0] {
            assert_eq!(n.command, "sudo ls");
        }
        assert_eq!(e.pending(), 0);
    }

    #[test]
    fn skipped_wins_over_the_after_hooks_not_approved() {
        let p = Proc::new("eng-skip");
        let mut e = Engine::new(p.root().into());
        let a = e.on_event(&ev(Kind::Skipped(Reason::Away), 100, "sudo ls"), 1000);
        assert_eq!(notices(&a), vec![NoticeKind::Skipped(Reason::Away)]);
        assert_eq!(records(&a), vec![Outcome::SkippedAway]);
        let b = e.on_event(&ev(Kind::NotApproved, 100, "sudo ls"), 1000);
        assert_eq!(b, vec![Action::Recheck], "the same pid is not told twice");
        // Another sudo, or the same pid long after, is a new story.
        let c = e.on_event(&ev(Kind::NotApproved, 101, "sudo ls"), 1001);
        assert_eq!(notices(&c), vec![NoticeKind::NotApproved]);
        let d = e.on_event(
            &ev(Kind::NotApproved, 100, "sudo ls"),
            1000 + SKIP_MEMORY + 1,
        );
        assert_eq!(notices(&d), vec![NoticeKind::NotApproved]);
    }

    #[test]
    fn skipped_closes_a_pending_asking_and_keeps_its_command() {
        let p = Proc::new("eng-skip2");
        let mut e = Engine::new(p.root().into());
        e.on_event(&ev(Kind::Asking, 100, "sudo make install"), 1000);
        let a = e.on_event(&ev(Kind::Skipped(Reason::Paused), 100, ""), 1001);
        if let Action::Notify(n) = &a[0] {
            assert_eq!(n.command, "sudo make install");
        }
        assert_eq!(records(&a), vec![Outcome::SkippedPaused]);
        assert_eq!(e.pending(), 0);
    }

    #[test]
    fn an_empty_command_reads_sudo() {
        let p = Proc::new("eng-empty");
        let mut e = Engine::new(p.root().into());
        let a = e.on_event(&ev(Kind::Asking, 7, ""), 1);
        if let Action::Notify(n) = &a[0] {
            assert_eq!(n.command, "sudo");
        }
    }

    #[test]
    fn duplicate_asking_is_one_notification() {
        let p = Proc::new("eng-dup");
        let mut e = Engine::new(p.root().into());
        e.on_event(&ev(Kind::Asking, 5, "sudo a"), 1);
        let a = e.on_event(&ev(Kind::Asking, 5, "sudo b"), 2);
        assert_eq!(a, vec![Action::Recheck]);
        assert_eq!(e.pending(), 1);
    }

    #[test]
    fn sudo_ending_or_silence_closes_the_notification() {
        let p = Proc::new("eng-gone");
        p.proc(100, &[]);
        let mut e = Engine::new(p.root().into());
        e.on_event(&ev(Kind::Asking, 100, "sudo -v"), 1000);
        p.kill(100);
        let a = e.tick(1001);
        assert_eq!(notices(&a), vec![NoticeKind::Close]);
        assert!(records(&a).is_empty());
        // A sudo we cannot see: kept until the give-up time, then closed.
        e.on_event(&ev(Kind::Asking, 555, "sudo x"), 2000);
        assert!(e.tick(2000 + GIVE_UP).is_empty());
        assert_eq!(
            notices(&e.tick(2000 + GIVE_UP + 1)),
            vec![NoticeKind::Close]
        );
        assert_eq!(e.pending(), 0);
    }

    #[test]
    fn pending_is_bounded() {
        let p = Proc::new("eng-cap");
        let mut e = Engine::new(p.root().into());
        for pid in 1..=(MAX_PENDING as u32 + 5) {
            e.on_event(&ev(Kind::Asking, pid, "sudo x"), u64::from(pid));
        }
        assert_eq!(e.pending(), MAX_PENDING);
    }

    #[test]
    fn a_flood_is_dropped() {
        let p = Proc::new("eng-flood");
        let mut e = Engine::new(p.root().into());
        let mut acted = 0;
        for i in 0..1000u32 {
            if !e
                .on_event(&ev(Kind::NotApproved, 1 + (i % 50), "x"), 5000)
                .is_empty()
            {
                acted += 1;
            }
        }
        assert_eq!(acted, RATE_MAX);
        // The window moves on: new events are accepted again.
        assert!(
            !e.on_event(&ev(Kind::NotApproved, 9, "x"), 5000 + RATE_WINDOW)
                .is_empty()
        );
    }
}
