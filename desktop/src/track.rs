//! Did sudo start its command? World-readable `/proc` answers: once the sudo process has a child
//! that is not one of PAM's own helpers, authentication is over and the command is running
//! (docs/DESKTOP.md, "approved"). The proc root is a parameter so tests build a fake tree.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// The helpers `pam_exec` forks from inside sudo during authentication: the gate, the probe and
/// the after-hook. They are children of sudo too, so counting them would announce "approved"
/// before the phone was asked. Matched on the script's name in the child's command line.
const PAM_HELPERS: [&[u8]; 2] = [b"sudostamp-probe", b"sudostamp-is-local"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Poll {
    Waiting,
    /// A child that is not a PAM helper appeared: the command started.
    Approved,
    /// The sudo process ended without starting anything we could see.
    Gone,
}

#[derive(Debug)]
pub struct Tracker {
    pid: u32,
    /// Children already accounted for: what existed when the question was asked (the probe that
    /// sent the event) and helpers seen since.
    seen: HashSet<u32>,
    /// Whether `/proc/<pid>` was ever readable. Under `hidepid` it is not, and "gone" would then
    /// be a lie: such a sudo is simply untrackable.
    visible: bool,
}

/// The pids in `/proc/<pid>/task/*/children`, or `None` when the process is not there.
fn children(root: &Path, pid: u32) -> Option<Vec<u32>> {
    let tasks = fs::read_dir(root.join(pid.to_string()).join("task")).ok()?;
    let mut out = Vec::new();
    for t in tasks.flatten() {
        if let Ok(s) = fs::read_to_string(t.path().join("children")) {
            out.extend(s.split_whitespace().filter_map(|c| c.parse::<u32>().ok()));
        }
    }
    Some(out)
}

fn is_pam_helper(root: &Path, child: u32) -> bool {
    fs::read(root.join(child.to_string()).join("cmdline"))
        .map(|c| {
            PAM_HELPERS
                .iter()
                .any(|h| c.windows(h.len()).any(|w| w == *h))
        })
        .unwrap_or(true) // already gone or unreadable: too short-lived to be the command
}

impl Tracker {
    pub fn new(root: &Path, pid: u32) -> Self {
        let kids = children(root, pid);
        Tracker {
            pid,
            visible: kids.is_some(),
            seen: kids.unwrap_or_default().into_iter().collect(),
        }
    }

    pub fn poll(&mut self, root: &Path) -> Poll {
        let Some(kids) = children(root, self.pid) else {
            return if self.visible {
                Poll::Gone
            } else {
                Poll::Waiting
            };
        };
        self.visible = true;
        for c in kids {
            if self.seen.insert(c) && !is_pam_helper(root, c) {
                return Poll::Approved;
            }
        }
        Poll::Waiting
    }
}

#[cfg(test)]
pub mod fake {
    //! A throwaway /proc for tests.
    use std::fs;
    use std::path::{Path, PathBuf};

    pub struct Proc(pub PathBuf);

    impl Proc {
        pub fn new(name: &str) -> Self {
            let d =
                std::env::temp_dir().join(format!("sudostamp-proc-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&d);
            fs::create_dir_all(&d).unwrap();
            Proc(d)
        }
        pub fn root(&self) -> &Path {
            &self.0
        }
        /// A process with these children (listed under one thread, as the kernel does).
        pub fn proc(&self, pid: u32, kids: &[u32]) {
            let t = self
                .0
                .join(pid.to_string())
                .join("task")
                .join(pid.to_string());
            fs::create_dir_all(&t).unwrap();
            let list: Vec<String> = kids.iter().map(ToString::to_string).collect();
            fs::write(t.join("children"), list.join(" ") + " ").unwrap();
        }
        pub fn cmdline(&self, pid: u32, args: &[&str]) {
            let d = self.0.join(pid.to_string());
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("cmdline"), args.join("\0") + "\0").unwrap();
        }
        pub fn kill(&self, pid: u32) {
            let _ = fs::remove_dir_all(self.0.join(pid.to_string()));
        }
    }

    impl Drop for Proc {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::Proc;
    use super::*;

    #[test]
    fn the_probe_that_asked_is_not_an_approval() {
        let p = Proc::new("probe");
        p.proc(100, &[101]);
        p.cmdline(
            101,
            &[
                "/bin/bash",
                "/usr/local/sbin/sudostamp-probe",
                "phone=1.2.3.4:7777",
            ],
        );
        let mut t = Tracker::new(p.root(), 100);
        assert_eq!(t.poll(p.root()), Poll::Waiting);
        assert_eq!(t.poll(p.root()), Poll::Waiting);
    }

    #[test]
    fn a_new_non_helper_child_is_the_command() {
        let p = Proc::new("cmd");
        p.proc(100, &[101]);
        p.cmdline(101, &["sudostamp-probe"]);
        let mut t = Tracker::new(p.root(), 100);
        p.proc(100, &[101, 205]);
        p.cmdline(205, &["pacman", "-Syu"]);
        assert_eq!(t.poll(p.root()), Poll::Approved);
    }

    #[test]
    fn the_after_hook_and_gate_are_not_the_command() {
        let p = Proc::new("hook");
        p.proc(100, &[]);
        let mut t = Tracker::new(p.root(), 100);
        p.proc(100, &[300]);
        p.cmdline(
            300,
            &["/bin/sh", "/usr/local/sbin/sudostamp-probe", "after"],
        );
        assert_eq!(t.poll(p.root()), Poll::Waiting);
        p.proc(100, &[300, 301]);
        p.cmdline(301, &["/usr/local/sbin/sudostamp-is-local.sh"]);
        assert_eq!(t.poll(p.root()), Poll::Waiting);
        // A real command after them still counts.
        p.proc(100, &[300, 301, 302]);
        p.cmdline(302, &["id"]);
        assert_eq!(t.poll(p.root()), Poll::Approved);
    }

    #[test]
    fn children_of_any_thread_count() {
        let p = Proc::new("threads");
        p.proc(100, &[]);
        let mut t = Tracker::new(p.root(), 100);
        let other = p.root().join("100/task/555");
        fs::create_dir_all(&other).unwrap();
        fs::write(other.join("children"), "777 ").unwrap();
        p.cmdline(777, &["ls"]);
        assert_eq!(t.poll(p.root()), Poll::Approved);
    }

    #[test]
    fn a_child_that_vanished_before_it_could_be_read_is_ignored() {
        let p = Proc::new("fast");
        p.proc(100, &[]);
        let mut t = Tracker::new(p.root(), 100);
        p.proc(100, &[900]); // no /proc/900 at all
        assert_eq!(t.poll(p.root()), Poll::Waiting);
    }

    #[test]
    fn gone_only_after_it_was_seen() {
        let p = Proc::new("gone");
        p.proc(100, &[]);
        let mut t = Tracker::new(p.root(), 100);
        p.kill(100);
        assert_eq!(t.poll(p.root()), Poll::Gone);
        // Never visible (hidepid, or a made-up pid): not "gone", just unknown.
        let mut blind = Tracker::new(p.root(), 4242);
        assert_eq!(blind.poll(p.root()), Poll::Waiting);
    }

    #[test]
    fn garbage_in_children_files_is_skipped() {
        let p = Proc::new("junk");
        p.proc(100, &[]);
        let t = p.root().join("100/task/100/children");
        fs::write(t, "abc -5 99999999999 \0 \n").unwrap();
        let mut tr = Tracker::new(p.root(), 100);
        assert_eq!(tr.poll(p.root()), Poll::Waiting);
    }
}
