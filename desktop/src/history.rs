//! The last 100 sudo events this desktop saw, in `$XDG_STATE_HOME/sudostamp/history.jsonl`: the
//! computer-side counterpart of the phone's history. One JSON object per line. The file is the
//! user's own and any process of the user may edit it, so reading treats it like input: corrupt or
//! oversize lines are skipped, and only the tail is ever read.

use crate::event::MAX_COMMAND;
use crate::text::clean;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

pub const KEEP: usize = 100;
/// Rewrite the file once it grows past this, so it stays a few tens of KiB for ever.
const COMPACT_ABOVE: u64 = 96 * 1024;
/// How much of the tail one read looks at (100 entries are at most ~70 KiB).
const READ_TAIL: u64 = 128 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Approved,
    NotApproved,
    SkippedAway,
    SkippedPaused,
    SkippedWrongKey,
}

impl Outcome {
    pub fn label(self) -> &'static str {
        match self {
            Outcome::Approved => "Approved on the phone",
            Outcome::NotApproved => "Not approved: password",
            Outcome::SkippedAway => "Phone not reachable: password",
            Outcome::SkippedPaused => "Paused: password",
            Outcome::SkippedWrongKey => "Phone has another key: password",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub ts: u64,
    pub outcome: Outcome,
    pub command: String,
}

impl Entry {
    fn line(&self) -> String {
        let mut s = serde_json::to_string(self).unwrap_or_default();
        s.push('\n');
        s
    }
}

fn parse_line(line: &str) -> Option<Entry> {
    let mut e: Entry = serde_json::from_str(line).ok()?;
    if e.command.chars().count() > MAX_COMMAND {
        return None;
    }
    e.command = clean(&e.command, MAX_COMMAND);
    Some(e)
}

/// The last `KEEP` valid entries, oldest first.
pub fn read(path: &Path) -> Vec<Entry> {
    let Ok(mut f) = fs::File::open(path) else {
        return Vec::new();
    };
    let Ok(len) = f.metadata().map(|m| m.len()) else {
        return Vec::new();
    };
    let start = len.saturating_sub(READ_TAIL);
    let mut buf = Vec::new();
    if f.seek(SeekFrom::Start(start)).is_err() || f.take(READ_TAIL).read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&buf);
    // Starting mid-file, the first line is a fragment.
    let mut lines = text.lines();
    if start > 0 {
        lines.next();
    }
    let mut all: Vec<Entry> = lines.filter_map(parse_line).collect();
    // Appended in time order, but a clock step or a hand edit must not scramble the list.
    all.sort_by_key(|e| e.ts);
    all.drain(..all.len().saturating_sub(KEEP));
    all
}

pub fn append(path: &Path, e: &Entry) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    let mut f = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)?;
    // One write of the whole line: appends of this size do not interleave.
    f.write_all(e.line().as_bytes())?;
    if f.metadata()?.len() > COMPACT_ABOVE {
        compact(path)?;
    }
    Ok(())
}

fn compact(path: &Path) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    for e in read(path) {
        f.write_all(e.line().as_bytes())?;
    }
    drop(f);
    fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Rng, iterations, seed};

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sudostamp-hist-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn entry(n: u64) -> Entry {
        Entry {
            ts: n,
            outcome: Outcome::Approved,
            command: format!("sudo cmd {n}"),
        }
    }

    #[test]
    fn append_and_read_back() {
        let d = scratch("rw");
        let p = d.join("state").join("history.jsonl");
        assert!(read(&p).is_empty());
        for n in 0..3 {
            append(&p, &entry(n)).unwrap();
        }
        assert_eq!(read(&p), vec![entry(0), entry(1), entry(2)]);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn keeps_only_the_last_hundred_and_stays_small() {
        let d = scratch("bound");
        let p = d.join("history.jsonl");
        for n in 0..2000 {
            let mut e = entry(n);
            e.command = format!("sudo {}", "x".repeat(300));
            append(&p, &e).unwrap();
        }
        let got = read(&p);
        assert_eq!(got.len(), KEEP);
        assert_eq!(got.last().unwrap().ts, 1999);
        assert_eq!(got[0].ts, 1900);
        assert!(fs::metadata(&p).unwrap().len() <= COMPACT_ABOVE + 1024);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn corrupt_and_hostile_lines_are_skipped() {
        let d = scratch("bad");
        fs::create_dir_all(&d).unwrap();
        let p = d.join("history.jsonl");
        let long = "y".repeat(MAX_COMMAND + 1);
        let text = format!(
            "{}not json\n\n{{\"ts\":1}}\n{{\"ts\":2,\"outcome\":\"bogus\",\"command\":\"x\"}}\n{{\"ts\":3,\"outcome\":\"approved\",\"command\":\"{long}\"}}\n{{\"ts\":4,\"outcome\":\"not-approved\",\"command\":\"a\\nb\"}}\n\u{0}\u{1}\u{2}\n",
            entry(1).line()
        );
        fs::write(&p, text).unwrap();
        let got = read(&p);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], entry(1));
        assert_eq!(
            (got[1].outcome, got[1].command.as_str()),
            (Outcome::NotApproved, "a?b")
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_huge_file_is_only_read_at_its_tail() {
        let d = scratch("huge");
        fs::create_dir_all(&d).unwrap();
        let p = d.join("history.jsonl");
        let mut text = String::new();
        for n in 0..20_000 {
            text.push_str(&entry(n).line());
        }
        fs::write(&p, &text).unwrap();
        let got = read(&p);
        assert_eq!(got.len(), KEEP);
        assert_eq!(got.last().unwrap().ts, 19_999);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn random_files_never_panic() {
        let d = scratch("rand");
        fs::create_dir_all(&d).unwrap();
        let p = d.join("history.jsonl");
        let mut rng = Rng::new(seed());
        let good = entry(7).line();
        for _ in 0..iterations() / 100 {
            let mut b = good.repeat(3).into_bytes();
            for _ in 0..rng.below(6) {
                let n = b.len();
                let at = rng.below(n);
                b[at] = rng.bytes(1)[0];
            }
            fs::write(&p, &b).unwrap();
            for e in read(&p) {
                assert!(e.command.chars().count() <= MAX_COMMAND);
            }
        }
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn file_and_directory_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("mode");
        let p = d.join("s").join("history.jsonl");
        append(&p, &entry(1)).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&p), 0o600);
        assert_eq!(mode(p.parent().unwrap()), 0o700);
        fs::remove_dir_all(&d).unwrap();
    }
}
