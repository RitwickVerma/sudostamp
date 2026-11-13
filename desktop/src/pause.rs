//! The pause flag (docs/DESKTOP.md, "Pause flag"): `$XDG_RUNTIME_DIR/sudostamp/paused`.
//!
//! Empty file = paused until resumed; a decimal unix time = paused until then. The probe reads it
//! as the user and treats anything unreadable, malformed or past as "not paused". The only effect
//! of the flag is that sudo goes straight to the password: it can never make anything authenticate,
//! so anyone running as the user may set it (and so may this app, with no privilege).

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pause {
    Off,
    Until(u64),
    Indefinitely,
}

impl Pause {
    pub fn active(self) -> bool {
        self != Pause::Off
    }
}

/// What the flag's content means at time `now` (unix seconds).
pub fn parse(content: &str, now: u64) -> Pause {
    let c = content.trim();
    if c.is_empty() {
        return Pause::Indefinitely;
    }
    match c.parse::<u64>() {
        Ok(t) if c.bytes().all(|b| b.is_ascii_digit()) && t > now => Pause::Until(t),
        _ => Pause::Off,
    }
}

/// What to write for a pause of `secs` from `now`; `None` = until resumed.
pub fn content(secs: Option<u64>, now: u64) -> String {
    secs.map_or_else(String::new, |s| format!("{}\n", now.saturating_add(s)))
}

/// A few bytes at most: the flag is tiny and a hostile huge file must not be slurped.
pub fn read(path: &Path, now: u64) -> Pause {
    let Ok(f) = fs::File::open(path) else {
        return Pause::Off;
    };
    let mut s = String::new();
    match f.take(64).read_to_string(&mut s) {
        Ok(_) => parse(&s, now),
        Err(_) => Pause::Off,
    }
}

/// Write the flag, creating its directory 0700. Replaced atomically so the probe never reads half.
pub fn write(path: &Path, secs: Option<u64>, now: u64) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no directory"))?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let tmp = path.with_extension("tmp");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(content(secs, now).as_bytes())?;
    drop(f);
    fs::rename(tmp, path)
}

pub fn clear(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{iterations, seed, Rng};
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sudostamp-pause-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn meaning() {
        assert_eq!(parse("", 100), Pause::Indefinitely);
        assert_eq!(parse("\n", 100), Pause::Indefinitely);
        assert_eq!(parse("200", 100), Pause::Until(200));
        assert_eq!(parse("200\n", 100), Pause::Until(200));
        assert_eq!(parse("100", 100), Pause::Off); // until now = over
        assert_eq!(parse("99", 100), Pause::Off);
    }

    #[test]
    fn malformed_is_not_paused() {
        for bad in [
            "soon",
            "-5",
            "+200",
            "2e9",
            "200 300",
            "0x10",
            "99999999999999999999999",
            "١٢٣",
        ] {
            assert_eq!(parse(bad, 100), Pause::Off, "{bad:?}");
        }
    }

    #[test]
    fn content_matches_the_spec() {
        assert_eq!(content(None, 1000), "");
        assert_eq!(content(Some(3600), 1000), "4600\n");
        assert_eq!(parse(&content(Some(3600), 1000), 1000), Pause::Until(4600));
        assert_eq!(parse(&content(None, 1000), 1000), Pause::Indefinitely);
    }

    #[test]
    fn random_text_never_panics_and_never_pauses_by_accident() {
        let mut rng = Rng::new(seed());
        for _ in 0..iterations() {
            let n = rng.below(20);
            let s = String::from_utf8_lossy(&rng.bytes(n)).into_owned();
            let p = parse(&s, 1_000_000);
            if let Pause::Until(t) = p {
                assert!(t > 1_000_000);
            }
            if p == Pause::Indefinitely {
                assert!(s.trim().is_empty());
            }
        }
    }

    #[test]
    fn write_read_clear() {
        let dir = scratch("rw");
        let flag = dir.join("sudostamp").join("paused");
        assert_eq!(read(&flag, 10), Pause::Off);
        write(&flag, None, 10).unwrap();
        assert_eq!(read(&flag, 10), Pause::Indefinitely);
        assert_eq!(fs::read(&flag).unwrap(), b"");
        write(&flag, Some(3600), 10).unwrap();
        assert_eq!(read(&flag, 10), Pause::Until(3610));
        assert_eq!(read(&flag, 3610), Pause::Off);
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(flag.parent().unwrap()), 0o700);
        assert_eq!(mode(&flag), 0o600);
        assert!(!flag.with_extension("tmp").exists());
        clear(&flag).unwrap();
        clear(&flag).unwrap(); // already gone is fine
        assert_eq!(read(&flag, 10), Pause::Off);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_huge_flag_is_not_slurped() {
        let dir = scratch("big");
        fs::create_dir_all(&dir).unwrap();
        let flag = dir.join("paused");
        fs::write(&flag, "9".repeat(1 << 20)).unwrap();
        assert_eq!(read(&flag, 10), Pause::Off);
        fs::remove_dir_all(&dir).unwrap();
    }
}
