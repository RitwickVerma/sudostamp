//! The pairing QR code (qr-v1): a fresh secret and the link that carries it to the phone. The
//! protocol is written up in the app's `Pairing.kt`; the computer's half is `tools/pair.py`, which
//! gets the secret on stdin (`discover --qr-stdin`, `setup --json --qr`), never on a command line.
//!
//! ```text
//! https://sudostamp.ritwickverma.dev/pair#1.<secret>.<this computer's name>
//! ```
//!
//! Both after the '#', which a browser never sends: if the link opens in a browser instead of the
//! app (no app yet), the secret does not reach the site. Anyone who sees the code holds the secret,
//! so it lives two minutes and is never used twice.

use std::fs;
use std::io::{self, Read};
use std::time::{Duration, Instant};

pub const HOST: &str = "sudostamp.ritwickverma.dev";
pub const LIFETIME: Duration = Duration::from_secs(120);
const SECRET: usize = 16;
const MAX_LABEL: usize = 32;

/// One code's secret. No `Debug`: it must not end up in a log line by accident.
pub struct Ticket {
    secret: [u8; SECRET],
    made: Instant,
    label: String,
}

impl Ticket {
    /// A new secret from the kernel's random source, for the computer named `label`.
    pub fn new(label: &str) -> io::Result<Self> {
        let mut secret = [0u8; SECRET];
        fs::File::open("/dev/urandom")?.read_exact(&mut secret)?;
        Ok(Self::with(secret, label, Instant::now()))
    }

    fn with(secret: [u8; SECRET], label: &str, made: Instant) -> Self {
        Ticket {
            secret,
            made,
            label: clean_label(label),
        }
    }

    /// The secret as `pair.py` reads it.
    pub fn secret_text(&self) -> String {
        b64url(&self.secret)
    }

    /// What the QR code holds.
    pub fn link(&self) -> String {
        format!(
            "https://{HOST}/pair#1.{}.{}",
            b64url(&self.secret),
            b64url(self.label.as_bytes())
        )
    }

    pub fn stale(&self) -> bool {
        self.made.elapsed() >= LIFETIME
    }

    /// How long until a new code replaces this one.
    pub fn left(&self) -> Duration {
        LIFETIME.saturating_sub(self.made.elapsed())
    }
}

/// The name the phone shows ("Pair with edith?"): printable ASCII, at most 32 characters. The
/// phone cleans it again; this keeps the code small.
pub fn clean_label(raw: &str) -> String {
    raw.chars()
        .filter(|c| (' '..='~').contains(c))
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_LABEL)
        .collect()
}

/// This computer's name, as `hostname` prints it; empty if it cannot be read (the phone then
/// says "a computer").
pub fn hostname() -> String {
    ["/proc/sys/kernel/hostname", "/etc/hostname"]
        .iter()
        .find_map(|p| {
            fs::read_to_string(p)
                .ok()
                .map(|s| clean_label(&s))
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_default()
}

/// Unpadded base64url (RFC 4648 section 5).
pub fn b64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..=c.len() {
            out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The secret of the protocol test vectors (QrPairingTest.kt, test_pair.py).
    fn vector() -> [u8; SECRET] {
        std::array::from_fn(|i| 100 + i as u8)
    }

    #[test]
    fn base64url_as_the_phone_and_pair_py_read_it() {
        assert_eq!(b64url(&vector()), "ZGVmZ2hpamtsbW5vcHFycw");
        assert_eq!(b64url(b""), "");
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
        assert_eq!(b64url(&[0xfb, 0xff, 0xbf]), "-_-_");
        assert_eq!(b64url(b"edith"), "ZWRpdGg");
    }

    #[test]
    fn the_link_the_phone_expects() {
        let t = Ticket::with(vector(), "edith", Instant::now());
        assert_eq!(
            t.link(),
            "https://sudostamp.ritwickverma.dev/pair#1.ZGVmZ2hpamtsbW5vcHFycw.ZWRpdGg"
        );
        assert_eq!(t.secret_text(), "ZGVmZ2hpamtsbW5vcHFycw");
        assert_eq!(
            Ticket::with(vector(), "", Instant::now()).link(),
            "https://sudostamp.ritwickverma.dev/pair#1.ZGVmZ2hpamtsbW5vcHFycw."
        );
    }

    #[test]
    fn names_are_bounded_display_text() {
        assert_eq!(clean_label(" edith\n"), "edith");
        assert_eq!(clean_label("a\u{1b}[2Jb\u{202e}c"), "a[2Jbc");
        assert_eq!(clean_label(&"x".repeat(100)).len(), MAX_LABEL);
        assert_eq!(clean_label("élan"), "lan");
    }

    #[test]
    fn every_code_is_new_and_lives_two_minutes() {
        let (a, b) = (Ticket::new("e").unwrap(), Ticket::new("e").unwrap());
        assert_ne!(a.secret_text(), b.secret_text());
        assert_eq!(a.secret_text().len(), 22);
        assert!(!a.stale());
        let old = Ticket::with(vector(), "e", Instant::now() - LIFETIME);
        assert!(old.stale());
        assert_eq!(old.left(), Duration::ZERO);
    }
}
