//! `/etc/authorized_keys/<user>.keys`: the key blobs the phone must offer for sudo to use it.
//! The file is root-owned and world-readable; this only reads it, to compare what the phone lists.

use std::path::{Path, PathBuf};

pub const KEY_DIR: &str = "/etc/authorized_keys";

/// A user name that is safe to put in a path: the file name is `<user>.keys`.
pub fn valid_user(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 64
        && !u.starts_with('.')
        && u.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

pub fn key_file(dir: &Path, user: &str) -> Option<PathBuf> {
    valid_user(user).then(|| dir.join(format!("{user}.keys")))
}

/// Standard base64 with padding, nothing lenient: this is a key file, not a mail.
fn base64(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.is_empty() || !b.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for (i, chunk) in b.chunks(4).enumerate() {
        let last = i == b.len() / 4 - 1;
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &chunk[..4 - pad] {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => return None,
            };
            n = (n << 6) | u32::from(v);
        }
        n <<= 6 * pad as u32;
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..4 - pad]);
    }
    Some(out)
}

/// The key blobs in an authorized_keys text. A line counts only when its blob starts with the key
/// type it names; options, comments and anything unparseable are skipped, never guessed at.
pub fn parse(text: &str) -> Vec<Vec<u8>> {
    let mut keys = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut f = line.split_whitespace();
        let (Some(kind), Some(b64)) = (f.next(), f.next()) else {
            continue;
        };
        let Some(blob) = base64(b64) else { continue };
        let named = blob
            .get(..4)
            .and_then(|l| usize::try_from(u32::from_be_bytes([l[0], l[1], l[2], l[3]])).ok())
            .and_then(|n| blob.get(4..4usize.checked_add(n)?));
        if named == Some(kind.as_bytes()) && !keys.contains(&blob) {
            keys.push(blob);
        }
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Rng, iterations, seed};

    fn encode(data: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for c in data.chunks(3) {
            let n = (u32::from(c[0]) << 16)
                | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                | u32::from(*c.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= c.len() {
                    s.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    s.push('=');
                }
            }
        }
        s
    }

    fn blob(kind: &str, rest: &[u8]) -> Vec<u8> {
        let mut b = (kind.len() as u32).to_be_bytes().to_vec();
        b.extend(kind.as_bytes());
        b.extend(rest);
        b
    }

    #[test]
    fn base64_rfc4648_vectors() {
        for (plain, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), enc);
            if !enc.is_empty() {
                assert_eq!(base64(enc), Some(plain.as_bytes().to_vec()));
            }
        }
    }

    #[test]
    fn base64_refuses_what_is_not_canonical() {
        for bad in [
            "", "Zg", "Zg=", "Zm9v=", "=Zm9", "Zg==Zm9v", "Zm 9", "Zm9v\n", "Z===", "Zm9*",
        ] {
            assert_eq!(base64(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn base64_roundtrips_random_data() {
        let mut rng = Rng::new(seed());
        for _ in 0..iterations() / 10 {
            let n = rng.below(120);
            let d = rng.bytes(n);
            if d.is_empty() {
                continue;
            }
            assert_eq!(base64(&encode(&d)), Some(d));
        }
    }

    #[test]
    fn parses_a_key_file() {
        let k1 = blob("ecdsa-sha2-nistp256", b"\0\0\0\x08nistp256\0\0\0\x01\x04");
        let k2 = blob("ssh-ed25519", &[9; 36]);
        let text = format!(
            "# SudoStamp key for ritwick\n\necdsa-sha2-nistp256 {} sudostamp-phone\n  ssh-ed25519 {}  \n",
            encode(&k1),
            encode(&k2)
        );
        assert_eq!(parse(&text), vec![k1, k2]);
    }

    #[test]
    fn skips_lines_it_cannot_vouch_for() {
        let k = blob("ecdsa-sha2-nistp256", &[1, 2, 3]);
        let good = encode(&k);
        let text = format!(
            "ecdsa-sha2-nistp256\n\
             ssh-ed25519 {good}\n\
             ecdsa-sha2-nistp256 not*base64\n\
             ecdsa-sha2-nistp256 {}\n\
             from=\"1.2.3.4\" ecdsa-sha2-nistp256 {good}\n\
             ecdsa-sha2-nistp256 {good} one\n\
             ecdsa-sha2-nistp256 {good} two\n",
            encode(b"\xff\xff\xff\xffshort")
        );
        // Only the last two are real lines, and they carry the same blob: listed once.
        assert_eq!(parse(&text), vec![k]);
    }

    #[test]
    fn hostile_text_never_panics() {
        let mut rng = Rng::new(seed());
        for _ in 0..iterations() / 4 {
            let n = rng.below(300);
            let junk = String::from_utf8_lossy(&rng.bytes(n)).into_owned();
            let _ = parse(&junk);
        }
    }

    #[test]
    fn user_names_stay_inside_the_directory() {
        assert_eq!(
            key_file(Path::new("/k"), "ritwick"),
            Some(PathBuf::from("/k/ritwick.keys"))
        );
        for bad in [
            "",
            "..",
            ".x",
            "a/b",
            "../x",
            "a b",
            "x\0y",
            &"u".repeat(65),
        ] {
            assert_eq!(key_file(Path::new("/k"), bad), None, "{bad:?}");
        }
        assert!(valid_user("first.last_1-x"));
    }
}
