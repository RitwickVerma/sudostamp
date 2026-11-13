//! A tiny ssh-agent client: one REQUEST_IDENTITIES, to see whether the phone would answer sudo.
//!
//! This is exactly the question the host probe asks (docs/DESKTOP.md, "Tray status"), and it costs
//! the phone one accept. It never sends a SIGN_REQUEST, holds no key and cannot approve anything.
//!
//! Pitfall 22: the phone writes its length prefix in small pieces, so frames are read in a loop,
//! never with one `recv(4)`.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// The whole exchange (connect, request, reply) must finish inside this, like the host probe's.
pub const BUDGET: Duration = Duration::from_secs(4);
/// A phone with a few keys answers in a few hundred bytes; this only bounds a hostile peer.
const MAX_FRAME: usize = 64 * 1024;
const MAX_KEYS: u32 = 256;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// The phone answered and lists a pinned key: sudo will ask it.
    Ready,
    /// No (valid) answer within the budget: sudo will use the password. Not an error.
    Away,
    /// It answered, but without this user's pinned key: paired with another computer, or the app
    /// was reinstalled.
    WrongKey,
}

pub fn check(addr: SocketAddr, pinned: &[Vec<u8>], budget: Duration) -> Status {
    match identities(addr, Instant::now() + budget) {
        Ok(listed) => classify(&listed, pinned),
        Err(_) => Status::Away,
    }
}

pub fn classify(listed: &[Vec<u8>], pinned: &[Vec<u8>]) -> Status {
    if listed.iter().any(|k| pinned.contains(k)) {
        Status::Ready
    } else {
        Status::WrongKey
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(io::ErrorKind::TimedOut.into())
    } else {
        Ok(left)
    }
}

/// Every read gets what is left of the one budget, so a peer that dribbles bytes cannot stretch it.
struct Deadline<'a> {
    stream: &'a TcpStream,
    at: Instant,
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(remaining(self.at)?))?;
        // A timed-out read surfaces as WouldBlock on Unix; callers only care that it failed.
        self.stream.read(buf)
    }
}

fn identities(addr: SocketAddr, deadline: Instant) -> io::Result<Vec<Vec<u8>>> {
    let mut stream = TcpStream::connect_timeout(&addr, remaining(deadline)?)?;
    stream.set_write_timeout(Some(remaining(deadline)?))?;
    stream.write_all(&[0, 0, 0, 1, REQUEST_IDENTITIES])?;
    let frame = read_frame(
        &mut Deadline {
            stream: &stream,
            at: deadline,
        },
        MAX_FRAME,
    )?;
    parse_identities(&frame)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "not an identities answer"))
}

fn fill<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<()> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// One length-prefixed ssh-agent frame, however the peer chops it up.
pub fn read_frame<R: Read>(r: &mut R, max: usize) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    fill(r, &mut len)?;
    let n = usize::try_from(u32::from_be_bytes(len)).unwrap_or(usize::MAX);
    if n == 0 || n > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad frame length",
        ));
    }
    let mut body = vec![0u8; n];
    fill(r, &mut body)?;
    Ok(body)
}

fn string<'a>(b: &mut &'a [u8]) -> Option<&'a [u8]> {
    let n = usize::try_from(u32::from_be_bytes(b.get(..4)?.try_into().ok()?)).ok()?;
    let s = b.get(4..4usize.checked_add(n)?)?;
    *b = &b[4 + n..];
    Some(s)
}

/// SSH2_AGENT_IDENTITIES_ANSWER: the key blobs it lists (comments are the phone's text: dropped).
pub fn parse_identities(body: &[u8]) -> Option<Vec<Vec<u8>>> {
    let (&kind, mut rest) = body.split_first()?;
    if kind != IDENTITIES_ANSWER {
        return None;
    }
    let count = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?);
    rest = &rest[4..];
    if count > MAX_KEYS {
        return None;
    }
    let mut keys = Vec::new();
    for _ in 0..count {
        keys.push(string(&mut rest)?.to_vec());
        string(&mut rest)?;
    }
    Some(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Rng, iterations, seed};

    fn s(b: &[u8]) -> Vec<u8> {
        let mut v = (b.len() as u32).to_be_bytes().to_vec();
        v.extend(b);
        v
    }

    fn answer(keys: &[&[u8]]) -> Vec<u8> {
        let mut v = vec![IDENTITIES_ANSWER];
        v.extend((keys.len() as u32).to_be_bytes());
        for k in keys {
            v.extend(s(k));
            v.extend(s(b"comment"));
        }
        v
    }

    /// A reader that hands out one byte per call: pitfall 22 in miniature.
    struct Dribble(Vec<u8>, usize);
    impl Read for Dribble {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.1 >= self.0.len() || buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.0[self.1];
            self.1 += 1;
            Ok(1)
        }
    }

    #[test]
    fn frames_survive_being_chopped_up() {
        let body = answer(&[b"k1", b"k2"]);
        let mut wire = (body.len() as u32).to_be_bytes().to_vec();
        wire.extend(&body);
        assert_eq!(
            read_frame(&mut Dribble(wire.clone(), 0), 1024).unwrap(),
            body
        );
        // Truncated anywhere: an error, never a short frame.
        for cut in 0..wire.len() {
            assert!(
                read_frame(&mut Dribble(wire[..cut].to_vec(), 0), 1024).is_err(),
                "{cut}"
            );
        }
    }

    #[test]
    fn frame_lengths_are_bounded() {
        for len in [0u32, 1025, u32::MAX] {
            let mut wire = len.to_be_bytes().to_vec();
            wire.extend(vec![0; 2000]);
            assert!(read_frame(&mut Dribble(wire, 0), 1024).is_err(), "{len}");
        }
    }

    #[test]
    fn identities_answer_parses() {
        assert_eq!(
            parse_identities(&answer(&[b"a", b"bb"])),
            Some(vec![b"a".to_vec(), b"bb".to_vec()])
        );
        assert_eq!(parse_identities(&answer(&[])), Some(vec![]));
    }

    #[test]
    fn anything_else_is_not_an_answer() {
        assert_eq!(parse_identities(&[]), None);
        assert_eq!(parse_identities(&[5]), None); // SSH_AGENT_FAILURE
        assert_eq!(parse_identities(&[14, 0, 0, 0, 0]), None);
        let mut cut = answer(&[b"abc"]);
        cut.pop();
        assert_eq!(parse_identities(&cut), None);
        let mut lie = vec![IDENTITIES_ANSWER];
        lie.extend(2u32.to_be_bytes());
        lie.extend(s(b"only-one-key"));
        lie.extend(s(b"c"));
        assert_eq!(parse_identities(&lie), None);
        let mut many = vec![IDENTITIES_ANSWER];
        many.extend((MAX_KEYS + 1).to_be_bytes());
        assert_eq!(parse_identities(&many), None);
        let mut huge = vec![IDENTITIES_ANSWER, 0, 0, 0, 1];
        huge.extend(u32::MAX.to_be_bytes());
        assert_eq!(parse_identities(&huge), None);
    }

    #[test]
    fn classification() {
        let pinned = vec![b"mine".to_vec()];
        assert_eq!(
            classify(&[b"other".to_vec(), b"mine".to_vec()], &pinned),
            Status::Ready
        );
        assert_eq!(classify(&[b"other".to_vec()], &pinned), Status::WrongKey);
        assert_eq!(classify(&[], &pinned), Status::WrongKey);
        assert_eq!(classify(&[b"mine".to_vec()], &[]), Status::WrongKey);
    }

    #[test]
    fn hostile_answers_never_panic() {
        let mut rng = Rng::new(seed());
        let base = answer(&[b"k1", b"key-two"]);
        for _ in 0..iterations() {
            let mut b = base.clone();
            for _ in 0..=rng.below(3) {
                if b.is_empty() {
                    break;
                }
                let at = rng.below(b.len());
                match rng.below(3) {
                    0 => b[at] = rng.bytes(1)[0],
                    1 => b.truncate(at),
                    _ => b.extend(rng.junk(7)),
                }
            }
            let _ = parse_identities(&b);
            let n = rng.below(80);
            let _ = parse_identities(&rng.bytes(n));
        }
    }
}
