//! The datagram the probe and its after-hook send (docs/DESKTOP.md, "Event socket").
//!
//! UNTRUSTED: the socket sits in a directory of the user, so any process of the user can write to
//! it. Every field is type- and length-checked, text is cleaned, unknown fields are ignored, and
//! the result is only ever displayed. Nothing here can make anything authenticate.

use crate::text::clean;
use serde_json::{Map, Value};

pub const MAX_DATAGRAM: usize = 2048;
pub const MAX_COMMAND: usize = 512;
const MAX_TTY: usize = 64;
const MAX_PHONE: usize = 128;
/// The largest pid_max Linux allows on 64-bit (2^22).
const MAX_PID: u64 = 4_194_304;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Away,
    Paused,
    WrongKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Asking,
    Skipped(Reason),
    NotApproved,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub kind: Kind,
    pub sudo_pid: u32,
    pub tty: String,
    pub command: String,
    pub phone: String,
    pub ts: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Reject {
    Size,
    Utf8,
    Json,
    NotObject,
    Version,
    Event,
    Pid,
    Reason,
    Field(&'static str),
}

/// A string field that may be absent (empty) but, when present, must be a string within `max`
/// characters. Over-long is refused rather than cut: the sender already cuts, so a longer one did
/// not come from it.
fn text(obj: &Map<String, Value>, name: &'static str, max: usize) -> Result<String, Reject> {
    match obj.get(name) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) if s.chars().count() <= max => Ok(clean(s, max)),
        Some(_) => Err(Reject::Field(name)),
    }
}

pub fn parse(buf: &[u8]) -> Result<Event, Reject> {
    if buf.is_empty() || buf.len() > MAX_DATAGRAM {
        return Err(Reject::Size);
    }
    let s = std::str::from_utf8(buf).map_err(|_| Reject::Utf8)?;
    let v: Value = serde_json::from_str(s).map_err(|_| Reject::Json)?;
    let obj = v.as_object().ok_or(Reject::NotObject)?;
    if obj.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(Reject::Version);
    }
    let kind = match obj.get("event").and_then(Value::as_str) {
        Some("asking") => Kind::Asking,
        Some("not-approved") => Kind::NotApproved,
        Some("skipped") => Kind::Skipped(match obj.get("reason").and_then(Value::as_str) {
            Some("away") => Reason::Away,
            Some("paused") => Reason::Paused,
            Some("wrong-key") => Reason::WrongKey,
            _ => return Err(Reject::Reason),
        }),
        _ => return Err(Reject::Event),
    };
    let sudo_pid = obj
        .get("sudo_pid")
        .and_then(Value::as_u64)
        .filter(|p| (1..=MAX_PID).contains(p))
        .and_then(|p| u32::try_from(p).ok())
        .ok_or(Reject::Pid)?;
    let ts = match obj.get("ts") {
        None | Some(Value::Null) => 0,
        Some(t) => t.as_u64().ok_or(Reject::Field("ts"))?,
    };
    Ok(Event {
        kind,
        sudo_pid,
        tty: text(obj, "tty", MAX_TTY)?,
        command: text(obj, "command", MAX_COMMAND)?,
        phone: text(obj, "phone", MAX_PHONE)?,
        ts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Rng, iterations, seed};
    use serde_json::json;

    fn valid() -> Value {
        json!({"v":1,"event":"asking","sudo_pid":4242,"tty":"/dev/pts/3",
               "command":"sudo pacman -Syu","phone":"192.168.1.20:7777","ts":1_780_000_000})
    }

    fn bytes(v: &Value) -> Vec<u8> {
        serde_json::to_vec(v).unwrap()
    }

    #[test]
    fn asking_parses() {
        let e = parse(&bytes(&valid())).unwrap();
        assert_eq!(e.kind, Kind::Asking);
        assert_eq!(e.sudo_pid, 4242);
        assert_eq!(e.command, "sudo pacman -Syu");
        assert_eq!(e.tty, "/dev/pts/3");
        assert_eq!(e.phone, "192.168.1.20:7777");
        assert_eq!(e.ts, 1_780_000_000);
    }

    #[test]
    fn skipped_needs_a_known_reason() {
        for (r, want) in [
            ("away", Reason::Away),
            ("paused", Reason::Paused),
            ("wrong-key", Reason::WrongKey),
        ] {
            let mut v = valid();
            v["event"] = json!("skipped");
            v["reason"] = json!(r);
            assert_eq!(parse(&bytes(&v)).unwrap().kind, Kind::Skipped(want));
        }
        let mut v = valid();
        v["event"] = json!("skipped");
        assert_eq!(parse(&bytes(&v)), Err(Reject::Reason));
        v["reason"] = json!("because");
        assert_eq!(parse(&bytes(&v)), Err(Reject::Reason));
        v["reason"] = json!(7);
        assert_eq!(parse(&bytes(&v)), Err(Reject::Reason));
    }

    #[test]
    fn not_approved_parses_and_ignores_a_stray_reason() {
        let mut v = valid();
        v["event"] = json!("not-approved");
        v["reason"] = json!("anything");
        assert_eq!(parse(&bytes(&v)).unwrap().kind, Kind::NotApproved);
    }

    #[test]
    fn unknown_fields_are_ignored_and_optional_ones_may_be_absent() {
        let v = json!({"v":1,"event":"asking","sudo_pid":7,"future":{"x":[1,2,3]}});
        let e = parse(&bytes(&v)).unwrap();
        assert_eq!((e.command.as_str(), e.tty.as_str(), e.ts), ("", "", 0));
    }

    #[test]
    fn wrong_versions_events_and_pids_are_refused() {
        for (field, val, want) in [
            ("v", json!(2), Reject::Version),
            ("v", json!("1"), Reject::Version),
            ("v", json!(1.0), Reject::Version),
            ("event", json!("approved"), Reject::Event),
            ("event", json!(1), Reject::Event),
            ("sudo_pid", json!(0), Reject::Pid),
            ("sudo_pid", json!(-5), Reject::Pid),
            ("sudo_pid", json!(4_194_305), Reject::Pid),
            ("sudo_pid", json!(1.5), Reject::Pid),
            ("sudo_pid", json!("12"), Reject::Pid),
            ("command", json!(12), Reject::Field("command")),
            ("tty", json!([]), Reject::Field("tty")),
            ("phone", json!({}), Reject::Field("phone")),
            ("ts", json!("now"), Reject::Field("ts")),
            ("ts", json!(-1), Reject::Field("ts")),
        ] {
            let mut v = valid();
            v[field] = val;
            assert_eq!(parse(&bytes(&v)), Err(want), "{field}");
        }
    }

    #[test]
    fn missing_required_fields_are_refused() {
        for f in ["v", "event", "sudo_pid"] {
            let mut v = valid();
            v.as_object_mut().unwrap().remove(f);
            assert!(parse(&bytes(&v)).is_err(), "{f}");
        }
    }

    #[test]
    fn length_limits() {
        let mut v = valid();
        v["command"] = json!("x".repeat(MAX_COMMAND));
        assert_eq!(parse(&bytes(&v)).unwrap().command.len(), MAX_COMMAND);
        v["command"] = json!("x".repeat(MAX_COMMAND + 1));
        assert_eq!(parse(&bytes(&v)), Err(Reject::Field("command")));
        v["command"] = json!("é".repeat(MAX_COMMAND));
        assert!(parse(&bytes(&v)).is_ok()); // characters, not bytes
        let mut raw = bytes(&valid());
        raw.resize(MAX_DATAGRAM, b' ');
        assert!(parse(&raw).is_ok());
        raw.push(b' ');
        assert_eq!(parse(&raw), Err(Reject::Size));
        assert_eq!(parse(b""), Err(Reject::Size));
    }

    #[test]
    fn text_is_cleaned() {
        let mut v = valid();
        v["command"] = json!("sudo x\n\u{1b}[2J\u{202e}y");
        assert_eq!(parse(&bytes(&v)).unwrap().command, "sudo x??[2J?y");
    }

    #[test]
    fn garbage_is_refused() {
        assert_eq!(parse(b"\xff\xfe"), Err(Reject::Utf8));
        assert_eq!(parse(b"not json"), Err(Reject::Json));
        assert_eq!(parse(b"[1,2]"), Err(Reject::NotObject));
        assert_eq!(parse(b"\"asking\""), Err(Reject::NotObject));
        assert_eq!(
            parse(b"{\"v\":1,\"event\":\"asking\"} trailing"),
            Err(Reject::Json)
        );
        assert_eq!(parse(&b"[".repeat(1000)), Err(Reject::Json)); // recursion limit, no stack blow
    }

    /// What a valid datagram must look like after parsing, whatever the hostile mutation did.
    fn check_invariants(e: &Event) {
        assert!((1..=MAX_PID).contains(&u64::from(e.sudo_pid)));
        for (s, max) in [
            (&e.command, MAX_COMMAND),
            (&e.tty, MAX_TTY),
            (&e.phone, MAX_PHONE),
        ] {
            assert!(s.chars().count() <= max);
            assert!(
                !s.chars().any(char::is_control),
                "control char survived: {s:?}"
            );
        }
    }

    #[test]
    fn never_panics_on_random_bytes() {
        let seed = seed();
        let mut rng = Rng::new(seed);
        for i in 0..iterations() {
            let n = rng.below(600);
            let buf = rng.bytes(n);
            if let Ok(e) = parse(&buf) {
                check_invariants(&e);
            }
            let _ = i;
        }
    }

    #[test]
    fn mutated_valid_datagrams_never_break_the_invariants() {
        let seed = seed();
        let mut rng = Rng::new(seed);
        let base = bytes(&valid());
        let (mut ok, mut bad) = (0u32, 0u32);
        for i in 0..iterations() {
            let mut buf = base.clone();
            for _ in 0..=rng.below(4) {
                match rng.below(5) {
                    0 if !buf.is_empty() => {
                        let at = rng.below(buf.len());
                        buf[at] = rng.bytes(1)[0];
                    }
                    1 if !buf.is_empty() => {
                        let at = rng.below(buf.len());
                        buf.remove(at);
                    }
                    2 => {
                        let at = rng.below(buf.len() + 1);
                        buf.insert(at, rng.bytes(1)[0]);
                    }
                    3 => buf.truncate(rng.below(buf.len() + 1)),
                    _ => buf.extend(rng.junk(39)),
                }
            }
            match parse(&buf) {
                Ok(e) => {
                    check_invariants(&e);
                    ok += 1;
                }
                Err(_) => bad += 1,
            }
            let _ = i;
        }
        // The property must be able to fail: both outcomes have to occur, or the mutation is idle.
        assert!(ok > 0 && bad > 0, "ok={ok} bad={bad} seed={seed}");
    }

    /// Against a reference written without the parser's code: build a datagram from chosen fields
    /// with plain string formatting, and what comes back must be what was put in.
    #[test]
    fn roundtrip_against_a_hand_built_datagram() {
        let seed = seed();
        let mut rng = Rng::new(seed);
        let alphabet: Vec<char> = "abcXYZ019 /-_.:=\"\\\u{e9}\u{4e2d}'".chars().collect();
        for _ in 0..iterations() {
            let len = rng.below(MAX_COMMAND + 1);
            let cmd: String = (0..len)
                .map(|_| alphabet[rng.below(alphabet.len())])
                .collect();
            let pid = 1 + rng.below(4_194_304);
            let (name, kind) = match rng.below(3) {
                0 => ("asking", Kind::Asking),
                1 => ("not-approved", Kind::NotApproved),
                _ => ("skipped", Kind::Skipped(Reason::Away)),
            };
            let esc: String = cmd
                .chars()
                .flat_map(|c| match c {
                    '"' => vec!['\\', '"'],
                    '\\' => vec!['\\', '\\'],
                    c => vec![c],
                })
                .collect();
            let raw = format!(
                "{{\"v\":1,\"event\":\"{name}\",\"reason\":\"away\",\"sudo_pid\":{pid},\"command\":\"{esc}\",\"x\":null}}"
            );
            let e = parse(raw.as_bytes()).unwrap();
            assert_eq!(
                (e.kind, e.sudo_pid as usize, e.command),
                (kind, pid, cmd),
                "{raw}"
            );
        }
    }
}
