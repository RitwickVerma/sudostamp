//! `install.sh setup --json` (docs/DESKTOP.md): a state machine over the installer's JSON lines.
//!
//! Steps with a status, a question the person must answer (the 6-digit code the phone shows, or a
//! yes/no), and a final result with the key's attestation. The installer is the authority and is
//! run through pkexec; this only renders what it says and writes back the answers.

use crate::text::clean;
use serde_json::Value;
use std::net::SocketAddr;

const MAX_LINE: usize = 8 * 1024;
const MAX_STEPS: usize = 64;
const MAX_TEXT: usize = 400;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepStatus {
    Running,
    Ok,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub name: String,
    pub status: StepStatus,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Prompt {
    Code(String),
    Confirm(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Done {
    pub ok: bool,
    pub attestation: String,
    pub phone: String,
    pub text: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Setup {
    pub steps: Vec<Step>,
    pub prompt: Option<Prompt>,
    pub done: Option<Done>,
}

impl Setup {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one stdout line. Anything that is not a version-1 object of a known shape is ignored:
    /// the installer promises JSON only, but a polkit helper or a wrapper may print around it.
    pub fn feed(&mut self, line: &str) {
        if self.done.is_some() || line.len() > MAX_LINE {
            return;
        }
        let Ok(Value::Object(o)) = serde_json::from_str::<Value>(line) else {
            return;
        };
        if o.get("v").and_then(Value::as_u64) != Some(1) {
            return;
        }
        let s = |k: &str| clean(o.get(k).and_then(Value::as_str).unwrap_or(""), MAX_TEXT);
        if let Some(done) = o.get("done").and_then(Value::as_bool) {
            self.prompt = None;
            self.done = Some(Done {
                ok: done,
                attestation: s("attestation"),
                phone: s("phone"),
                text: s("text"),
            });
        } else if let Some(ask) = o.get("ask").and_then(Value::as_str) {
            self.prompt = match ask {
                "code" => Some(Prompt::Code(s("text"))),
                "confirm" => Some(Prompt::Confirm(s("text"))),
                _ => return,
            };
        } else if let Some(name) = o.get("step").and_then(Value::as_str) {
            let status = match o.get("status").and_then(Value::as_str) {
                Some("start") => StepStatus::Running,
                Some("ok") => StepStatus::Ok,
                Some("fail") => StepStatus::Failed,
                _ => return,
            };
            let name = clean(name, 64);
            let step = Step {
                name: name.clone(),
                status,
                text: s("text"),
            };
            if let Some(known) = self.steps.iter_mut().find(|x| x.name == name) {
                *known = step;
            } else if self.steps.len() < MAX_STEPS {
                self.steps.push(step);
            }
        }
    }

    /// The text to write to the installer's stdin for a code the person typed, if it can be one:
    /// exactly six digits, and only while the installer is asking for a code.
    pub fn answer_code(&mut self, typed: &str) -> Option<String> {
        let code = typed.trim();
        if !matches!(self.prompt, Some(Prompt::Code(_)))
            || code.len() != 6
            || !code.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        self.prompt = None;
        Some(format!("{code}\n"))
    }

    pub fn answer_confirm(&mut self, yes: bool) -> Option<String> {
        if !matches!(self.prompt, Some(Prompt::Confirm(_))) {
            return None;
        }
        self.prompt = None;
        Some(if yes { "yes\n" } else { "no\n" }.to_string())
    }

    /// The process ended. Without a `done` line that is a failure, whatever its exit status said:
    /// only the installer's own final line (or a clean exit after one) means success.
    pub fn finished(&mut self, exit: Option<i32>) {
        if self.done.is_some() {
            return;
        }
        self.prompt = None;
        let text = match exit {
            // pkexec: 126 = not authorized or the prompt was dismissed, 127 = could not authenticate.
            Some(126) => "The administrator prompt was dismissed or refused.".to_string(),
            Some(127) => "polkit could not authenticate (is a polkit agent running?).".to_string(),
            Some(c) => format!("The installer stopped (exit {c}) before it finished."),
            None => "The installer was stopped before it finished.".to_string(),
        };
        self.done = Some(Done {
            ok: false,
            attestation: String::new(),
            phone: String::new(),
            text,
        });
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Phone {
    pub addr: SocketAddr,
    pub name: String,
}

/// `pair.py discover` prints `address:port<TAB>name` per phone. The name is network text.
pub fn parse_discover(out: &str) -> Vec<Phone> {
    let mut phones: Vec<Phone> = Vec::new();
    for line in out.lines().take(32) {
        let (addr, name) = line.split_once('\t').unwrap_or((line, ""));
        let Ok(addr) = addr.trim().parse::<SocketAddr>() else {
            continue;
        };
        if addr.port() == 0 || phones.iter().any(|p| p.addr == addr) {
            continue;
        }
        let name = clean(name.trim(), 64);
        phones.push(Phone {
            addr,
            name: if name.is_empty() {
                "a phone".into()
            } else {
                name
            },
        });
    }
    phones
}

/// A phone address a person typed, as the canonical text to pass on. Never anything else: this is
/// what reaches a privileged command line.
pub fn manual_address(typed: &str) -> Option<SocketAddr> {
    typed
        .trim()
        .parse::<SocketAddr>()
        .ok()
        .filter(|a| a.port() != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(lines: &[&str]) -> Setup {
        let mut s = Setup::new();
        for l in lines {
            s.feed(l);
        }
        s
    }

    #[test]
    fn a_whole_run() {
        let mut s = run(&[
            r#"{"v":1,"step":"stage","status":"start","text":"Installing pam_rssh"}"#,
            r#"{"v":1,"step":"stage","status":"ok","text":"pam_rssh ready"}"#,
            r#"{"v":1,"step":"pair","status":"start","text":"Pairing"}"#,
            r#"{"v":1,"ask":"code","text":"Type the 6-digit code the phone shows (check it names edith)"}"#,
        ]);
        assert_eq!(s.steps.len(), 2);
        assert_eq!(
            s.steps[0],
            Step {
                name: "stage".into(),
                status: StepStatus::Ok,
                text: "pam_rssh ready".into()
            }
        );
        assert_eq!(s.steps[1].status, StepStatus::Running);
        assert!(matches!(s.prompt, Some(Prompt::Code(ref t)) if t.contains("edith")));
        assert_eq!(s.answer_code(" 123456 "), Some("123456\n".into()));
        assert_eq!(s.prompt, None);
        s.feed(r#"{"v":1,"ask":"confirm","text":"Not hardware-attested. Continue?"}"#);
        assert_eq!(s.answer_confirm(true), Some("yes\n".into()));
        s.feed(r#"{"v":1,"step":"pair","status":"ok","text":"Paired"}"#);
        s.feed(r#"{"v":1,"done":true,"attestation":"hardware-backed (StrongBox)","phone":"192.168.1.20:7777","text":"Done"}"#);
        let d = s.done.clone().unwrap();
        assert!(d.ok);
        assert_eq!(
            (d.attestation.as_str(), d.phone.as_str()),
            ("hardware-backed (StrongBox)", "192.168.1.20:7777")
        );
        assert_eq!(s.steps[1].status, StepStatus::Ok);
    }

    #[test]
    fn code_must_be_six_digits_and_asked_for() {
        let mut s = run(&[r#"{"v":1,"ask":"code","text":"c"}"#]);
        for bad in [
            "",
            "12345",
            "1234567",
            "12345a",
            "١٢٣٤٥٦",
            "12 456",
            "-12345",
            "+12345",
        ] {
            assert_eq!(s.answer_code(bad), None, "{bad:?}");
            assert!(s.prompt.is_some(), "a refused code keeps the question");
        }
        assert_eq!(s.answer_confirm(true), None, "wrong kind of answer");
        assert_eq!(s.answer_code("000123"), Some("000123\n".into()));
        assert_eq!(s.answer_code("000123"), None, "nothing is being asked");
        assert_eq!(Setup::new().answer_code("123456"), None);
    }

    #[test]
    fn confirm_no() {
        let mut s = run(&[r#"{"v":1,"ask":"confirm","text":"?"}"#]);
        assert_eq!(s.answer_code("123456"), None);
        assert_eq!(s.answer_confirm(false), Some("no\n".into()));
    }

    #[test]
    fn a_failed_step_and_a_failed_done() {
        let s = run(&[
            r#"{"v":1,"step":"pair","status":"fail","text":"the phone refused"}"#,
            r#"{"v":1,"done":false,"text":"Nothing was changed"}"#,
        ]);
        assert_eq!(s.steps[0].status, StepStatus::Failed);
        assert!(!s.done.unwrap().ok);
    }

    #[test]
    fn junk_and_unknown_lines_are_ignored() {
        let s = run(&[
            "",
            "Authenticating as: root",
            "{not json",
            "[1]",
            r#"{"v":2,"step":"x","status":"ok","text":""}"#,
            r#"{"step":"x","status":"ok","text":""}"#,
            r#"{"v":1,"step":"x","status":"later","text":""}"#,
            r#"{"v":1,"ask":"password","text":"?"}"#,
            r#"{"v":1,"nothing":true}"#,
            &format!(
                r#"{{"v":1,"step":"big","status":"ok","text":"{}"}}"#,
                "x".repeat(MAX_LINE)
            ),
        ]);
        assert_eq!(s, Setup::new());
    }

    #[test]
    fn nothing_after_done_and_text_is_cleaned() {
        let mut s = run(&[r#"{"v":1,"done":true,"text":"ok\u001b[2J"}"#]);
        assert_eq!(s.done.as_ref().unwrap().text, "ok?[2J");
        s.feed(r#"{"v":1,"step":"late","status":"ok","text":""}"#);
        s.feed(r#"{"v":1,"ask":"code","text":""}"#);
        s.feed(r#"{"v":1,"done":false,"text":"changed my mind"}"#);
        assert!(s.steps.is_empty() && s.prompt.is_none() && s.done.as_ref().unwrap().ok);
    }

    #[test]
    fn steps_are_bounded_and_repeat_updates_in_place() {
        let mut s = Setup::new();
        for i in 0..200 {
            s.feed(&format!(
                r#"{{"v":1,"step":"s{i}","status":"ok","text":""}}"#
            ));
        }
        assert_eq!(s.steps.len(), MAX_STEPS);
        s.feed(r#"{"v":1,"step":"s0","status":"fail","text":"again"}"#);
        assert_eq!(s.steps[0].status, StepStatus::Failed);
        assert_eq!(s.steps.len(), MAX_STEPS);
    }

    #[test]
    fn ending_without_done_is_a_failure_with_a_reason() {
        for (exit, needle) in [
            (Some(126), "dismissed"),
            (Some(127), "polkit"),
            (Some(1), "exit 1"),
            (None, "stopped"),
        ] {
            let mut s = run(&[r#"{"v":1,"ask":"code","text":"c"}"#]);
            s.finished(exit);
            let d = s.done.unwrap();
            assert!(!d.ok && d.text.contains(needle), "{exit:?}: {}", d.text);
            assert_eq!(s.prompt, None);
        }
        let mut ok = run(&[r#"{"v":1,"done":true,"text":"fine"}"#]);
        ok.finished(Some(1));
        assert!(ok.done.unwrap().ok, "an earlier done stands");
        let mut zero = Setup::new();
        zero.finished(Some(0));
        assert!(
            !zero.done.unwrap().ok,
            "exit 0 without done is still not success"
        );
    }

    #[test]
    fn discover_output() {
        let out = "192.168.1.20:7777\tPixel 9\n[fd00::5]:7777\tTab\u{202e}let\n192.168.1.20:7777\tdup\nnot-an-address\tx\n10.0.0.1:0\tzero\n10.0.0.2:7777\n";
        let p = parse_discover(out);
        assert_eq!(p.len(), 3);
        assert_eq!(
            (p[0].addr.to_string().as_str(), p[0].name.as_str()),
            ("192.168.1.20:7777", "Pixel 9")
        );
        assert_eq!(p[1].name, "Tab?let");
        assert_eq!(p[2].name, "a phone");
        assert!(parse_discover("").is_empty());
        assert_eq!(parse_discover(&"1.2.3.4:7777\tx\n".repeat(100)).len(), 1);
    }

    #[test]
    fn manual_addresses_are_canonical_or_refused() {
        assert_eq!(
            manual_address(" 192.168.1.20:7777 ").unwrap().to_string(),
            "192.168.1.20:7777"
        );
        assert_eq!(
            manual_address("[fd00::1]:7777").unwrap().to_string(),
            "[fd00::1]:7777"
        );
        for bad in [
            "",
            "phone.local:7777",
            "1.2.3.4",
            "1.2.3.4:0",
            "1.2.3.4:7777 --evil",
            "$(reboot):1",
            "1.2.3.4:7777;ls",
            "-h",
        ] {
            assert_eq!(manual_address(bad), None, "{bad:?}");
        }
    }
}
