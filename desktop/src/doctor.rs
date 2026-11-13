//! `sudostamp doctor --json` (docs/DESKTOP.md): the checklist the Health tab renders and the
//! tray's "Needs attention" comes from. The installer prints it, but the text is still cleaned:
//! this program renders what it is given, it never executes it (see `plan_fix` for what a Fix
//! button may run).

use crate::text::clean;
use serde::Deserialize;
use std::net::SocketAddr;

const MAX_CHECKS: usize = 64;
const MAX_TEXT: usize = 400;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    pub id: String,
    pub level: Level,
    pub text: String,
    pub fix: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub checks: Vec<Check>,
    pub exit: i64,
}

#[derive(Deserialize)]
struct RawCheck {
    id: String,
    status: String,
    text: String,
    #[serde(default)]
    fix: String,
}

#[derive(Deserialize)]
struct Raw {
    v: u64,
    checks: Vec<RawCheck>,
    #[serde(default)]
    exit: i64,
}

pub fn parse(json: &str) -> Result<Report, String> {
    let raw: Raw =
        serde_json::from_str(json).map_err(|e| format!("not doctor --json output: {e}"))?;
    if raw.v != 1 {
        return Err(format!("doctor --json version {} is not supported", raw.v));
    }
    let checks = raw
        .checks
        .into_iter()
        .take(MAX_CHECKS)
        .map(|c| Check {
            id: clean(&c.id, 64),
            // A status this version does not know is shown as a warning, never as fine.
            level: match c.status.as_str() {
                "ok" => Level::Ok,
                "fail" => Level::Fail,
                _ => Level::Warn,
            },
            text: clean(&c.text, MAX_TEXT),
            fix: clean(&c.fix, MAX_TEXT),
        })
        .collect();
    Ok(Report {
        checks,
        exit: raw.exit,
    })
}

impl Report {
    /// A failing check other than `phone`. The phone check fails whenever the phone is away, which
    /// is not an error (the tray's own probe tells away from wrong-key), so it does not count.
    pub fn needs_attention(&self) -> bool {
        self.checks
            .iter()
            .any(|c| c.level == Level::Fail && c.id != "phone")
    }

    pub fn first_problem(&self) -> Option<&Check> {
        self.checks
            .iter()
            .find(|c| c.level == Level::Fail && c.id != "phone")
    }
}

/// What a Fix button does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fix {
    /// `pkexec <installer> <args>`: only `apply` or `stage`, with at most a concrete `--phone`.
    Installer(Vec<String>),
    /// Pairing again is the repair: open the Pair tab.
    Pair,
    /// Anything else (`chown`, `sudoedit`, a package manager): shown to copy, never run.
    Show(String),
}

/// The installer's fix strings read `sudo sudostamp apply --phone 1.2.3.4:7777   (explanation)`.
/// Only the installer's own non-interactive subcommands are run, and only with a literal phone
/// address: placeholders like `<phone-ip>` and `setup` (which asks questions) go to the Pair tab,
/// and everything else is displayed, not executed. The privileged program stays the one reviewed
/// installer.
pub fn plan_fix(fix: &str) -> Fix {
    let fix = fix.split("   (").next().unwrap_or("").trim();
    let Some(cmd) = fix.strip_prefix("sudo ") else {
        return Fix::Pair;
    };
    let words: Vec<&str> = cmd.split_whitespace().collect();
    let prog_ok = words
        .first()
        .is_some_and(|p| *p == "sudostamp" || p.ends_with("/install.sh") || *p == "install.sh");
    if !prog_ok {
        return Fix::Show(fix.to_string());
    }
    match words.as_slice() {
        [_, "setup", ..] => Fix::Pair,
        [_, sub @ ("apply" | "stage")] => Fix::Installer(vec![(*sub).to_string()]),
        [_, sub @ ("apply" | "stage"), "--phone", addr] => match addr.parse::<SocketAddr>() {
            Ok(a) if a.port() != 0 => {
                Fix::Installer(vec![(*sub).to_string(), "--phone".into(), a.to_string()])
            }
            _ => Fix::Pair,
        },
        _ => Fix::Show(fix.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"v":1,"checks":[
      {"id":"platform","status":"ok","text":"Linux (arch)","fix":""},
      {"id":"pam-block","status":"fail","text":"PAM block: not applied","fix":"sudo sudostamp setup   (or, if paired already: sudo sudostamp apply --phone <phone-ip>:7777)"},
      {"id":"phone","status":"fail","text":"phone: nothing answers","fix":"sudo sudostamp doctor"},
      {"id":"local-reader","status":"warn","text":"needs root","fix":""},
      {"id":"user","status":"surprise","text":"new status","extra":1}
    ],"exit":1,"more":true}"#;

    #[test]
    fn parses_the_documented_shape() {
        let r = parse(SAMPLE).unwrap();
        assert_eq!(r.exit, 1);
        assert_eq!(r.checks.len(), 5);
        assert_eq!(r.checks[0].level, Level::Ok);
        assert_eq!(r.checks[1].level, Level::Fail);
        assert_eq!(r.checks[3].level, Level::Warn);
        assert_eq!(r.checks[4].level, Level::Warn); // unknown status: never "ok"
        assert_eq!(r.checks[4].fix, "");
    }

    #[test]
    fn attention_ignores_the_phone_check_alone() {
        let r = parse(SAMPLE).unwrap();
        assert!(r.needs_attention());
        assert_eq!(r.first_problem().unwrap().id, "pam-block");
        let only_phone = parse(
            r#"{"v":1,"checks":[{"id":"phone","status":"fail","text":"x","fix":""}],"exit":1}"#,
        )
        .unwrap();
        assert!(!only_phone.needs_attention());
        let warns = parse(
            r#"{"v":1,"checks":[{"id":"user","status":"warn","text":"x","fix":""}],"exit":0}"#,
        )
        .unwrap();
        assert!(!warns.needs_attention());
    }

    #[test]
    fn refuses_what_is_not_the_contract() {
        for bad in [
            "",
            "{}",
            "[]",
            "not json",
            r#"{"v":2,"checks":[]}"#,
            r#"{"v":1}"#,
            r#"{"v":1,"checks":[{"id":"x"}]}"#,
            r#"{"v":"1","checks":[]}"#,
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn text_is_cleaned_and_bounded() {
        let long = "x".repeat(5000);
        let j = format!(
            r#"{{"v":1,"checks":[{{"id":"a\nb","status":"ok","text":"t\u001b[2J{long}","fix":""}}]}}"#
        );
        let r = parse(&j).unwrap();
        assert_eq!(r.checks[0].id, "a?b");
        assert!(r.checks[0].text.starts_with("t?[2J"));
        assert_eq!(r.checks[0].text.chars().count(), MAX_TEXT);
        let many = format!(
            r#"{{"v":1,"checks":[{}]}}"#,
            vec![r#"{"id":"a","status":"ok","text":"t"}"#; 500].join(",")
        );
        assert_eq!(parse(&many).unwrap().checks.len(), MAX_CHECKS);
    }

    #[test]
    fn fixes() {
        use Fix::*;
        let apply = |a: &str| Installer(vec!["apply".into(), "--phone".into(), a.into()]);
        assert_eq!(
            plan_fix("sudo sudostamp apply --phone 192.168.1.20:7777"),
            apply("192.168.1.20:7777")
        );
        assert_eq!(
            plan_fix("sudo sudostamp apply --phone [fd00::1]:7777   (rebuilds it)"),
            apply("[fd00::1]:7777")
        );
        assert_eq!(
            plan_fix("sudo tools/install.sh stage"),
            Installer(vec!["stage".into()])
        );
        assert_eq!(
            plan_fix("sudo sudostamp stage"),
            Installer(vec!["stage".into()])
        );
        // Placeholders and interactive setup go to pairing.
        assert_eq!(
            plan_fix("sudo sudostamp apply --phone <phone-ip>:7777"),
            Pair
        );
        assert_eq!(
            plan_fix("sudo sudostamp setup   (migrates an older SudoStamp)"),
            Pair
        );
        assert_eq!(plan_fix("sudo sudostamp setup"), Pair);
        assert_eq!(plan_fix(""), Pair);
        assert_eq!(plan_fix("pair again"), Pair);
        assert_eq!(plan_fix("sudo sudostamp apply --phone 1.2.3.4:0"), Pair);
        // Other commands are shown, never run.
        assert_eq!(
            plan_fix("sudo rm -f /tmp/x"),
            Show("sudo rm -f /tmp/x".into())
        );
        assert_eq!(
            plan_fix("sudo chown 0:0 /a && sudo chmod 0755 /a"),
            Show("sudo chown 0:0 /a && sudo chmod 0755 /a".into())
        );
        assert_eq!(
            plan_fix("sudo sudostamp apply --phone 1.2.3.4:7777 --force"),
            Show("sudo sudostamp apply --phone 1.2.3.4:7777 --force".into())
        );
        assert_eq!(
            plan_fix("sudo sudostamp uninstall"),
            Show("sudo sudostamp uninstall".into())
        );
        assert_eq!(
            plan_fix("sudo sudostamp apply; rm -rf ~"),
            Show("sudo sudostamp apply; rm -rf ~".into())
        );
        assert_eq!(
            plan_fix("sudo sudostamp apply --phone 1.2.3.4:7777; reboot"),
            Show("sudo sudostamp apply --phone 1.2.3.4:7777; reboot".into())
        );
    }
}
