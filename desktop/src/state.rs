//! The tray's four states and how they follow from what the checks found (docs/DESKTOP.md,
//! "Tray status"). Pure: the worker threads gather the inputs, this decides.

use crate::agent;
use crate::doctor::Report;
use crate::pause::Pause;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Ready,
    Away,
    Paused,
    NeedsAttention,
}

impl State {
    /// The icon's name in the theme and the file stem under `icons/`.
    pub fn icon(self) -> &'static str {
        match self {
            State::Ready => "sudostamp-desktop-ready",
            State::Away => "sudostamp-desktop-away",
            State::Paused => "sudostamp-desktop-paused",
            State::NeedsAttention => "sudostamp-desktop-attention",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            State::Ready => "Ready",
            State::Away => "Phone away",
            State::Paused => "Paused",
            State::NeedsAttention => "Needs attention",
        }
    }
}

/// Why the setup cannot be checked at all (before the phone is even asked).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Config {
    Ok,
    Broken(String),
}

#[derive(Clone, Debug)]
pub struct Inputs {
    pub pause: Pause,
    pub config: Config,
    /// `None`: the check has not run yet.
    pub agent: Option<agent::Status>,
    /// `None`: doctor has not run, or is not available (an older installer without `--json`).
    pub doctor: Option<Report>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub state: State,
    pub detail: String,
}

fn v(state: State, detail: &str) -> Verdict {
    Verdict {
        state,
        detail: detail.to_string(),
    }
}

/// Paused wins (sudo goes straight to the password whatever else is true), then anything broken,
/// then the phone itself. WrongKey is broken, not away: the phone answers, so waiting will not help.
pub fn compute(i: &Inputs) -> Verdict {
    if i.pause.active() {
        return v(
            State::Paused,
            "Paused on this computer: sudo asks for the password.",
        );
    }
    if let Config::Broken(why) = &i.config {
        return v(State::NeedsAttention, why);
    }
    if let Some(p) = i.doctor.as_ref().and_then(Report::first_problem) {
        return Verdict {
            state: State::NeedsAttention,
            detail: p.text.clone(),
        };
    }
    match i.agent {
        Some(agent::Status::WrongKey) => v(
            State::NeedsAttention,
            "The phone answers but does not offer this computer's key: pair again.",
        ),
        Some(agent::Status::Ready) => v(State::Ready, "The phone answers: sudo will ask it."),
        Some(agent::Status::Away) => v(
            State::Away,
            "The phone does not answer: sudo will ask for the password.",
        ),
        None => v(State::Away, "Checking the phone…"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::parse;

    fn base() -> Inputs {
        Inputs {
            pause: Pause::Off,
            config: Config::Ok,
            agent: Some(agent::Status::Ready),
            doctor: None,
        }
    }

    fn doctor(fail_id: &str) -> Option<Report> {
        Some(parse(&format!(r#"{{"v":1,"checks":[{{"id":"{fail_id}","status":"fail","text":"broken {fail_id}","fix":""}}],"exit":1}}"#)).unwrap())
    }

    #[test]
    fn the_four_states() {
        assert_eq!(compute(&base()).state, State::Ready);
        let away = Inputs {
            agent: Some(agent::Status::Away),
            ..base()
        };
        assert_eq!(compute(&away).state, State::Away);
        let paused = Inputs {
            pause: Pause::Indefinitely,
            ..base()
        };
        assert_eq!(compute(&paused).state, State::Paused);
        let broken = Inputs {
            doctor: doctor("pam-block"),
            ..base()
        };
        let v = compute(&broken);
        assert_eq!(
            (v.state, v.detail.as_str()),
            (State::NeedsAttention, "broken pam-block")
        );
    }

    #[test]
    fn paused_wins_over_everything() {
        let i = Inputs {
            pause: Pause::Until(5),
            config: Config::Broken("x".into()),
            agent: Some(agent::Status::WrongKey),
            doctor: doctor("pam-block"),
        };
        assert_eq!(compute(&i).state, State::Paused);
    }

    #[test]
    fn a_failing_phone_check_alone_is_just_away() {
        let i = Inputs {
            agent: Some(agent::Status::Away),
            doctor: doctor("phone"),
            ..base()
        };
        assert_eq!(compute(&i).state, State::Away);
    }

    #[test]
    fn wrong_key_and_broken_config_need_attention() {
        let wrong = Inputs {
            agent: Some(agent::Status::WrongKey),
            ..base()
        };
        assert_eq!(compute(&wrong).state, State::NeedsAttention);
        let cfg = Inputs {
            config: Config::Broken("no SudoStamp block".into()),
            agent: None,
            ..base()
        };
        let v = compute(&cfg);
        assert_eq!(
            (v.state, v.detail.as_str()),
            (State::NeedsAttention, "no SudoStamp block")
        );
    }

    #[test]
    fn before_the_first_check_it_does_not_claim_ready() {
        let i = Inputs {
            agent: None,
            ..base()
        };
        let v = compute(&i);
        assert_eq!(v.state, State::Away);
        assert!(v.detail.contains("Checking"));
    }

    #[test]
    fn icons_are_distinct() {
        let all = [
            State::Ready,
            State::Away,
            State::Paused,
            State::NeedsAttention,
        ];
        let names: std::collections::HashSet<_> = all.iter().map(|s| s.icon()).collect();
        assert_eq!(names.len(), 4);
    }
}
