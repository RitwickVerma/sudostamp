//! Where things live. Pure: the environment is passed in, so tests never touch the real one.

use std::path::{Path, PathBuf};

pub const SYSTEM_INSTALLER: &str = "/usr/bin/sudostamp";
pub const SYSTEM_PAIR: &str = "/usr/lib/sudostamp/pair.py";
pub const PAM_SUDO: &str = "/etc/pam.d/sudo";

pub type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

fn absolute(v: Option<String>) -> Option<PathBuf> {
    v.map(PathBuf::from).filter(|p| p.is_absolute())
}

/// `$XDG_RUNTIME_DIR/sudostamp`, the directory of the event socket and the pause flag. No runtime
/// directory (no login session) means there is nothing to do: refuse rather than guess a /tmp path.
pub fn runtime_dir(env: Env) -> Option<PathBuf> {
    absolute(env("XDG_RUNTIME_DIR")).map(|d| d.join("sudostamp"))
}

pub fn socket(runtime: &Path) -> PathBuf {
    runtime.join("events.sock")
}

pub fn pause_flag(runtime: &Path) -> PathBuf {
    runtime.join("paused")
}

/// `$XDG_STATE_HOME/sudostamp` (default `~/.local/state/sudostamp`).
pub fn state_dir(env: Env) -> Option<PathBuf> {
    absolute(env("XDG_STATE_HOME"))
        .or_else(|| absolute(env("HOME")).map(|h| h.join(".local/state")))
        .map(|d| d.join("sudostamp"))
}

pub fn history_file(state: &Path) -> PathBuf {
    state.join("history.jsonl")
}

pub fn user(env: Env) -> Option<String> {
    ["USER", "LOGNAME"]
        .iter()
        .filter_map(|k| env(k))
        .find(|u| crate::keys::valid_user(u))
}

/// The installer to run. `SUDOSTAMP_INSTALLER` (tests, a checkout's `tools/install.sh`) wins over
/// the packaged `/usr/bin/sudostamp`. A privileged run refuses a path that is not root-owned
/// (`exec::privileged`), so an override cannot be used to escalate.
pub fn installer(env: Env, system_exists: bool) -> Option<PathBuf> {
    absolute(env("SUDOSTAMP_INSTALLER"))
        .or_else(|| system_exists.then(|| PathBuf::from(SYSTEM_INSTALLER)))
}

/// `pair.py` (phone discovery): `SUDOSTAMP_PAIR`, else beside a checkout's installer, else the
/// packaged copy.
pub fn pair_script(
    env: Env,
    installer: Option<&Path>,
    exists: &dyn Fn(&Path) -> bool,
) -> Option<PathBuf> {
    if let Some(p) = absolute(env("SUDOSTAMP_PAIR")) {
        return Some(p);
    }
    let beside = installer
        .and_then(Path::parent)
        .map(|d| d.join("pair.py"))
        .filter(|p| exists(p));
    beside.or_else(|| {
        let p = PathBuf::from(SYSTEM_PAIR);
        exists(&p).then_some(p)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn runtime_and_state() {
        let e = env(&[("XDG_RUNTIME_DIR", "/run/user/1000"), ("HOME", "/home/a")]);
        let r = runtime_dir(&e).unwrap();
        assert_eq!(r, PathBuf::from("/run/user/1000/sudostamp"));
        assert_eq!(
            socket(&r),
            PathBuf::from("/run/user/1000/sudostamp/events.sock")
        );
        assert_eq!(
            pause_flag(&r),
            PathBuf::from("/run/user/1000/sudostamp/paused")
        );
        assert_eq!(
            history_file(&state_dir(&e).unwrap()),
            PathBuf::from("/home/a/.local/state/sudostamp/history.jsonl")
        );
        let e2 = env(&[("XDG_STATE_HOME", "/s"), ("HOME", "/home/a")]);
        assert_eq!(state_dir(&e2), Some(PathBuf::from("/s/sudostamp")));
    }

    #[test]
    fn relative_or_missing_paths_are_refused() {
        assert_eq!(runtime_dir(&env(&[])), None);
        assert_eq!(runtime_dir(&env(&[("XDG_RUNTIME_DIR", "run/x")])), None);
        assert_eq!(
            state_dir(&env(&[("XDG_STATE_HOME", "rel"), ("HOME", "rel")])),
            None
        );
    }

    #[test]
    fn user_must_be_path_safe() {
        assert_eq!(user(&env(&[("USER", "ritwick")])), Some("ritwick".into()));
        assert_eq!(
            user(&env(&[("USER", "../x"), ("LOGNAME", "ok")])),
            Some("ok".into())
        );
        assert_eq!(user(&env(&[("USER", "a/b")])), None);
    }

    #[test]
    fn installer_precedence() {
        let with = env(&[("SUDOSTAMP_INSTALLER", "/tmp/fake")]);
        assert_eq!(installer(&with, true), Some("/tmp/fake".into()));
        assert_eq!(installer(&env(&[]), true), Some(SYSTEM_INSTALLER.into()));
        assert_eq!(installer(&env(&[]), false), None);
        assert_eq!(
            installer(&env(&[("SUDOSTAMP_INSTALLER", "rel/x")]), false),
            None
        );
    }

    #[test]
    fn pair_script_order() {
        let yes = |_: &Path| true;
        let no = |_: &Path| false;
        let e = env(&[("SUDOSTAMP_PAIR", "/x/pair.py")]);
        assert_eq!(pair_script(&e, None, &no), Some("/x/pair.py".into()));
        let none = env(&[]);
        assert_eq!(
            pair_script(&none, Some(Path::new("/repo/tools/install.sh")), &yes),
            Some("/repo/tools/pair.py".into())
        );
        assert_eq!(
            pair_script(&none, Some(Path::new("/usr/bin/sudostamp")), &yes),
            Some("/usr/bin/pair.py".into())
        );
        let only_system = |p: &Path| p == Path::new(SYSTEM_PAIR);
        assert_eq!(
            pair_script(&none, Some(Path::new("/usr/bin/sudostamp")), &only_system),
            Some(SYSTEM_PAIR.into())
        );
        assert_eq!(pair_script(&none, None, &no), None);
    }
}
