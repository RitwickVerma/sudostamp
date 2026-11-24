//! Where things live. Pure: the environment is passed in, so tests never touch the real one.

use std::path::{Path, PathBuf};

pub const SYSTEM_INSTALLER: &str = "/usr/bin/sudostamp";
pub const SYSTEM_PAIR: &str = "/usr/lib/sudostamp/pair.py";
pub const PAM_SUDO: &str = "/etc/pam.d/sudo";

pub type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

fn absolute(v: Option<String>) -> Option<PathBuf> {
    v.map(PathBuf::from).filter(|p| p.is_absolute())
}

/// `/run/user/<uid>/sudostamp`, the directory of the event socket and the pause flag: exactly where
/// the probe looks (it knows the uid, not this process's environment). An `XDG_RUNTIME_DIR` that
/// says otherwise (su without a login, an inherited environment) would have the tray listen and
/// pause where sudo never looks.
pub fn runtime_dir(uid: u32) -> PathBuf {
    PathBuf::from(format!("/run/user/{uid}/sudostamp"))
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

/// Whether the `SUDOSTAMP_*` overrides (another installer, another pair.py, a pkexec stand-in)
/// are honoured: in this crate's own tests and in a `--features test-hooks` build, never in a
/// package. Each function that reads one takes it as an argument, so a test can show what a
/// release build does.
pub const TEST_HOOKS: bool = cfg!(any(test, feature = "test-hooks"));

/// The installer to run: the packaged `/usr/bin/sudostamp`. Under `TEST_HOOKS` only,
/// `SUDOSTAMP_INSTALLER` (tests, a checkout's `tools/install.sh`) wins over it. In a package an
/// environment variable must not choose what pkexec runs as root: the root-owned check alone
/// would accept any system binary (`/usr/bin/bash apply`), and `exec::privileged` refuses all
/// but the packaged path too.
pub fn installer(env: Env, system_exists: bool) -> Option<PathBuf> {
    installer_hooks(env, system_exists, TEST_HOOKS)
}

fn installer_hooks(env: Env, system_exists: bool, hooks: bool) -> Option<PathBuf> {
    hooks
        .then(|| absolute(env("SUDOSTAMP_INSTALLER")))
        .flatten()
        .or_else(|| system_exists.then(|| PathBuf::from(SYSTEM_INSTALLER)))
}

/// `pair.py` (phone discovery): `SUDOSTAMP_PAIR` (under `TEST_HOOKS` only), else beside the
/// installer (a checkout's, which only `TEST_HOOKS` can name), else the packaged copy. It is handed
/// the QR secret, and `exec::discover` runs it only if root owns it and every directory above.
pub fn pair_script(
    env: Env,
    installer: Option<&Path>,
    exists: &dyn Fn(&Path) -> bool,
) -> Option<PathBuf> {
    pair_script_hooks(env, installer, exists, TEST_HOOKS)
}

fn pair_script_hooks(
    env: Env,
    installer: Option<&Path>,
    exists: &dyn Fn(&Path) -> bool,
    hooks: bool,
) -> Option<PathBuf> {
    if hooks && let Some(p) = absolute(env("SUDOSTAMP_PAIR")) {
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
        // The probe's path for the uid, whatever XDG_RUNTIME_DIR says.
        let e = env(&[("XDG_RUNTIME_DIR", "/elsewhere"), ("HOME", "/home/a")]);
        let r = runtime_dir(1000);
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
    fn outside_tests_only_the_packaged_installer_is_run() {
        // A release build: SUDOSTAMP_INSTALLER would let an environment variable pick what
        // pkexec runs as root (any root-owned binary passes the ownership check).
        let with = env(&[("SUDOSTAMP_INSTALLER", "/usr/bin/bash")]);
        assert_eq!(
            installer_hooks(&with, true, false),
            Some(SYSTEM_INSTALLER.into())
        );
        assert_eq!(installer_hooks(&with, false, false), None);
    }

    #[test]
    fn outside_tests_sudostamp_pair_is_ignored() {
        // A release build: pair.py reads the QR secret, so it is never taken from the
        // environment (~/.config/environment.d is the user's, and so anything of theirs).
        let no = |_: &Path| false;
        let e = env(&[("SUDOSTAMP_PAIR", "/home/u/.local/evil.py")]);
        assert_eq!(pair_script_hooks(&e, None, &no, false), None);
        let only_system = |p: &Path| p == Path::new(SYSTEM_PAIR);
        assert_eq!(
            pair_script_hooks(&e, None, &only_system, false),
            Some(SYSTEM_PAIR.into())
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
