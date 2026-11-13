//! `sudostamp-desktop`: the tray process (no argument) and the window (`window`).
//! docs/DESKTOP.md; README in desktop/.
#![forbid(unsafe_code)]

use std::process::ExitCode;
use sudostamp_desktop::{daemon, window};

const USAGE: &str = "\
sudostamp-desktop: SudoStamp on the desktop (tray status, sudo notifications, pause)

  sudostamp-desktop           run the tray icon and the notifications (what autostart runs)
  sudostamp-desktop window    open the Health and Pair a phone window
  sudostamp-desktop --version

Per-user and unprivileged. It cannot approve anything: the phone is the only authority.
Repairs and pairing run the installer through pkexec, with polkit's own administrator prompt.
";

fn main() -> ExitCode {
    let env = |k: &str| std::env::var(k).ok();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => daemon::run(&env),
        ["window"] => window::run(&env),
        ["--version" | "-V"] => {
            println!("sudostamp-desktop {}", env!("CARGO_PKG_VERSION"));
            0
        }
        ["--help" | "-h"] => {
            print!("{USAGE}");
            0
        }
        _ => {
            eprint!("{USAGE}");
            2
        }
    };
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
