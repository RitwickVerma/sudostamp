//! Plain-text hygiene for everything that came from outside this process.
//!
//! Any process of the user can write to the event socket, and the installer's output and a phone's
//! mDNS name are text somebody else chose. None of it is trusted: it is shown as plain text, with
//! the characters that can forge a line or reorder it replaced.

/// Controls, line separators and the invisible, blank-looking or direction-changing characters
/// that let one string pose as another (a right-to-left override can make `sudo rm -rf x` read
/// differently; a Hangul filler or a variation selector hides text). std has no Unicode general
/// category, so these are the Cf, Zl, Zp and default-ignorable code points, listed.
fn spoofs(c: char) -> bool {
    c.is_control()
        || matches!(c as u32,
            0x00AD | 0x034F | 0x061C | 0x0600..=0x0605 | 0x06DD | 0x070F | 0x0890..=0x0891
            | 0x08E2 | 0x115F | 0x1160 | 0x17B4 | 0x17B5 | 0x180B..=0x180F | 0x200B..=0x200F
            | 0x2028..=0x202E | 0x2060..=0x206F | 0x2800 | 0x3164 | 0xFE00..=0xFE0F | 0xFEFF
            | 0xFFA0 | 0xFFF0..=0xFFFB | 0x110BD | 0x110CD | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0000..=0xE0FFF)
}

/// Spaces other than the ASCII one (no-break, wide, thin): shown as a plain space, so a gap cannot
/// pose as the end of a line or hide how far apart words are.
fn odd_space(c: char) -> bool {
    matches!(
        c as u32,
        0x00A0 | 0x1680 | 0x2000..=0x200A | 0x202F | 0x205F | 0x3000
    )
}

/// `s` cut to `max` characters with every spoofing character replaced by `?` and every odd space
/// by a plain one.
pub fn clean(s: &str, max: usize) -> String {
    s.chars()
        .take(max)
        .map(|c| {
            if spoofs(c) {
                '?'
            } else if odd_space(c) {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// An agent's run (`sudostamp ask`, docs/AGENTS-SUDO.md) is sudo's command line
/// `sudo -k -- /usr/local/sbin/sudostamp-run <sha256> <agent> -- <why>`: shown as
/// `<agent>: <why> (script <first 16 of the hash>)`, the same 16 `sudostamp ask` prints and the phone shows, what a person can check against the agent's
/// own words. Anything else, unchanged.
pub fn describe(command: &str) -> String {
    describe_run(command).unwrap_or_else(|| command.to_string())
}

fn describe_run(command: &str) -> Option<String> {
    let mut w = command.split(' ');
    if w.next()?.rsplit('/').next()? != "sudo" {
        return None;
    }
    let mut t = w.next()?;
    if t == "-k" {
        t = w.next()?;
    }
    if t == "--" {
        t = w.next()?;
    }
    // The installed runner and nothing else: a `sudostamp-run` anywhere else is somebody's
    // program dressed as an agent's run, and is shown as the command line it is.
    if t != "/usr/local/sbin/sudostamp-run" {
        return None;
    }
    let sha = w.next()?;
    let agent = w.next()?;
    let ok_sha = sha.len() == 64
        && sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let ok_agent = !agent.is_empty()
        && agent.len() <= 32
        && agent
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && agent
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b));
    if !ok_sha || !ok_agent || w.next()? != "--" {
        return None;
    }
    let why = w.filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ");
    if why.is_empty() {
        return None;
    }
    Some(format!("{agent}: {why} (script {}…)", &sha[..16]))
}

/// For notification bodies and tooltips, which accept a subset of HTML: the command is data.
pub fn escape_markup(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls_and_bidi_are_replaced() {
        assert_eq!(clean("a\nb\tc\u{1b}[31m", 99), "a?b?c?[31m");
        assert_eq!(clean("sudo \u{202E}fdp.txt", 99), "sudo ?fdp.txt");
        assert_eq!(clean("a\u{2028}b\u{200b}c\u{feff}", 99), "a?b?c?");
    }

    #[test]
    fn cut_counts_characters_not_bytes() {
        assert_eq!(clean("ééééé", 3), "ééé");
        assert_eq!(clean("abc", 0), "");
    }

    #[test]
    fn markup_is_escaped() {
        assert_eq!(
            escape_markup("<a href=\"x\">&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;"
        );
    }

    #[test]
    fn an_agents_run_reads_as_who_why_and_which_script() {
        let sha = "a3f9".repeat(16);
        let c = format!(
            "sudo -k -- /usr/local/sbin/sudostamp-run {sha} hermes -- rebuild pam_rssh now"
        );
        assert_eq!(
            describe(&c),
            "hermes: rebuild pam_rssh now (script a3f9a3f9a3f9a3f9…)"
        );
        let plain = format!("sudo /usr/local/sbin/sudostamp-run {sha} claude-code -- x");
        assert_eq!(
            describe(&plain),
            "claude-code: x (script a3f9a3f9a3f9a3f9…)"
        );
        for bad in [
            format!(
                "sudo -k -- /usr/local/sbin/sudostamp-run {} hermes -- x",
                &sha[..63]
            ),
            format!(
                "sudo -k -- /usr/local/sbin/sudostamp-run {} hermes -- x",
                sha.to_uppercase()
            ),
            format!("sudo -k -- /usr/local/sbin/sudostamp-run {sha} Hermes -- x"),
            format!("sudo -k -- /usr/local/sbin/sudostamp-run {sha} hermes x"),
            format!("sudo -k -- /usr/local/sbin/sudostamp-run {sha} hermes --"),
            format!("doas /usr/local/sbin/sudostamp-run {sha} hermes -- x"),
            // Only the installed runner: one anywhere else is shown as the command it is.
            format!("sudo -k -- /tmp/evil/sudostamp-run {sha} backup -- nightly snapshot"),
            format!("sudo -k -- sudostamp-run {sha} backup -- nightly snapshot"),
            "sudo pacman -Syu".to_string(),
            String::new(),
        ] {
            assert_eq!(describe(&bad), bad, "{bad}");
        }
    }

    #[test]
    fn hidden_and_blank_looking_characters_are_shown() {
        // Each of these renders as nothing or as blank space: a filler, a variation selector, a
        // tag, the Arabic letter mark, a soft hyphen, a Braille blank.
        for c in [
            '\u{3164}',
            '\u{FE0F}',
            '\u{E0041}',
            '\u{061C}',
            '\u{00AD}',
            '\u{2800}',
            '\u{034F}',
        ] {
            assert_eq!(clean(&format!("a{c}b"), 10), "a?b", "U+{:04X}", c as u32);
        }
        assert_eq!(clean("a\u{00A0}b\u{3000}c", 10), "a b c");
        assert_eq!(
            clean("plain ascii, é and 日本", 64),
            "plain ascii, é and 日本"
        );
    }
}
