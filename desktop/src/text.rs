//! Plain-text hygiene for everything that came from outside this process.
//!
//! Any process of the user can write to the event socket, and the installer's output and a phone's
//! mDNS name are text somebody else chose. None of it is trusted: it is shown as plain text, with
//! the characters that can forge a line or reorder it replaced.

/// Controls, line separators and the invisible or direction-changing characters that let one
/// string pose as another (a right-to-left override can make `sudo rm -rf x` read differently).
fn spoofs(c: char) -> bool {
    c.is_control()
        || matches!(c as u32,
            0x200B..=0x200F | 0x2028..=0x202E | 0x2060..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB)
}

/// `s` cut to `max` characters with every spoofing character replaced by `?`.
pub fn clean(s: &str, max: usize) -> String {
    s.chars()
        .take(max)
        .map(|c| if spoofs(c) { '?' } else { c })
        .collect()
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
}
