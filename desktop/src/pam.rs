//! Find the SudoStamp block in `/etc/pam.d/sudo` and read the phone's address from the pam_rssh
//! line, so the app asks the same phone sudo does (world-readable file, no privilege).

use std::net::SocketAddr;

/// `install.sh` writes `# >>> SudoStamp >>> managed by ...`: match the start of the line.
const BEGIN: &str = "# >>> SudoStamp >>>";
const END: &str = "# <<< SudoStamp <<<";

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// No SudoStamp block: sudo does not ask the phone at all.
    NoBlock,
    /// A BEGIN without its END, or two blocks: the installer refuses these too.
    Damaged,
    /// The block has no pam_rssh line with a usable `ssh_agent_addr=`.
    NoAddress,
}

pub fn phone_address(text: &str) -> Result<SocketAddr, Error> {
    let mut inside = false;
    let mut blocks = 0;
    let mut addr = None;
    for line in text.lines() {
        if line.starts_with(BEGIN) {
            if inside {
                return Err(Error::Damaged);
            }
            inside = true;
            blocks += 1;
        } else if line.trim_end() == END {
            if !inside {
                return Err(Error::Damaged);
            }
            inside = false;
        } else if inside && addr.is_none() {
            let rule = line.trim_start();
            if !rule.starts_with('#') && rule.contains("pam_rssh") {
                addr = rule
                    .split_whitespace()
                    .find_map(|t| t.strip_prefix("ssh_agent_addr="))
                    .and_then(|a| a.parse::<SocketAddr>().ok())
                    .filter(|a| a.port() != 0);
            }
        }
    }
    match (blocks, inside) {
        (0, _) => Err(Error::NoBlock),
        (1, false) => addr.ok_or(Error::NoAddress),
        _ => Err(Error::Damaged),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCK: &str = "\
# >>> SudoStamp >>> managed by tools/install.sh; 'install.sh rollback' removes it
auth       [success=ignore default=1]  pam_exec.so quiet /usr/local/sbin/sudostamp-probe phone=192.168.1.20:7777 keys=/etc/authorized_keys
auth       sufficient   pam_rssh.so ssh_agent_addr=192.168.1.20:7777 auth_key_file=/etc/authorized_keys/${user}.keys cue cue_prompt=SudoStamp-approve-on-your-phone-(up-to-60s)
# <<< SudoStamp <<<
";

    fn file(block: &str) -> String {
        format!("#%PAM-1.0\nauth sufficient pam_other.so ssh_agent_addr=9.9.9.9:1\n{block}auth include system-auth\n")
    }

    #[test]
    fn ipv4() {
        assert_eq!(
            phone_address(&file(BLOCK)),
            Ok("192.168.1.20:7777".parse().unwrap())
        );
    }

    #[test]
    fn ipv6() {
        let b = BLOCK.replace("192.168.1.20:7777 auth_key", "[fd00::1234]:7777 auth_key");
        assert_eq!(
            phone_address(&file(&b)),
            Ok("[fd00::1234]:7777".parse().unwrap())
        );
    }

    #[test]
    fn only_the_blocks_own_pam_rssh_line_counts() {
        // The decoy outside the block names another address; the probe line names the phone too
        // but is not the module line.
        let b = BLOCK.replace("192.168.1.20:7777 auth_key", "10.0.0.2:7777 auth_key");
        assert_eq!(
            phone_address(&file(&b)),
            Ok("10.0.0.2:7777".parse().unwrap())
        );
    }

    #[test]
    fn no_block_damaged_and_no_address() {
        assert_eq!(phone_address(""), Err(Error::NoBlock));
        assert_eq!(
            phone_address("auth sufficient pam_rssh.so ssh_agent_addr=1.2.3.4:7777\n"),
            Err(Error::NoBlock)
        );
        let begin_only = BLOCK.replace("# <<< SudoStamp <<<\n", "");
        assert_eq!(phone_address(&begin_only), Err(Error::Damaged));
        assert_eq!(
            phone_address(&format!("{BLOCK}{BLOCK}")),
            Err(Error::Damaged)
        );
        assert_eq!(phone_address("# <<< SudoStamp <<<\n"), Err(Error::Damaged));
        let nested = format!("{BEGIN}\n{BLOCK}");
        assert_eq!(phone_address(&nested), Err(Error::Damaged));
        let none = BLOCK.replace("ssh_agent_addr=192.168.1.20:7777", "");
        assert_eq!(phone_address(&none), Err(Error::NoAddress));
    }

    #[test]
    fn bad_addresses_and_comments_are_not_addresses() {
        for bad in [
            "ssh_agent_addr=phone.local:7777",
            "ssh_agent_addr=1.2.3.4",
            "ssh_agent_addr=1.2.3.4:0",
            "ssh_agent_addr=1.2.3.4:99999",
            "ssh_agent_addr=[fe80::1%wlan0]:7777",
        ] {
            let b = BLOCK.replace("ssh_agent_addr=192.168.1.20:7777", bad);
            assert_eq!(phone_address(&file(&b)), Err(Error::NoAddress), "{bad}");
        }
        let commented = BLOCK.replace(
            "auth       sufficient   pam_rssh",
            "#auth       sufficient   pam_rssh",
        );
        assert_eq!(phone_address(&commented), Err(Error::NoAddress));
    }
}
