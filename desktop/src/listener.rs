//! The event socket (docs/DESKTOP.md): a `SOCK_DGRAM` Unix socket in `$XDG_RUNTIME_DIR/sudostamp/`,
//! directory 0700, socket 0600. The probe sends to it after dropping to this user, so what reaches
//! it is only what this user could send anyway; `event::parse` still treats every byte as hostile.

use crate::event::{self, Event, MAX_DATAGRAM};
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixDatagram;
use std::path::Path;

pub enum Bind {
    Bound(UnixDatagram),
    /// A live instance owns the socket: this one has nothing to do.
    AlreadyRunning,
}

fn my_uid() -> io::Result<u32> {
    // The owner of /proc/self is the process's effective user: no libc needed to ask.
    Ok(fs::metadata("/proc/self")?.uid())
}

/// The directory must be a real directory (not a symlink) of ours, and private.
fn private_dir(dir: &Path) -> io::Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() && m.uid() == my_uid()? => {
            if m.mode() & 0o077 != 0 {
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            }
            Ok(())
        }
        Ok(_) => Err(io::Error::other(format!(
            "{} exists but is not a directory of yours",
            dir.display()
        ))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir),
        Err(e) => Err(e),
    }
}

pub fn bind(dir: &Path, sock: &Path) -> io::Result<Bind> {
    private_dir(dir)?;
    match fs::symlink_metadata(sock) {
        Ok(m) if m.file_type().is_socket() => {
            // A datagram socket cannot be asked "are you there" without sending: connecting is
            // enough. Refused or missing = nobody is bound to it, a leftover from a crash.
            match UnixDatagram::unbound()?.connect(sock) {
                Ok(()) => return Ok(Bind::AlreadyRunning),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                    ) =>
                {
                    fs::remove_file(sock)?;
                }
                Err(e) => return Err(e),
            }
        }
        // Never delete anything that is not a socket.
        Ok(_) => {
            return Err(io::Error::other(format!(
                "{} exists and is not a socket",
                sock.display()
            )));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let s = UnixDatagram::bind(sock)?;
    fs::set_permissions(sock, fs::Permissions::from_mode(0o600))?;
    Ok(Bind::Bound(s))
}

/// Receive datagrams until `on_event` returns false or the socket fails. One byte more than the
/// limit is read so an oversize datagram is told from one that exactly fits.
pub fn serve(sock: &UnixDatagram, mut on_event: impl FnMut(Event) -> bool) {
    let mut buf = vec![0u8; MAX_DATAGRAM + 1];
    loop {
        match sock.recv(&mut buf) {
            Ok(n) => {
                if let Ok(e) = event::parse(&buf[..n])
                    && !on_event(e)
                {
                    return;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sudostamp-sock-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn mode(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    const ASKING: &[u8] = br#"{"v":1,"event":"asking","sudo_pid":42,"command":"sudo id"}"#;

    #[test]
    fn creates_a_private_dir_and_socket_and_receives() {
        let root = scratch("recv");
        let dir = root.join("sudostamp");
        let sock = dir.join("events.sock");
        let Bind::Bound(s) = bind(&dir, &sock).unwrap() else {
            panic!("not bound")
        };
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&sock), 0o600);
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || serve(&s, |e| tx.send(e).is_ok()));
        let c = UnixDatagram::unbound().unwrap();
        c.send_to(b"garbage", &sock).unwrap();
        c.send_to(&vec![b' '; MAX_DATAGRAM + 1], &sock).unwrap();
        c.send_to(ASKING, &sock).unwrap();
        let e = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!((e.sudo_pid, e.command.as_str()), (42, "sudo id"));
        assert!(
            rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "bad datagrams are dropped"
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_live_instance_is_detected_and_a_stale_socket_is_replaced() {
        let root = scratch("stale");
        let dir = root.join("sudostamp");
        let sock = dir.join("events.sock");
        let Bind::Bound(first) = bind(&dir, &sock).unwrap() else {
            panic!()
        };
        assert!(matches!(bind(&dir, &sock).unwrap(), Bind::AlreadyRunning));
        drop(first); // the file stays behind, like after a crash
        assert!(fs::symlink_metadata(&sock).unwrap().file_type().is_socket());
        assert!(matches!(bind(&dir, &sock).unwrap(), Bind::Bound(_)));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn never_removes_what_is_not_a_socket_and_fixes_a_loose_directory() {
        let root = scratch("safe");
        let dir = root.join("sudostamp");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let sock = dir.join("events.sock");
        fs::write(&sock, "precious").unwrap();
        assert!(bind(&dir, &sock).is_err());
        assert_eq!(fs::read_to_string(&sock).unwrap(), "precious");
        assert_eq!(mode(&dir), 0o700);
        // A symlink in place of the directory is refused.
        let link = root.join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(bind(&link, &link.join("events.sock")).is_err());
        fs::remove_dir_all(&root).unwrap();
    }
}
