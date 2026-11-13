//! `agent::check` against the repo's mock phone (`tools/test/mock_agent.py`, a software-key
//! stand-in, loopback only) and against hostile peers written here.
//!
//! The mock needs python3 with `cryptography`. Without them the mock tests say so loudly and stop;
//! CI sets SUDOSTAMP_REQUIRE_MOCK=1, which turns that into a failure so they cannot silently not run.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use sudostamp_desktop::agent::{self, Status};
use sudostamp_desktop::keys;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Mock {
    child: Child,
    addr: SocketAddr,
    log: Arc<Mutex<Vec<String>>>,
    dir: PathBuf,
}

impl Mock {
    /// `None` (after saying why) when python3 or `cryptography` is missing.
    fn start(name: &str, mode: &str) -> Option<Mock> {
        let have = Command::new("python3")
            .args(["-c", "import cryptography"])
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !have {
            assert!(
                std::env::var("SUDOSTAMP_REQUIRE_MOCK").is_err(),
                "SUDOSTAMP_REQUIRE_MOCK is set but python3 with `cryptography` is not available"
            );
            eprintln!("SKIPPED {name}: python3 with `cryptography` is needed for the mock phone");
            return None;
        }
        let dir =
            std::env::temp_dir().join(format!("sudostamp-mock-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("mode"), mode).unwrap();
        let port = free_port();
        let mut child = Command::new("python3")
            .arg(repo().join("tools/test/mock_agent.py"))
            .args(["--port", &port.to_string()])
            .arg("--pubkey-out")
            .arg(dir.join("key.pub"))
            .arg("--mode-file")
            .arg(dir.join("mode"))
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("python3 starts");
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let mut first = String::new();
        out.read_line(&mut first).unwrap();
        assert!(
            first.starts_with("mock agent on"),
            "mock did not start: {first:?}"
        );
        let log = Arc::new(Mutex::new(Vec::new()));
        let l = Arc::clone(&log);
        thread::spawn(move || {
            for line in out.lines().map_while(Result::ok) {
                l.lock().unwrap().push(line);
            }
        });
        Some(Mock {
            child,
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
            log,
            dir,
        })
    }

    fn pinned(&self) -> Vec<Vec<u8>> {
        keys::parse(&std::fs::read_to_string(self.dir.join("key.pub")).unwrap())
    }

    fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn mock_phone_listing_the_pinned_key_is_ready_and_is_never_asked_to_sign() {
    let Some(m) = Mock::start("ready", "approve") else {
        return;
    };
    let pinned = m.pinned();
    assert_eq!(pinned.len(), 1, "the mock wrote one key line");
    assert_eq!(agent::check(m.addr, &pinned, agent::BUDGET), Status::Ready);
    thread::sleep(Duration::from_millis(200));
    let log = m.log();
    assert!(log.iter().any(|l| l.starts_with("identities:")), "{log:?}");
    assert!(
        !log.iter().any(|l| l.starts_with("sign")),
        "the app must never ask for a signature: {log:?}"
    );
}

#[test]
fn mock_phone_with_another_key_is_wrong_key() {
    let Some(m) = Mock::start("foreign", "foreign") else {
        return;
    };
    let pinned = m.pinned();
    assert_eq!(
        agent::check(m.addr, &pinned, agent::BUDGET),
        Status::WrongKey
    );
    // Control: the same phone in another mode lists the pinned key, so the result above came from
    // the key comparison and not from a broken exchange.
    std::fs::write(m.dir.join("mode"), "approve").unwrap();
    assert_eq!(agent::check(m.addr, &pinned, agent::BUDGET), Status::Ready);
}

#[test]
fn nobody_listening_is_away_at_once() {
    let addr = SocketAddr::from(([127, 0, 0, 1], free_port()));
    let t = Instant::now();
    assert_eq!(
        agent::check(addr, &[b"k".to_vec()], agent::BUDGET),
        Status::Away
    );
    assert!(t.elapsed() < Duration::from_secs(2));
}

#[test]
fn a_listener_that_accepts_and_never_answers_is_away_within_the_budget() {
    // The phone case that matters most: the TCP handshake succeeds (the kernel does it), then
    // silence. sudo would hang on the same peer if the probe did not cut it off.
    let Some(m) = Mock::start("stall", "stall") else {
        return;
    };
    let t = Instant::now();
    assert_eq!(
        agent::check(m.addr, &[b"k".to_vec()], agent::BUDGET),
        Status::Away
    );
    let took = t.elapsed();
    assert!(
        took >= Duration::from_millis(3500) && took < Duration::from_millis(4600),
        "took {took:?}"
    );
}

#[test]
fn the_same_silence_without_python() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let held = thread::spawn(move || {
        let (s, _) = l.accept().unwrap();
        thread::sleep(Duration::from_secs(3));
        drop(s);
    });
    let t = Instant::now();
    assert_eq!(
        agent::check(addr, &[b"k".to_vec()], Duration::from_millis(800)),
        Status::Away
    );
    let took = t.elapsed();
    assert!(
        took >= Duration::from_millis(700) && took < Duration::from_millis(1500),
        "took {took:?}"
    );
    held.join().unwrap();
}

/// A peer that writes the answer one byte at a time, slower than a read() each, and one that keeps
/// dribbling past the deadline: the first is Ready (pitfall 22), the second still ends on time.
#[test]
fn dribbled_answers_are_read_in_a_loop_but_cannot_stretch_the_budget() {
    let key = b"ecdsa-blob".to_vec();
    let mut body = vec![12u8];
    body.extend(1u32.to_be_bytes());
    body.extend((key.len() as u32).to_be_bytes());
    body.extend(&key);
    body.extend(0u32.to_be_bytes());
    let mut wire = (body.len() as u32).to_be_bytes().to_vec();
    wire.extend(&body);

    let serve = |wire: Vec<u8>, pause: u64| {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut req = [0u8; 5];
            s.read_exact(&mut req).unwrap();
            assert_eq!(req, [0, 0, 0, 1, 11], "exactly REQUEST_IDENTITIES");
            s.set_nodelay(true).unwrap();
            for b in wire {
                if s.write_all(&[b]).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(pause));
            }
            thread::sleep(Duration::from_secs(1));
        });
        addr
    };
    let addr = serve(wire.clone(), 5);
    assert_eq!(
        agent::check(addr, std::slice::from_ref(&key), agent::BUDGET),
        Status::Ready
    );

    let slow = serve(wire, 200);
    let t = Instant::now();
    assert_eq!(
        agent::check(slow, std::slice::from_ref(&key), Duration::from_millis(700)),
        Status::Away
    );
    assert!(
        t.elapsed() < Duration::from_millis(1400),
        "{:?}",
        t.elapsed()
    );
}

#[test]
fn garbage_and_failure_answers_are_away() {
    for reply in [
        vec![0, 0, 0, 1, 5],
        vec![0, 0, 0, 3, 12, 0, 0],
        vec![0xff; 16],
        vec![],
    ] {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut req = [0u8; 5];
            let _ = s.read_exact(&mut req);
            let _ = s.write_all(&reply);
        });
        assert_eq!(
            agent::check(addr, &[b"k".to_vec()], Duration::from_secs(2)),
            Status::Away
        );
    }
}
