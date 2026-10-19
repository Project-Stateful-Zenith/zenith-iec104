//! What the TLS interop suites (`c104.rs`, `lib60870.rs`) share: certificate
//! files made at test time, an external peer process and its stdout, and our
//! blocking master over TLS through the examples' driver.

#![allow(dead_code)]

#[path = "../../../examples/common/mod.rs"]
pub mod common;
#[path = "../pki/mod.rs"]
pub mod pki;

use std::io::{self, BufRead, BufReader};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use iec104::asdu::AddressSizes;
use iec104::link::{Role, State};
use iec104::manager::{ConnectionManager, StationConfig};
use iec104::params::LinkParams;
use iec104_tls::{TlsConfig, TlsStream};
use pki::{Ca, Leaf};
use rcgen::KeyPair;

impl common::Socket for TlsStream {
    fn tcp(&self) -> &TcpStream {
        self.get_ref()
    }
}

/// `C_IC_NA_1`, cause 6, common address 1, IOA 0, QOI 20 (101 cl.7.3.4.1).
pub const INTERROGATION: [u8; 10] = [0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14];

pub fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the workspace root")
}

/// Which keys a test PKI uses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Keys {
    /// ECDSA P-256, made by rcgen.
    P256,
    /// RSA 2048, made by `openssl genpkey` (rcgen with *ring* cannot).
    Rsa2048,
}

/// The certificates of one test: the interop CA, a rogue CA nobody trusts,
/// and leaves, all as PEM files in a temporary directory.
pub struct Pki {
    pub dir: PathBuf,
    pub ca: Ca,
    pub rogue: Ca,
    keys: Keys,
}

impl Pki {
    pub fn new(test: &str, keys: Keys) -> Self {
        let dir = std::env::temp_dir().join(format!("iec104-tls-{test}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca = Ca::with_key("interop CA", key(keys, &dir));
        let rogue = Ca::with_key("rogue CA", key(keys, &dir));
        std::fs::write(dir.join("ca.crt"), &ca.pem).unwrap();
        std::fs::write(dir.join("rogue.crt"), &rogue.pem).unwrap();
        Self {
            dir,
            ca,
            rogue,
            keys,
        }
    }

    /// A leaf from `ca` for 127.0.0.1, written as `<name>.crt` and `<name>.key`.
    pub fn leaf(&self, ca: &Ca, name: &str, serial: u64) -> Leaf {
        let key = key(self.keys, &self.dir);
        let leaf = ca.leaf_with_key(&["127.0.0.1", "localhost"], serial, &key);
        std::fs::write(self.path(&format!("{name}.crt")), &leaf.cert_pem).unwrap();
        std::fs::write(self.path(&format!("{name}.key")), &leaf.key_pem).unwrap();
        leaf
    }

    pub fn path(&self, file: &str) -> String {
        self.dir.join(file).to_string_lossy().into_owned()
    }

    /// Our end: `leaf`, trusting the interop CA.
    pub fn ours(&self, leaf: &Leaf) -> TlsConfig {
        TlsConfig::builder(leaf.identity(), vec![self.ca.cert.clone()])
            .build()
            .unwrap()
    }
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn key(keys: Keys, dir: &Path) -> KeyPair {
    match keys {
        Keys::P256 => KeyPair::generate().unwrap(),
        Keys::Rsa2048 => {
            let file = dir.join("rsa.key");
            let status = Command::new("openssl")
                .args([
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    "rsa_keygen_bits:2048",
                    "-out",
                ])
                .arg(&file)
                .stderr(Stdio::null())
                .status()
                .expect("RSA keys need openssl");
            assert!(status.success(), "openssl genpkey failed");
            let pem = std::fs::read_to_string(&file).unwrap();
            let _ = std::fs::remove_file(&file);
            KeyPair::from_pem(&pem).unwrap()
        }
    }
}

/// An external peer process; its stdout lines (and the notable stderr ones,
/// prefixed `STDERR`) arrive in order.
pub struct Peer {
    pub child: Child,
    lines: mpsc::Receiver<String>,
    pub log: Vec<String>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Peer {
    pub fn spawn(program: &Path, args: &[String]) -> Self {
        let mut child = Command::new(program)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("cannot run {}: {e}", program.display()));
        let (lines, received) = mpsc::channel();
        let stdout = child.stdout.take().unwrap();
        let out = lines.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let _ = out.send(line);
            }
        });
        // Keep only the verdicts of the peers' TLS diagnostics.
        let stderr = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if line.starts_with("ERROR") || line.contains("failed") || line.contains("alert") {
                    let _ = lines.send(format!("STDERR {line}"));
                }
            }
        });
        Self {
            child,
            lines: received,
            log: Vec::new(),
        }
    }

    /// Waits for a line `wanted` accepts, within `limit`.
    pub fn wait_for(&mut self, limit: Duration, wanted: impl Fn(&str) -> bool) -> bool {
        let deadline = Instant::now() + limit;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    let found = wanted(&line);
                    self.log.push(line);
                    if found {
                        return true;
                    }
                }
                Err(_) => return false,
            }
        }
    }

    /// Everything the peer printed so far.
    pub fn drain(&mut self) -> &[String] {
        self.log.extend(self.lines.try_iter());
        &self.log
    }
}

/// Dials `port` over TLS, retrying while the peer's listener is not up yet
/// (both peers start listening a moment after they report it).
pub fn dial(port: u16, config: &TlsConfig) -> io::Result<TlsStream> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match iec104_tls::connect(&format!("127.0.0.1:{port}"), config) {
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            result => return result,
        }
    }
}

/// What our blocking master saw of one connection.
pub struct Run {
    /// Every ASDU received, in order.
    pub asdus: Vec<Vec<u8>>,
    /// Whether the connection ended within the run (the driver prints why).
    pub closed: bool,
}

/// Runs our blocking master over `tls` for `run`: STARTDT, a station
/// interrogation, then idles (t3's test frames keep the link busy).
pub fn blocking_master(tls: TlsStream, run: Duration) -> Run {
    let mut manager = ConnectionManager::new(
        Role::Controlling,
        vec![StationConfig::new(LinkParams::default())],
    )
    .unwrap();
    let mut link = common::Link::new(AddressSizes::CONVENTIONAL);
    let now = Instant::now();
    link.attach(tls, &mut manager, now).unwrap();
    let start = manager.request_start(common::STATION, now).unwrap();
    link.perform(&mut manager, start);
    let (mut sent, mut asdus) = (false, Vec::new());
    let deadline = Instant::now() + run;
    while Instant::now() < deadline && link.is_up() {
        let now = Instant::now();
        let expired = manager.tick(now);
        link.perform(&mut manager, expired);
        asdus.extend(link.receive(&mut manager, now));
        let started = manager.station(common::STATION).unwrap().state() == State::Started;
        if started && !sent {
            link.send_asdu(&mut manager, &INTERROGATION, now);
            sent = true;
        }
    }
    Run {
        asdus,
        closed: !link.is_up(),
    }
}
