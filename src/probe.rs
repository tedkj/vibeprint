//! What a network printer itself says (SPEC section 2): 3 pings, TCP connects to 9100 (RAW),
//! 631 (IPP) and 515 (LPR) with 1.5 s each, IPP Get-Printer-Attributes when 631 is open, SNMP v1,
//! and ARP for the MAC on the same subnet. The model and its words are plain Rust; `ask` does the
//! asking on the calling (worker) thread, the parts at once on threads of their own.

use crate::net::Mac;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

pub const PORTS: [u16; 3] = [9100, 631, 515];
pub const CONNECT_WAIT: Duration = Duration::from_millis(1500);
pub const PINGS: usize = 3;
pub const PING_WAIT_MS: u32 = 1000;

/// One TCP port's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortState {
    Open,
    /// Refused (a reset): the device is there, the port is not.
    Closed,
    /// No answer in time.
    Silent,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ping {
    pub sent: u32,
    /// Round trips of the echoes that came back, in microseconds.
    pub replies: Vec<u32>,
    /// Why nothing could be sent, if so.
    pub error: Option<String>,
}

impl Ping {
    /// "3 of 3, 2.1 ms" or "no reply (3 sent)".
    pub fn words(&self) -> String {
        if let Some(e) = &self.error {
            return format!("not sent: {e}");
        }
        if self.replies.is_empty() {
            return format!("no reply ({} sent; many printers do not answer ping)", self.sent);
        }
        let avg = self.replies.iter().map(|&r| r as u64).sum::<u64>() / self.replies.len() as u64;
        format!("{} of {}, {}", self.replies.len(), self.sent, ms(avg as u32))
    }
}

/// Microseconds as the window shows them: "0.4 ms", "12 ms".
pub fn ms(us: u32) -> String {
    if us < 10_000 { format!("{:.1} ms", us as f64 / 1000.0) } else { format!("{} ms", us / 1000) }
}

/// Everything one probe of one address found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answers {
    pub at: IpAddr,
    pub ping: Ping,
    /// (port, state) for 9100, 631, 515.
    pub ports: Vec<(u16, PortState)>,
    /// IPP, when 631 was open.
    pub ipp: Option<crate::ipp::Outcome>,
    pub snmp: crate::snmp::Outcome,
    /// From ARP, on the same subnet only.
    pub mac: Option<Mac>,
}

impl Answers {
    pub fn port(&self, p: u16) -> Option<PortState> {
        self.ports.iter().find(|x| x.0 == p).map(|x| x.1)
    }

    pub fn open(&self, p: u16) -> bool {
        self.port(p) == Some(PortState::Open)
    }

    pub fn snmp_answers(&self) -> bool {
        self.snmp.answered()
    }

    /// The device answered as a printer: IPP (in any way), SNMP, 9100 or 515 (SPEC rule 3). A
    /// ping alone is not that.
    pub fn answers(&self) -> bool {
        self.open(9100) || self.open(515) || self.open(631) || self.ipp.as_ref().is_some_and(|o| o.answered()) || self.snmp_answers()
    }

    /// Anything at all came back (a ping too).
    pub fn anything(&self) -> bool {
        self.answers() || !self.ping.replies.is_empty() || self.ports.iter().any(|p| p.1 == PortState::Closed)
    }

    /// The device's own state: (words, a fault). IPP first, then SNMP's Printer MIB; a device
    /// that answers but tells nothing says so.
    pub fn state(&self) -> (String, bool) {
        if let Some(crate::ipp::Outcome::Answered(a)) = &self.ipp {
            return (a.words(), a.has_problem());
        }
        if let crate::snmp::Outcome::Answered(s) = &self.snmp
            && (s.status.is_some() || !s.errors.is_empty())
        {
            return (s.words(), s.has_problem());
        }
        if matches!(self.ipp, Some(crate::ipp::Outcome::TlsOnly)) {
            return ("Answers IPPS only (not checked in v1)".into(), false);
        }
        let open: Vec<String> = PORTS.iter().filter(|p| self.open(**p)).map(|p| p.to_string()).collect();
        if open.is_empty() {
            ("Answers SNMP, says nothing about printing".into(), false)
        } else {
            (format!("Answers, says nothing (port {} only)", open.join(", ")), false)
        }
    }

    /// The model the device names (IPP's make and model, else SNMP's sysDescr).
    pub fn model(&self) -> Option<String> {
        if let Some(crate::ipp::Outcome::Answered(a)) = &self.ipp
            && let Some(m) = &a.make_model
        {
            return Some(m.clone());
        }
        match &self.snmp {
            crate::snmp::Outcome::Answered(s) => s.descr.clone(),
            _ => None,
        }
    }

    /// "9100 open · 631 open · 515 closed".
    pub fn ports_words(&self) -> String {
        self.ports
            .iter()
            .map(|(p, s)| {
                format!(
                    "{p} {}",
                    match s {
                        PortState::Open => "open",
                        PortState::Closed => "closed",
                        PortState::Silent => "no answer",
                    }
                )
            })
            .collect::<Vec<_>>()
            .join(" · ")
    }
}

/// How a probe of a printer stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Probe {
    /// Not a network printer.
    NotNetwork,
    /// A network printer whose address is not known: why.
    NoAddress(String),
    /// Being asked.
    Checking,
    Done(Box<Answers>),
}

/// The network the probes run over (the tests script it).
pub trait Net: Send + Sync {
    fn ping(&self, ip: IpAddr) -> Ping;
    fn connect(&self, addr: SocketAddr, wait: Duration) -> PortState;
    fn ipp(&self, addr: SocketAddr, path: &str) -> crate::ipp::Outcome;
    /// SNMP v1 with `community`.
    fn snmp(&self, addr: SocketAddr, community: &str) -> crate::snmp::Outcome;
    fn arp(&self, ip: std::net::Ipv4Addr) -> Option<Mac>;
    /// Find's mDNS browse out of this PC's address `src`.
    fn browse(&self, _src: std::net::Ipv4Addr, _stop: &dyn Fn() -> bool) -> Vec<crate::mdns::Announced> {
        Vec::new()
    }
    /// Find's port sweep: the open (address, port) pairs of `pairs`.
    fn sweep(&self, _pairs: &[(std::net::Ipv4Addr, u16)], _stop: &dyn Fn() -> bool) -> Vec<(std::net::Ipv4Addr, u16)> {
        Vec::new()
    }
    /// The up IPv4 adapters Find searches.
    fn adapters(&self) -> Vec<crate::net::Adapter> {
        Vec::new()
    }
    /// A host name's addresses (a TCP/IP port that names a host).
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        use std::net::ToSocketAddrs;
        match (host, 0).to_socket_addrs() {
            Ok(a) => {
                let mut v: Vec<IpAddr> = a.map(|s| s.ip()).collect();
                v.dedup();
                if v.is_empty() { Err(format!("{host} has no address")) } else { Ok(v) }
            }
            Err(e) => Err(format!("{host} did not resolve ({e})")),
        }
    }
}

/// The real network.
pub struct RealNet;

impl Net for RealNet {
    fn ping(&self, ip: IpAddr) -> Ping {
        let mut p = Ping { sent: 0, ..Ping::default() };
        let mut pinger = match crate::icmp::Pinger::open(ip.is_ipv6()) {
            Ok(x) => x,
            Err(e) => {
                p.error = Some(e);
                return p;
            }
        };
        for _ in 0..PINGS {
            p.sent += 1;
            match pinger.ping(ip, PING_WAIT_MS) {
                Ok(Some(rtt)) => p.replies.push(rtt),
                Ok(None) => {}
                Err(e) => {
                    p.error = Some(e);
                    break;
                }
            }
        }
        p
    }

    fn connect(&self, addr: SocketAddr, wait: Duration) -> PortState {
        match std::net::TcpStream::connect_timeout(&addr, wait) {
            Ok(s) => {
                // A reset rather than a FIN: the printer drops its side at once.
                use std::os::windows::io::AsRawSocket;
                use windows_sys::Win32::Networking::WinSock::{LINGER, SO_LINGER, SOL_SOCKET, setsockopt};
                let l = LINGER { l_onoff: 1, l_linger: 0 };
                // SAFETY: the stream's own socket and a LINGER of the size given.
                unsafe { setsockopt(s.as_raw_socket() as usize, SOL_SOCKET, SO_LINGER, (&l as *const LINGER).cast(), size_of::<LINGER>() as i32) };
                PortState::Open
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => PortState::Closed,
            Err(_) => PortState::Silent,
        }
    }

    fn ipp(&self, addr: SocketAddr, path: &str) -> crate::ipp::Outcome {
        crate::ipp::get_printer_attributes(addr, path)
    }

    fn snmp(&self, addr: SocketAddr, community: &str) -> crate::snmp::Outcome {
        crate::snmp::query(addr, community)
    }

    fn arp(&self, ip: std::net::Ipv4Addr) -> Option<Mac> {
        let adapters = crate::net::system_adapters().ok()?;
        let a = crate::net::on_link(&adapters, ip)?;
        match crate::arp::send_arp(ip, a.addr) {
            Ok(crate::arp::Arp::Answered(m)) => Some(m),
            _ => None,
        }
    }

    fn browse(&self, src: std::net::Ipv4Addr, stop: &dyn Fn() -> bool) -> Vec<crate::mdns::Announced> {
        crate::mdns::browse(src, stop)
    }

    fn sweep(&self, pairs: &[(std::net::Ipv4Addr, u16)], stop: &dyn Fn() -> bool) -> Vec<(std::net::Ipv4Addr, u16)> {
        crate::find::sweep(pairs, stop)
    }

    fn adapters(&self) -> Vec<crate::net::Adapter> {
        crate::net::system_adapters().unwrap_or_default()
    }
}

/// Ask everything of `ip` at once (each on its own thread), IPP over `path`, SNMP with
/// `community` (the port's own). Bounded: the slowest part is IPP's 5 s, so a probe takes at
/// most about 7 s.
pub fn ask(net: std::sync::Arc<dyn Net>, ip: IpAddr, path: &str, community: &str) -> Answers {
    let n1 = net.clone();
    let ping = std::thread::spawn(move || n1.ping(ip));
    let n2 = net.clone();
    let community = community.to_string();
    let snmp = std::thread::spawn(move || n2.snmp(SocketAddr::new(ip, crate::snmp::PORT), &community));
    let n3 = net.clone();
    let arp = std::thread::spawn(move || match ip {
        IpAddr::V4(v4) => n3.arp(v4),
        IpAddr::V6(_) => None,
    });
    let conns: Vec<_> = PORTS
        .iter()
        .map(|&p| {
            let n = net.clone();
            std::thread::spawn(move || (p, n.connect(SocketAddr::new(ip, p), CONNECT_WAIT)))
        })
        .collect();
    let ports: Vec<(u16, PortState)> = conns.into_iter().map(|h| h.join().unwrap_or((0, PortState::Silent))).filter(|p| p.0 != 0).collect();
    let ipp = ports.contains(&(631, PortState::Open)).then(|| net.ipp(SocketAddr::new(ip, crate::ipp::PORT), path));
    Answers {
        at: ip,
        ping: ping.join().unwrap_or_default(),
        ports,
        ipp,
        snmp: snmp.join().unwrap_or(crate::snmp::Outcome::Silent),
        mac: arp.join().unwrap_or(None),
    }
}
