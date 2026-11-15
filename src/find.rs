//! Find printers on the LAN (SPEC section 3): an mDNS browse per up IPv4 adapter, and a port
//! probe (9100, 631, 515) of each adapter's subnet (a /24 or smaller whole; a larger one only in
//! the /24 around this PC), 64 connects in flight, 400 ms each, paced. Responders are named by
//! IPP's `printer-make-and-model` or SNMP's `sysDescr`, then ARP and the OUI table give the MAC
//! and its maker. Each found device is matched to an installed printer: the same IP (it is that
//! printer), the same MAC (the same printer at a new address), the same model ("maybe").
//!
//! The merge and the matching are plain Rust; `run` drives a `probe::Net`.

use crate::mdns::Announced;
use crate::net::{Adapter, Mac};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub const PORTS: [u16; 3] = [9100, 631, 515];
pub const IN_FLIGHT: usize = 64;
pub const CONNECT_WAIT: Duration = Duration::from_millis(400);
/// At most one connect starts per PACE (a /24 times three ports: about 2.3 s of starts).
pub const PACE: Duration = Duration::from_millis(3);
/// The most responders named in one Find (IPP or SNMP each).
pub const MAX_NAMED: usize = 64;

/// One device Find found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Found {
    pub ip: Option<Ipv4Addr>,
    pub v6: Vec<Ipv6Addr>,
    /// The mDNS instance, else IPP's printer-name, else SNMP's sysName.
    pub name: String,
    pub model: Option<String>,
    pub mac: Option<Mac>,
    /// The MAC's maker (OUI), short.
    pub maker: Option<String>,
    /// mDNS service types ("_ipp._tcp").
    pub services: Vec<String>,
    /// Open printer ports.
    pub ports: Vec<u16>,
    /// The IPP path to use (mDNS `rp`).
    pub rp: Option<String>,
    pub adminurl: Option<String>,
    pub uuid: Option<String>,
    pub note: Option<String>,
}

impl Found {
    /// What answered: "mDNS: IPP, IPPS · ports 9100, 631".
    pub fn answered_words(&self) -> String {
        let mut parts = Vec::new();
        if !self.services.is_empty() {
            let s: Vec<&str> = self
                .services
                .iter()
                .map(|s| match s.as_str() {
                    "_ipp._tcp" => "IPP",
                    "_ipps._tcp" => "IPPS",
                    "_printer._tcp" => "LPR",
                    "_pdl-datastream._tcp" => "RAW",
                    _ => "other",
                })
                .collect();
            parts.push(format!("mDNS: {}", s.join(", ")));
        }
        if !self.ports.is_empty() {
            parts.push(format!("ports {}", self.ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")));
        }
        parts.join(" · ")
    }

    /// The name shown: the name, else the model, else the address.
    pub fn title(&self) -> String {
        if !self.name.is_empty() {
            return self.name.clone();
        }
        self.model.clone().or(self.ip.map(|i| i.to_string())).unwrap_or_else(|| "Unnamed device".into())
    }
}

/// What one sweep responder said when asked its name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Named {
    pub model: Option<String>,
    pub name: Option<String>,
    pub uuid: Option<String>,
}

/// Put together what mDNS announced and what the sweep found, by IPv4 address (an announcement
/// without one stands alone).
pub fn merge(announced: Vec<Announced>, open: &[(Ipv4Addr, u16)], named: &BTreeMap<Ipv4Addr, Named>, macs: &BTreeMap<Ipv4Addr, Mac>) -> Vec<Found> {
    let mut by_ip: BTreeMap<Ipv4Addr, Found> = BTreeMap::new();
    let mut alone: Vec<Found> = Vec::new();
    for a in announced {
        let ip = a.ipv4();
        let f = Found {
            ip,
            v6: a.v6.clone(),
            name: a.instance.clone(),
            model: a.model(),
            services: a.services.clone(),
            rp: a.txt.get("rp").cloned().filter(|s| !s.is_empty()),
            adminurl: a.txt.get("adminurl").cloned().filter(|s| !s.is_empty()),
            uuid: a.txt.get("UUID").cloned().filter(|s| !s.is_empty()),
            note: a.txt.get("note").cloned().filter(|s| !s.is_empty()),
            ..Found::default()
        };
        match ip {
            Some(ip) => {
                let e = by_ip.entry(ip).or_insert_with(|| Found { ip: Some(ip), ..Found::default() });
                for s in &f.services {
                    if !e.services.contains(s) {
                        e.services.push(s.clone());
                    }
                }
                if e.name.is_empty() {
                    e.name = f.name;
                }
                e.model = e.model.take().or(f.model);
                e.rp = e.rp.take().or(f.rp);
                e.adminurl = e.adminurl.take().or(f.adminurl);
                e.uuid = e.uuid.take().or(f.uuid);
                e.note = e.note.take().or(f.note);
                for v in f.v6 {
                    if !e.v6.contains(&v) {
                        e.v6.push(v);
                    }
                }
            }
            None => alone.push(f),
        }
    }
    for (ip, port) in open {
        let e = by_ip.entry(*ip).or_insert_with(|| Found { ip: Some(*ip), ..Found::default() });
        if !e.ports.contains(port) {
            e.ports.push(*port);
        }
    }
    for (ip, n) in named {
        if let Some(e) = by_ip.get_mut(ip) {
            if e.model.is_none() {
                e.model = n.model.clone();
            }
            if e.name.is_empty() {
                e.name = n.name.clone().unwrap_or_default();
            }
            if e.uuid.is_none() {
                e.uuid = n.uuid.clone();
            }
        }
    }
    for (ip, m) in macs {
        if let Some(e) = by_ip.get_mut(ip) {
            e.mac = Some(*m);
            let maker = crate::oui::lookup(m).short();
            e.maker = (!maker.is_empty()).then_some(maker);
        }
    }
    let mut out: Vec<Found> = by_ip.into_values().chain(alone).collect();
    for f in &mut out {
        f.ports.sort_unstable();
        f.services.sort();
        f.name = crate::text::clean_max(&f.name, 120);
        f.model = f.model.as_deref().map(|m| crate::text::clean_max(m, 120)).filter(|m| !m.is_empty());
    }
    out
}

/// An installed printer, as the matching sees it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Installed {
    pub name: Vec<u16>,
    pub display: String,
    pub ip: Option<IpAddr>,
    pub mac: Option<Mac>,
    /// What it is: its driver's name, and the model it told when it answered.
    pub models: Vec<String>,
    /// It answered at its own address in the last probe (None: not asked or not network).
    pub answers: Option<bool>,
    /// A Standard TCP/IP or WSD port (so "Point it here" applies).
    pub pointable: bool,
    /// What Windows knows of its device (a device at its address must match it: AUDIT-1
    /// PRINT-3).
    pub known: crate::status::Known,
}

/// How a found device relates to the installed printers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Match {
    /// Same IP: it is that printer (or nothing Windows knows says otherwise).
    Same(usize),
    /// Same IP, but its identity is not that printer's: a different device answers there.
    NotIt(usize),
    /// Same MAC at another address: that printer moved here.
    Moved(usize),
    /// Same model: maybe that printer.
    Maybe(usize),
    None,
}

impl Match {
    pub fn printer(&self) -> Option<usize> {
        match self {
            Match::Same(i) | Match::NotIt(i) | Match::Moved(i) | Match::Maybe(i) => Some(*i),
            Match::None => None,
        }
    }
}

/// The device a found one is, as the identity check sees it.
fn device_of(f: &Found) -> crate::status::Device<'_> {
    crate::status::Device { mac: f.mac, uuid: f.uuid.as_deref(), serial: None, model: f.model.as_deref() }
}

/// The match for `f` among `installed`: the same IP first (when its identity does not say it
/// is another device), then the same MAC, then the model; a device only at another printer's
/// address is "not it".
pub fn match_found(f: &Found, installed: &[Installed]) -> Match {
    let same_ip: Vec<usize> = installed.iter().enumerate().filter(|(_, p)| p.ip.is_some_and(|a| f.ip.is_some_and(|ip| a == IpAddr::V4(ip)) || f.v6.iter().any(|v| IpAddr::V6(*v) == a))).map(|(i, _)| i).collect();
    if let Some(&i) = same_ip.iter().find(|&&i| !matches!(crate::status::ident(&installed[i].known, &device_of(f)), crate::status::Ident::Other(_))) {
        return Match::Same(i);
    }
    if let Some(m) = f.mac
        && let Some(i) = installed.iter().position(|p| p.mac == Some(m))
    {
        return Match::Moved(i);
    }
    if let Some(model) = &f.model {
        // A printer that answers where it is would not be this one.
        let candidates: Vec<usize> = installed.iter().enumerate().filter(|(_, p)| p.answers != Some(true) && p.models.iter().any(|m| crate::drivers::fits(model, m) || crate::drivers::fits(m, model))).map(|(i, _)| i).collect();
        if let Some(&i) = candidates.first() {
            return Match::Maybe(i);
        }
    }
    match same_ip.first() {
        Some(&i) => Match::NotIt(i),
        None => Match::None,
    }
}

/// The match in words, as the results panel says it.
pub fn match_words(f: &Found, m: &Match, installed: &[Installed]) -> String {
    let at = f.ip.map(|i| i.to_string()).unwrap_or_else(|| "an unknown address".into());
    match m {
        Match::Same(i) => match crate::status::ident(&installed[*i].known, &device_of(f)) {
            crate::status::Ident::Same => format!("This is '{}'.", installed[*i].display),
            _ => format!("'{}' points at this address (not confirmed as the same printer).", installed[*i].display),
        },
        Match::NotIt(i) => format!("'{}' points at this address, but this is a different device: '{}' is not here.", installed[*i].display, installed[*i].display),
        Match::Moved(i) => {
            let p = &installed[*i];
            match p.ip {
                Some(old) => format!("The same printer as '{}', at a new address: it points at {old}.", p.display),
                None => format!("The same printer as '{}' (same MAC address).", p.display),
            }
        }
        Match::Maybe(i) => {
            let p = &installed[*i];
            let model = f.model.clone().unwrap_or_default();
            match (p.ip, p.answers) {
                (Some(old), Some(false)) => format!("A {model} answers at {at}; your '{}' points at {old}, which does not answer. Point it at {}?", p.display, short_ip(f.ip)),
                (Some(old), _) => format!("A {model} answers at {at}; your '{}' points at {old}. Maybe the same printer.", p.display),
                (None, _) => format!("A {model} answers at {at}; maybe your '{}'.", p.display),
            }
        }
        Match::None => "Not installed on this PC.".into(),
    }
}

/// ".77" of 192.168.1.77, as the spec writes a neighbour on the same /24.
fn short_ip(ip: Option<Ipv4Addr>) -> String {
    ip.map(|i| format!(".{}", i.octets()[3])).unwrap_or_default()
}

/// What a Find run found and what it searched.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Results {
    pub found: Vec<Found>,
    /// "searched 192.168.1.0/24", "mDNS only on Ethernet (link-local)".
    pub searched: Vec<String>,
    /// It was stopped before the end: what came is partial.
    pub stopped: bool,
}

/// Find, over `net`, on `adapters`. `stop` ends it early (what came counts, said as partial).
pub fn run(net: &dyn crate::probe::Net, adapters: &[Adapter], stop: &AtomicBool) -> Results {
    let mut searched = Vec::new();
    let mut pairs: Vec<(Ipv4Addr, u16)> = Vec::new();
    let mut seen_nets = Vec::new();
    for a in adapters {
        match crate::net::sweep_net(a) {
            Some((n, words)) if !seen_nets.contains(&n) => {
                seen_nets.push(n);
                searched.push(format!("{} ({})", words, crate::text::clean_max(&a.name, 40)));
                let (lo, hi) = n.hosts();
                for v in lo..=hi {
                    let ip = Ipv4Addr::from(v);
                    if ip == a.addr {
                        continue;
                    }
                    for p in PORTS {
                        pairs.push((ip, p));
                    }
                }
            }
            Some(_) => {}
            None => searched.push(format!("mDNS only on {} ({})", crate::text::clean_max(&a.name, 40), if a.link_local() { "link-local" } else { "no subnet to search" })),
        }
    }
    let halt = || stop.load(Ordering::SeqCst);
    // mDNS on every adapter while the sweep runs.
    let (announced, open) = std::thread::scope(|s| {
        let browses: Vec<_> = adapters.iter().map(|a| s.spawn(move || net.browse(a.addr, &|| stop.load(Ordering::SeqCst)))).collect();
        let open = net.sweep(&pairs, &halt);
        let mut all = Vec::new();
        for b in browses {
            all.extend(b.join().unwrap_or_default());
        }
        (all, open)
    });
    // Name the sweep's responders: IPP when 631 is open, else SNMP; and their MACs on-link.
    let mut responders: Vec<Ipv4Addr> = open.iter().map(|x| x.0).collect();
    responders.sort_unstable();
    responders.dedup();
    responders.truncate(MAX_NAMED);
    let rp: BTreeMap<Ipv4Addr, String> = announced.iter().filter_map(|a| Some((a.ipv4()?, a.txt.get("rp")?.clone()))).collect();
    let (named, macs) = std::thread::scope(|s| {
        let jobs: Vec<_> = responders
            .iter()
            .map(|&ip| {
                let has631 = open.contains(&(ip, 631));
                let path = rp.get(&ip).and_then(|r| crate::ipp::path_of(r)).unwrap_or_else(|| crate::ipp::DEFAULT_PATH.into());
                s.spawn(move || {
                    if halt() {
                        return (ip, Named::default(), None);
                    }
                    let mut n = Named::default();
                    if has631 && let crate::ipp::Outcome::Answered(a) = net.ipp(std::net::SocketAddr::new(IpAddr::V4(ip), crate::ipp::PORT), &path) {
                        n = Named { model: a.make_model, name: a.name, uuid: a.uuid };
                    }
                    if n.model.is_none() && let crate::snmp::Outcome::Answered(s) = net.snmp(std::net::SocketAddr::new(IpAddr::V4(ip), crate::snmp::PORT), crate::snmp::COMMUNITY) {
                        n.model = s.descr;
                        n.name = n.name.or(s.name);
                    }
                    (ip, n, net.arp(ip))
                })
            })
            .collect();
        let mut named = BTreeMap::new();
        let mut macs = BTreeMap::new();
        for j in jobs {
            if let Ok((ip, n, mac)) = j.join() {
                named.insert(ip, n);
                if let Some(m) = mac {
                    macs.insert(ip, m);
                }
            }
        }
        (named, macs)
    });
    Results { found: merge(announced, &open, &named, &macs), searched, stopped: halt() }
}

/// The sweep, for real: non-blocking connects to `pairs`, at most `IN_FLIGHT` at once, each given
/// `CONNECT_WAIT`, one started per `PACE`; closed with a reset. The open (address, port) pairs.
pub fn sweep(pairs: &[(Ipv4Addr, u16)], stop: &dyn Fn() -> bool) -> Vec<(Ipv4Addr, u16)> {
    use std::time::Instant;
    use windows_sys::Win32::Networking::WinSock::*;
    crate::net::winsock();
    let mut open = Vec::new();
    let mut queue: Vec<(Ipv4Addr, u16)> = pairs.to_vec();
    queue.reverse();
    let mut live: Vec<(SOCKET, Ipv4Addr, u16, Instant)> = Vec::new();
    let close = |s: SOCKET| {
        let l = LINGER { l_onoff: 1, l_linger: 0 };
        // SAFETY: a socket this function opened; closed once.
        unsafe {
            setsockopt(s, SOL_SOCKET, SO_LINGER, (&l as *const LINGER).cast(), size_of::<LINGER>() as i32);
            closesocket(s);
        }
    };
    // Paced by budget: the starts due since the sweep began (one per PACE on average). A sleep
    // or a select of 3 ms lasts a whole 15.6 ms timer tick on Windows, so pausing between single
    // starts would make the sweep five times slower (measured: 4.3 s for a /24 on one port).
    let began = Instant::now();
    let mut started: u128 = 0;
    loop {
        if stop() {
            break;
        }
        let due = began.elapsed().as_micros() / PACE.as_micros() + 1;
        while live.len() < IN_FLIGHT
            && started < due
            && let Some((ip, port)) = queue.pop()
        {
            started += 1;
            // SAFETY: plain socket calls on a socket this loop owns.
            unsafe {
                let s = socket(AF_INET as i32, SOCK_STREAM, IPPROTO_TCP);
                if s == INVALID_SOCKET {
                    continue;
                }
                let mut nb: u32 = 1;
                ioctlsocket(s, FIONBIO, &mut nb);
                let mut sa: SOCKADDR_IN = std::mem::zeroed();
                sa.sin_family = AF_INET;
                sa.sin_port = port.to_be();
                sa.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
                let r = connect(s, (&sa as *const SOCKADDR_IN).cast(), size_of::<SOCKADDR_IN>() as i32);
                if r == 0 {
                    open.push((ip, port));
                    close(s);
                } else if WSAGetLastError() == WSAEWOULDBLOCK {
                    live.push((s, ip, port, Instant::now()));
                } else {
                    close(s);
                }
            }
        }
        if live.is_empty() && queue.is_empty() {
            break;
        }
        if live.is_empty() {
            std::thread::sleep(PACE);
            continue;
        }
        // SAFETY: FD_SET structs filled with live sockets (at most 64, the struct's size).
        unsafe {
            let mut w: FD_SET = std::mem::zeroed();
            let mut e: FD_SET = std::mem::zeroed();
            for (i, (s, ..)) in live.iter().take(64).enumerate() {
                w.fd_array[i] = *s;
                e.fd_array[i] = *s;
            }
            w.fd_count = live.len().min(64) as u32;
            e.fd_count = w.fd_count;
            let tv = TIMEVAL { tv_sec: 0, tv_usec: PACE.as_micros() as i32 };
            select(0, std::ptr::null_mut(), &mut w, &mut e, &tv);
            let in_set = |set: &FD_SET, s: SOCKET| set.fd_array[..set.fd_count as usize].contains(&s);
            let mut i = 0;
            while i < live.len() {
                let (s, ip, port, t0) = live[i];
                let done = if in_set(&w, s) {
                    open.push((ip, port));
                    true
                } else {
                    in_set(&e, s) || t0.elapsed() >= CONNECT_WAIT
                };
                if done {
                    close(s);
                    live.swap_remove(i);
                } else {
                    i += 1;
                }
            }
        }
    }
    for (s, ..) in live.drain(..) {
        close(s);
    }
    open.sort_unstable();
    open
}
