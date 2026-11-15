//! Printers that announce themselves: an mDNS browse (RFC 6762/6763) for `_ipp._tcp`,
//! `_ipps._tcp`, `_printer._tcp` and `_pdl-datastream._tcp`, sent to 224.0.0.251:5353 from an
//! ephemeral port out of each adapter (legacy unicast: responders answer us directly, RFC 6762
//! section 6.7). PTR, SRV, TXT, A and AAAA records are taken from answers and additional records
//! for 3 s; an instance missing its SRV or a host missing its address is asked about once more.
//!
//! The message code is VibeScan's (`names.rs`): every length and pointer is checked, compression
//! pointers must point backwards (so no loop can be built), names are at most 255 bytes, and
//! everything that comes back is cleaned before anyone sees it.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
/// The most host names one Find keeps addresses for.
pub const MAX_HOSTS: usize = 1024;
pub const TYPE_SRV: u16 = 33;

/// The printer service types browsed.
pub const SERVICES: [&str; 4] = ["_ipp._tcp.local", "_ipps._tcp.local", "_printer._tcp.local", "_pdl-datastream._tcp.local"];
/// The TXT keys kept.
pub const TXT_KEYS: [&str; 8] = ["ty", "product", "rp", "UUID", "adminurl", "note", "usb_MFG", "usb_MDL"];

pub const LISTEN: Duration = Duration::from_secs(3);
pub const FOLLOW_UP: Duration = Duration::from_millis(1200);

/// Why a packet was not taken.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Bad {
    Truncated,
    /// A compression pointer that does not point backwards (the only way to build a loop).
    Pointer,
    /// A label type other than a plain label or a pointer.
    Label,
    /// A name longer than DNS allows (255 bytes on the wire).
    TooLong,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RData {
    Ptr(String),
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Srv { port: u16, target: String },
    Txt(Vec<Vec<u8>>),
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub data: RData,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub response: bool,
    /// Answers, authority and additional records together.
    pub records: Vec<Record>,
}

fn u16_at(b: &[u8], i: usize) -> Result<u16, Bad> {
    b.get(i..i + 2).map(|s| u16::from_be_bytes([s[0], s[1]])).ok_or(Bad::Truncated)
}

/// A (possibly compressed) name starting at `pos`: the name, dotted, and where the bytes after
/// it start. Pointers must point strictly before the label they replace, which makes loops
/// impossible; the whole name may not exceed 255 bytes. A label's bytes are kept as they came
/// (lossy UTF-8): an instance name may hold dots and spaces.
pub fn read_name(b: &[u8], pos: usize) -> Result<(String, usize), Bad> {
    let mut labels: Vec<String> = Vec::new();
    let mut at = pos;
    let mut after: Option<usize> = None;
    let mut wire_len = 0usize;
    let mut limit = pos;
    loop {
        let len = *b.get(at).ok_or(Bad::Truncated)? as usize;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    let next = after.unwrap_or(at + 1);
                    return Ok((labels.join("."), next));
                }
                let label = b.get(at + 1..at + 1 + len).ok_or(Bad::Truncated)?;
                wire_len += len + 1;
                if wire_len > 255 {
                    return Err(Bad::TooLong);
                }
                labels.push(String::from_utf8_lossy(label).into_owned());
                at += len + 1;
            }
            0xC0 => {
                let target = (u16_at(b, at)? & 0x3FFF) as usize;
                if target >= limit {
                    return Err(Bad::Pointer);
                }
                if after.is_none() {
                    after = Some(at + 2);
                }
                limit = target;
                at = target;
            }
            _ => return Err(Bad::Label),
        }
    }
}

/// A DNS message: its header and every record (questions skipped). One record that does not
/// parse makes the whole message bad.
pub fn parse_message(b: &[u8]) -> Result<Message, Bad> {
    let id = u16_at(b, 0)?;
    let flags = u16_at(b, 2)?;
    let qd = u16_at(b, 4)? as usize;
    let rr = u16_at(b, 6)? as usize + u16_at(b, 8)? as usize + u16_at(b, 10)? as usize;
    let mut at = 12;
    for _ in 0..qd {
        let (_, next) = read_name(b, at)?;
        at = next + 4;
        if at > b.len() {
            return Err(Bad::Truncated);
        }
    }
    let mut records = Vec::new();
    for _ in 0..rr {
        let (name, next) = read_name(b, at)?;
        let rtype = u16_at(b, next)?;
        let rdlen = u16_at(b, next + 8)? as usize;
        let start = next + 10;
        let end = start + rdlen;
        if end > b.len() {
            return Err(Bad::Truncated);
        }
        let data = match rtype {
            TYPE_PTR => {
                let (target, used) = read_name(b, start)?;
                if used > end {
                    return Err(Bad::Truncated);
                }
                RData::Ptr(target)
            }
            TYPE_A if rdlen == 4 => RData::A(Ipv4Addr::new(b[start], b[start + 1], b[start + 2], b[start + 3])),
            TYPE_AAAA if rdlen == 16 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&b[start..end]);
                RData::Aaaa(Ipv6Addr::from(o))
            }
            TYPE_SRV => {
                if rdlen < 7 {
                    return Err(Bad::Truncated);
                }
                let port = u16_at(b, start + 4)?;
                let (target, used) = read_name(b, start + 6)?;
                if used > end {
                    return Err(Bad::Truncated);
                }
                RData::Srv { port, target }
            }
            TYPE_TXT => {
                let mut strings = Vec::new();
                let mut i = start;
                while i < end {
                    let l = b[i] as usize;
                    let s = b.get(i + 1..i + 1 + l).filter(|_| i + 1 + l <= end).ok_or(Bad::Truncated)?;
                    strings.push(s.to_vec());
                    i += 1 + l;
                }
                RData::Txt(strings)
            }
            _ => RData::Other,
        };
        records.push(Record { name, rtype, data });
        if records.len() > 512 {
            break;
        }
        at = end;
    }
    Ok(Message { id, response: flags & 0x8000 != 0, records })
}

/// A query with one question per (name, type), each with the QU bit (answer me directly).
pub fn build_query(id: u16, questions: &[(&str, u16)]) -> Vec<u8> {
    let mut q = Vec::with_capacity(160);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0, 0]);
    q.extend_from_slice(&(questions.len() as u16).to_be_bytes());
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for (name, qtype) in questions {
        for label in split_name(name) {
            let l = &label.as_bytes()[..label.len().min(63)];
            q.push(l.len() as u8);
            q.extend_from_slice(l);
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&0x8001u16.to_be_bytes());
    }
    q
}

/// A name's labels: an instance name ("Brother HL-L2350DW series._ipp._tcp.local") keeps its
/// own dots in its first label, which ends where the service type begins.
fn split_name(name: &str) -> Vec<String> {
    let lower = name.to_ascii_lowercase();
    for svc in SERVICES {
        let tail = format!(".{svc}");
        if lower.ends_with(&tail) && name.len() > tail.len() {
            let inst = &name[..name.len() - tail.len()];
            let mut v = vec![inst.to_string()];
            v.extend(svc.split('.').map(str::to_string));
            return v;
        }
    }
    name.split('.').filter(|l| !l.is_empty()).map(str::to_string).collect()
}

/// A printer that announced itself (one instance of one service type).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Announced {
    /// "Brother HL-L2350DW series" (the instance's own label).
    pub instance: String,
    /// "_ipp._tcp", ...
    pub services: Vec<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub v4: Vec<Ipv4Addr>,
    pub v6: Vec<Ipv6Addr>,
    /// The kept TXT keys and their values (cleaned).
    pub txt: BTreeMap<String, String>,
    /// The address the answer came from.
    pub from: Option<IpAddr>,
}

impl Announced {
    /// The model as announced: `ty`, else `product` without its parentheses, else usb_MFG +
    /// usb_MDL.
    pub fn model(&self) -> Option<String> {
        if let Some(t) = self.txt.get("ty").filter(|t| !t.is_empty()) {
            return Some(t.clone());
        }
        if let Some(p) = self.txt.get("product").map(|p| p.trim_start_matches('(').trim_end_matches(')').trim().to_string()).filter(|p| !p.is_empty()) {
            return Some(p);
        }
        match (self.txt.get("usb_MFG"), self.txt.get("usb_MDL")) {
            (Some(m), Some(d)) if !d.is_empty() => Some(if d.to_ascii_lowercase().starts_with(&m.to_ascii_lowercase()) { d.clone() } else { format!("{m} {d}") }),
            (_, Some(d)) if !d.is_empty() => Some(d.clone()),
            _ => None,
        }
    }

    /// The first IPv4 address, else the address the answer came from.
    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        self.v4.first().copied().or(match self.from {
            Some(IpAddr::V4(a)) => Some(a),
            _ => None,
        })
    }
}

/// The service type of an instance name, and the instance's label: "X._ipp._tcp.local" ->
/// ("X", "_ipp._tcp").
pub fn split_instance(name: &str) -> Option<(String, String)> {
    let lower = name.to_ascii_lowercase();
    for svc in SERVICES {
        let tail = format!(".{svc}");
        if lower.ends_with(&tail) && name.len() > tail.len() {
            return Some((crate::text::clean(&name[..name.len() - tail.len()]), svc.trim_end_matches(".local").to_string()));
        }
    }
    None
}

/// Everything the browse heard, gathered by instance name (lower case).
#[derive(Clone, Debug, Default)]
pub struct Gathered {
    /// instance name (lower case) -> what is known of it
    pub instances: BTreeMap<String, Announced>,
    /// host name (lower case) -> addresses
    pub hosts: BTreeMap<String, (Vec<Ipv4Addr>, Vec<Ipv6Addr>)>,
}

impl Gathered {
    /// Take the records of one response that came from `from`.
    pub fn take(&mut self, m: &Message, from: IpAddr) {
        if !m.response {
            return;
        }
        for r in &m.records {
            match &r.data {
                RData::Ptr(target) if SERVICES.iter().any(|s| r.name.eq_ignore_ascii_case(s)) => {
                    if let Some((inst, svc)) = split_instance(target) {
                        let e = self.instance(target, &inst);
                        if !e.services.contains(&svc) {
                            e.services.push(svc);
                        }
                        e.from.get_or_insert(from);
                    }
                }
                RData::Srv { port, target } => {
                    if let Some((inst, svc)) = split_instance(&r.name) {
                        let e = self.instance(&r.name, &inst);
                        if !e.services.contains(&svc) {
                            e.services.push(svc);
                        }
                        e.host = Some(crate::text::clean(target).trim_end_matches('.').to_string());
                        e.port = Some(*port);
                        e.from.get_or_insert(from);
                    }
                }
                RData::Txt(strings) => {
                    if let Some((inst, _)) = split_instance(&r.name) {
                        let e = self.instance(&r.name, &inst);
                        for s in strings.iter().take(64) {
                            let s = String::from_utf8_lossy(s);
                            let Some((k, v)) = s.split_once('=') else { continue };
                            if let Some(key) = TXT_KEYS.iter().find(|t| t.eq_ignore_ascii_case(k)) {
                                e.txt.entry(key.to_string()).or_insert_with(|| crate::text::clean_max(v, 200));
                            }
                        }
                    }
                }
                RData::A(a) => {
                    if let Some(h) = self.host(&r.name)
                        && !h.0.contains(a)
                        && h.0.len() < 8
                    {
                        h.0.push(*a);
                    }
                }
                RData::Aaaa(a) => {
                    if let Some(h) = self.host(&r.name)
                        && !h.1.contains(a)
                        && h.1.len() < 8
                    {
                        h.1.push(*a);
                    }
                }
                _ => {}
            }
        }
    }

    /// A host's addresses; a flood of new names past `MAX_HOSTS` is dropped (AUDIT-1 PRINT-11).
    fn host(&mut self, name: &str) -> Option<&mut (Vec<Ipv4Addr>, Vec<Ipv6Addr>)> {
        let key = name.to_ascii_lowercase();
        if self.hosts.len() >= MAX_HOSTS && !self.hosts.contains_key(&key) {
            return None;
        }
        Some(self.hosts.entry(key).or_default())
    }

    fn instance(&mut self, full: &str, inst: &str) -> &mut Announced {
        let n = self.instances.len();
        let key = full.to_ascii_lowercase();
        if n >= 256 && !self.instances.contains_key(&key) {
            // A flood of instances: the rest go into one bin, never more memory.
            return self.instances.entry("~".into()).or_default();
        }
        self.instances.entry(key).or_insert_with(|| Announced { instance: inst.to_string(), ..Announced::default() })
    }

    /// What is still missing: instances without SRV (their full names) and hosts without an
    /// address.
    pub fn missing(&self) -> (Vec<String>, Vec<String>) {
        let mut srv = Vec::new();
        let mut addr = Vec::new();
        for (k, a) in &self.instances {
            if k == "~" {
                continue;
            }
            match &a.host {
                None => srv.push(k.clone()),
                Some(h) if !self.hosts.contains_key(&h.to_ascii_lowercase()) => addr.push(h.clone()),
                _ => {}
            }
        }
        (srv, addr)
    }

    /// The instances with their hosts' addresses filled in.
    pub fn finish(mut self) -> Vec<Announced> {
        let hosts = std::mem::take(&mut self.hosts);
        self.instances.remove("~");
        self.instances
            .into_values()
            .map(|mut a| {
                if let Some(h) = a.host.as_ref().and_then(|h| hosts.get(&h.to_ascii_lowercase())) {
                    a.v4 = h.0.clone();
                    a.v6 = h.1.clone();
                }
                a.services.sort();
                a
            })
            .collect()
    }
}

// ---------- the real browse ----------

fn query_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let seed = (std::process::id() as u16).wrapping_mul(40503);
    seed ^ NEXT.fetch_add(1, Ordering::Relaxed).wrapping_mul(7919)
}

/// A UDP socket on this computer's address `src` that sends multicast out of that adapter.
fn socket(src: Ipv4Addr) -> Option<UdpSocket> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{IN_ADDR, IP_MULTICAST_IF, IPPROTO_IP, setsockopt};
    crate::net::winsock();
    let sock = UdpSocket::bind(SocketAddrV4::new(src, 0)).ok()?;
    let _ = sock.set_multicast_ttl_v4(255);
    let _ = sock.set_multicast_loop_v4(false);
    let mut a: IN_ADDR = unsafe { std::mem::zeroed() };
    a.S_un.S_addr = u32::from_ne_bytes(src.octets());
    // SAFETY: a valid socket and an IN_ADDR of the size given.
    unsafe { setsockopt(sock.as_raw_socket() as usize, IPPROTO_IP, IP_MULTICAST_IF, (&a as *const IN_ADDR).cast(), size_of::<IN_ADDR>() as i32) };
    Some(sock)
}

const MDNS: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353);
/// Larger than any UDP datagram: Windows reports a longer one as an error, which would end the
/// listening early.
const BUF: usize = 65_536;

/// Send `query` and take every response from port 5353 into `g` until `wait` is over (or `stop`).
fn listen(sock: &UdpSocket, query: &[u8], wait: Duration, g: &mut Gathered, stop: &dyn Fn() -> bool) {
    if sock.send_to(query, MDNS).is_err() {
        return;
    }
    let t0 = Instant::now();
    let mut buf = vec![0u8; BUF];
    let mut resent = false;
    loop {
        let now = t0.elapsed();
        if now >= wait || stop() {
            return;
        }
        // Multicast on Wi-Fi gets lost: the question goes out once more after a third.
        if !resent && now >= wait / 3 {
            let _ = sock.send_to(query, MDNS);
            resent = true;
        }
        let step = (wait - now).min(Duration::from_millis(200)).max(Duration::from_millis(1));
        let _ = sock.set_read_timeout(Some(step));
        match sock.recv_from(&mut buf) {
            Ok((n, SocketAddr::V4(from))) if from.port() == 5353 => {
                if let Ok(m) = parse_message(&buf[..n]) {
                    g.take(&m, IpAddr::V4(*from.ip()));
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return,
        }
    }
}

/// The browse out of this computer's address `src`: 3 s of answers, then one follow-up for what
/// is missing. `stop` ends it early (what came counts).
pub fn browse(src: Ipv4Addr, stop: &dyn Fn() -> bool) -> Vec<Announced> {
    let Some(sock) = socket(src) else { return Vec::new() };
    let mut g = Gathered::default();
    let qs: Vec<(&str, u16)> = SERVICES.iter().map(|s| (*s, TYPE_PTR)).collect();
    listen(&sock, &build_query(query_id(), &qs), LISTEN, &mut g, stop);
    let (srv, addr) = g.missing();
    if !(srv.is_empty() && addr.is_empty()) && !stop() {
        let mut q: Vec<(String, u16)> = Vec::new();
        for i in srv.iter().take(16) {
            q.push((i.clone(), TYPE_SRV));
            q.push((i.clone(), TYPE_TXT));
        }
        for h in addr.iter().take(16) {
            q.push((h.clone(), TYPE_A));
        }
        let refs: Vec<(&str, u16)> = q.iter().map(|(n, t)| (n.as_str(), *t)).collect();
        listen(&sock, &build_query(query_id(), &refs), FOLLOW_UP, &mut g, stop);
    }
    g.finish()
}
