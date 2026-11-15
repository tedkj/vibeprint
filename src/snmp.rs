//! What a printer says over SNMP v1 (community `public`, UDP 161, 2 s, 2 tries): `sysDescr.0`,
//! `sysName.0`, and the Printer MIB's `hrPrinterStatus` and `hrPrinterDetectedErrorState` for the
//! first printer the agent lists (found by GETNEXT on their columns: the instance is not always
//! 1), and the Printer MIB's `prtGeneralSerialNumber` (the device's identity: AUDIT-1 R-PRINT-1,
//! asked on its own so an agent without it loses nothing else). The BER encoder and the strict decoder are plain Rust: every length is checked against
//! what is left, nothing indefinite, integers and OID arcs bounded, and every string is cleaned
//! before anyone sees it.

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

pub const PORT: u16 = 161;
pub const COMMUNITY: &str = "public";
pub const WAIT: Duration = Duration::from_secs(2);
pub const TRIES: usize = 2;

pub const SYS_DESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
pub const SYS_NAME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];
/// hrPrinterStatus and hrPrinterDetectedErrorState: the columns (an instance follows).
pub const HR_PRINTER_STATUS: &[u32] = &[1, 3, 6, 1, 2, 1, 25, 3, 5, 1, 1];
pub const HR_PRINTER_ERRORS: &[u32] = &[1, 3, 6, 1, 2, 1, 25, 3, 5, 1, 2];
/// prtGeneralSerialNumber (RFC 3805): the column (an instance follows).
pub const PRT_GENERAL_SERIAL: &[u32] = &[1, 3, 6, 1, 2, 1, 43, 5, 1, 1, 17];

const T_INTEGER: u8 = 0x02;
const T_OCTETS: u8 = 0x04;
const T_NULL: u8 = 0x05;
const T_OID: u8 = 0x06;
const T_SEQUENCE: u8 = 0x30;
pub const PDU_GET: u8 = 0xA0;
pub const PDU_GETNEXT: u8 = 0xA1;
const PDU_RESPONSE: u8 = 0xA2;

/// Why a packet was not taken.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Bad {
    Truncated,
    /// A length form BER allows but SNMP never needs (indefinite, more than 4 bytes).
    Length,
    /// A tag where another was due.
    Tag(u8),
    /// An integer or OID arc too large, an OID too long.
    TooBig,
}

/// One value of a variable binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Octets(Vec<u8>),
    Oid(Vec<u32>),
    Null,
    /// Counter, Gauge, TimeTicks, IpAddress, an exception: not needed by the app.
    Other(u8),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub community: Vec<u8>,
    pub request_id: i64,
    /// 0 noError, 1 tooBig, 2 noSuchName, 3 badValue, 4 readOnly, 5 genErr.
    pub error_status: i64,
    pub error_index: i64,
    pub bindings: Vec<(Vec<u32>, Value)>,
}

// ---------- the encoder ----------

fn push_len(out: &mut Vec<u8>, n: usize) {
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend_from_slice(&[0x81, n as u8]);
    } else {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    push_len(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

fn int(v: i64) -> Vec<u8> {
    let b = v.to_be_bytes();
    // The shortest two's complement form.
    let mut i = 0;
    while i < 7 && ((b[i] == 0 && b[i + 1] & 0x80 == 0) || (b[i] == 0xFF && b[i + 1] & 0x80 != 0)) {
        i += 1;
    }
    tlv(T_INTEGER, &b[i..])
}

fn oid(arcs: &[u32]) -> Vec<u8> {
    let mut c = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &a in &arcs[2..] {
        let mut tmp = Vec::new();
        let mut v = a;
        tmp.push((v & 0x7F) as u8);
        v >>= 7;
        while v > 0 {
            tmp.push(0x80 | (v & 0x7F) as u8);
            v >>= 7;
        }
        tmp.reverse();
        c.extend_from_slice(&tmp);
    }
    tlv(T_OID, &c)
}

/// A GET or GETNEXT (`pdu`) for `oids`, version 1, community `community`.
pub fn request(pdu: u8, request_id: i32, community: &str, oids: &[&[u32]]) -> Vec<u8> {
    let mut binds = Vec::new();
    for o in oids {
        let mut vb = oid(o);
        vb.extend_from_slice(&tlv(T_NULL, &[]));
        binds.extend_from_slice(&tlv(T_SEQUENCE, &vb));
    }
    let mut p = int(request_id as i64);
    p.extend_from_slice(&int(0));
    p.extend_from_slice(&int(0));
    p.extend_from_slice(&tlv(T_SEQUENCE, &binds));
    let mut m = int(0); // version-1
    m.extend_from_slice(&tlv(T_OCTETS, community.as_bytes()));
    m.extend_from_slice(&tlv(pdu, &p));
    tlv(T_SEQUENCE, &m)
}

// ---------- the decoder ----------

/// One TLV at `at`: (tag, content start, content end). The length must fit what is left.
fn read_tlv(b: &[u8], at: usize, end: usize) -> Result<(u8, usize, usize), Bad> {
    if at >= end {
        return Err(Bad::Truncated);
    }
    let tag = b[at];
    let l0 = *b.get(at + 1).filter(|_| at + 1 < end).ok_or(Bad::Truncated)?;
    let (len, start) = if l0 < 0x80 {
        (l0 as usize, at + 2)
    } else {
        let n = (l0 & 0x7F) as usize;
        if n == 0 || n > 4 {
            return Err(Bad::Length);
        }
        if at + 2 + n > end {
            return Err(Bad::Truncated);
        }
        let len = b[at + 2..at + 2 + n].iter().fold(0usize, |a, &x| (a << 8) | x as usize);
        (len, at + 2 + n)
    };
    let stop = start.checked_add(len).ok_or(Bad::Length)?;
    if stop > end {
        return Err(Bad::Truncated);
    }
    Ok((tag, start, stop))
}

fn expect(b: &[u8], at: usize, end: usize, tag: u8) -> Result<(usize, usize), Bad> {
    let (t, s, e) = read_tlv(b, at, end)?;
    if t != tag {
        return Err(Bad::Tag(t));
    }
    Ok((s, e))
}

fn read_int(c: &[u8]) -> Result<i64, Bad> {
    if c.is_empty() {
        return Err(Bad::Truncated);
    }
    if c.len() > 8 {
        return Err(Bad::TooBig);
    }
    let mut v: i64 = if c[0] & 0x80 != 0 { -1 } else { 0 };
    for &x in c {
        v = (v << 8) | x as i64;
    }
    Ok(v)
}

fn read_oid(c: &[u8]) -> Result<Vec<u32>, Bad> {
    if c.is_empty() {
        return Err(Bad::Truncated);
    }
    let mut out = Vec::with_capacity(16);
    let mut acc: u64 = 0;
    let mut first = true;
    let mut pending = false;
    for &x in c {
        acc = (acc << 7) | (x & 0x7F) as u64;
        if acc > u32::MAX as u64 {
            return Err(Bad::TooBig);
        }
        pending = true;
        if x & 0x80 == 0 {
            if first {
                let a = acc as u32;
                let (x0, x1) = if a < 40 { (0, a) } else if a < 80 { (1, a - 40) } else { (2, a - 80) };
                out.push(x0);
                out.push(x1);
                first = false;
            } else {
                out.push(acc as u32);
            }
            if out.len() > 128 {
                return Err(Bad::TooBig);
            }
            acc = 0;
            pending = false;
        }
    }
    if pending {
        return Err(Bad::Truncated);
    }
    Ok(out)
}

/// A GetResponse.
pub fn parse(b: &[u8]) -> Result<Response, Bad> {
    let (s, e) = expect(b, 0, b.len(), T_SEQUENCE)?;
    let (vs, ve) = expect(b, s, e, T_INTEGER)?;
    if read_int(&b[vs..ve])? != 0 {
        return Err(Bad::Tag(T_INTEGER)); // not version-1
    }
    let (cs, ce) = expect(b, ve, e, T_OCTETS)?;
    let (ps, pe) = expect(b, ce, e, PDU_RESPONSE)?;
    let (rs, re) = expect(b, ps, pe, T_INTEGER)?;
    let (es, ee) = expect(b, re, pe, T_INTEGER)?;
    let (is, ie) = expect(b, ee, pe, T_INTEGER)?;
    let (ls, le) = expect(b, ie, pe, T_SEQUENCE)?;
    let mut bindings = Vec::new();
    let mut at = ls;
    while at < le {
        let (bs, be) = expect(b, at, le, T_SEQUENCE)?;
        let (os, oe) = expect(b, bs, be, T_OID)?;
        let name = read_oid(&b[os..oe])?;
        let (t, s2, e2) = read_tlv(b, oe, be)?;
        let value = match t {
            T_INTEGER => Value::Int(read_int(&b[s2..e2])?),
            T_OCTETS => Value::Octets(b[s2..e2].to_vec()),
            T_OID => Value::Oid(read_oid(&b[s2..e2])?),
            T_NULL => Value::Null,
            other => Value::Other(other),
        };
        bindings.push((name, value));
        if bindings.len() > 64 {
            return Err(Bad::TooBig);
        }
        at = be;
    }
    Ok(Response { community: b[cs..ce].to_vec(), request_id: read_int(&b[rs..re])?, error_status: read_int(&b[es..ee])?, error_index: read_int(&b[is..ie])?, bindings })
}

// ---------- the Printer MIB ----------

/// hrPrinterStatus in words.
pub fn status_words(s: i64) -> &'static str {
    match s {
        1 => "Other",
        2 => "Unknown",
        3 => "Idle",
        4 => "Printing",
        5 => "Warming up",
        _ => "Unknown",
    }
}

/// The bits of hrPrinterDetectedErrorState (bit 0 is the first octet's top bit), in words.
pub const ERROR_BITS: [&str; 16] = [
    "Paper low",
    "Out of paper",
    "Toner low",
    "Out of toner",
    "Door open",
    "Paper jam",
    "Offline",
    "Service requested",
    "Input tray missing",
    "Output tray missing",
    "Marker supply missing",
    "Output tray almost full",
    "Output tray full",
    "Input tray empty",
    "Maintenance overdue",
    "",
];

/// The error bits set, in words, the worst first (jam, door, out of paper, out of toner...).
pub fn error_words(octets: &[u8]) -> Vec<&'static str> {
    const ORDER: [usize; 15] = [5, 4, 1, 3, 8, 9, 10, 12, 6, 7, 13, 0, 2, 11, 14];
    let set = |bit: usize| octets.get(bit / 8).is_some_and(|o| o & (0x80 >> (bit % 8)) != 0);
    ORDER.iter().filter(|&&b| set(b)).map(|&b| ERROR_BITS[b]).collect()
}

/// A fault that stops printing (not a "low" warning).
pub fn is_fault(word: &str) -> bool {
    !matches!(word, "Paper low" | "Toner low" | "Output tray almost full" | "Maintenance overdue" | "Service requested" | "")
}

/// What a printer said over SNMP.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Answer {
    pub descr: Option<String>,
    pub name: Option<String>,
    /// hrPrinterStatus of the first printer listed, and its index.
    pub status: Option<i64>,
    pub index: Option<u32>,
    pub errors: Vec<&'static str>,
    /// prtGeneralSerialNumber of the first printer listed (that printer's, when the status
    /// named one).
    pub serial: Option<String>,
}

impl Answer {
    pub fn words(&self) -> String {
        if let Some(e) = self.errors.first() {
            return e.to_string();
        }
        match self.status {
            Some(3) => "Ready".into(),
            Some(s) => status_words(s).into(),
            None => "Says nothing about its state".into(),
        }
    }

    pub fn has_problem(&self) -> bool {
        self.errors.iter().any(|e| is_fault(e))
    }
}

/// What the first GET answered: sysDescr and sysName (a noSuchName leaves both unknown; v1
/// fails the whole request then).
pub fn take_system(r: &Response, a: &mut Answer) {
    if r.error_status != 0 {
        return;
    }
    for (o, v) in &r.bindings {
        if let Value::Octets(b) = v {
            let t = crate::text::clean_bytes(b, 255);
            if t.is_empty() {
                continue;
            }
            if o == SYS_DESCR {
                a.descr = Some(t);
            } else if o == SYS_NAME {
                a.name = Some(t);
            }
        }
    }
}

/// What the GETNEXT on the two Printer MIB columns answered: only bindings still inside their
/// column count (an agent without the Printer MIB answers with whatever comes next), and both
/// must be the same printer (instance).
pub fn take_printer(r: &Response, a: &mut Answer) {
    if r.error_status != 0 {
        return;
    }
    let inside = |o: &[u32], col: &[u32]| o.len() == col.len() + 1 && o.starts_with(col);
    let mut index = None;
    for (o, v) in &r.bindings {
        if inside(o, HR_PRINTER_STATUS)
            && let Value::Int(s) = v
        {
            a.status = Some(*s);
            index = Some(o[col_len()]);
        }
    }
    for (o, v) in &r.bindings {
        if inside(o, HR_PRINTER_ERRORS)
            && (index.is_none() || index == Some(o[col_len()]))
            && let Value::Octets(b) = v
        {
            a.errors = error_words(b);
        }
    }
    a.index = index;
}

/// What the GETNEXT on prtGeneralSerialNumber answered: a binding inside the column, the
/// printer's own instance when the status named one.
pub fn take_serial(r: &Response, a: &mut Answer) {
    if r.error_status != 0 {
        return;
    }
    let col = PRT_GENERAL_SERIAL;
    for (o, v) in &r.bindings {
        if o.len() == col.len() + 1
            && o.starts_with(col)
            && (a.index.is_none() || a.index == Some(o[col.len()]))
            && let Value::Octets(b) = v
        {
            let t = crate::text::clean_bytes(b, 64);
            if !t.trim().is_empty() {
                a.serial = Some(t.trim().to_string());
            }
        }
    }
}

fn col_len() -> usize {
    HR_PRINTER_STATUS.len()
}

/// How the SNMP question ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Answered(Answer),
    /// No answer to either try (a v1 agent with another community is silent too).
    Silent,
    /// The question could not be asked (no socket, no route): why.
    Failed(String),
}

impl Outcome {
    pub fn answered(&self) -> bool {
        matches!(self, Outcome::Answered(_))
    }
}

/// One request and its answer: two tries of `WAIT`, the answer must carry our request id and
/// come from the address asked (the socket is connected to it).
fn ask(sock: &UdpSocket, community: &str, pdu: u8, id: i32, oids: &[&[u32]]) -> Result<Option<Response>, String> {
    let q = request(pdu, id, community, oids);
    let mut buf = vec![0u8; 65_536];
    for _ in 0..TRIES {
        if let Err(e) = sock.send(&q) {
            return Err(format!("the SNMP question did not go out ({e})"));
        }
        let deadline = Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let _ = sock.set_read_timeout(Some(left.max(Duration::from_millis(1))));
            match sock.recv(&mut buf) {
                Ok(n) => {
                    if let Ok(r) = parse(&buf[..n])
                        && r.request_id == id as i64
                    {
                        return Ok(Some(r));
                    }
                }
                // Port unreachable (ICMP) comes back as a reset on a connected UDP socket.
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return Ok(None),
                Err(_) => break,
            }
        }
    }
    Ok(None)
}

/// The system and Printer MIB questions at `addr`.
/// Ask `addr` with `community` (a printer's own port's, so the answer is what Windows' own SNMP
/// check would get: AUDIT-1 PRINT-4).
pub fn query(addr: SocketAddr, community: &str) -> Outcome {
    let bind: SocketAddr = if addr.is_ipv6() { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
    let sock = match UdpSocket::bind(bind).and_then(|s| s.connect(addr).map(|_| s)) {
        Ok(s) => s,
        Err(e) => return Outcome::Failed(format!("no SNMP socket ({e})")),
    };
    let id = (std::process::id() as i32).wrapping_mul(7919) & 0x3FFF_FFFF;
    let mut a = Answer::default();
    let first = match ask(&sock, community, PDU_GET, id, &[SYS_DESCR, SYS_NAME]) {
        Ok(Some(r)) => r,
        Ok(None) => return Outcome::Silent,
        Err(e) => return Outcome::Failed(e),
    };
    take_system(&first, &mut a);
    if let Ok(Some(r)) = ask(&sock, community, PDU_GETNEXT, id + 1, &[HR_PRINTER_STATUS, HR_PRINTER_ERRORS]) {
        take_printer(&r, &mut a);
    }
    if let Ok(Some(r)) = ask(&sock, community, PDU_GETNEXT, id + 2, &[PRT_GENERAL_SERIAL]) {
        take_serial(&r, &mut a);
    }
    Outcome::Answered(a)
}
