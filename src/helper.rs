//! The admin steps, in a short-lived helper (the VibeLink pattern; SPEC section 5). The app never
//! runs elevated. It creates a named pipe first (`\\.\pipe\vibeprint-<128-bit random>`, one
//! instance, first instance only, remote clients rejected, a DACL for the current user's SID
//! only), then relaunches its own exe from its final path with `ShellExecuteExW` verb `runas`:
//! `VibePrint.exe --helper <job> <pipe>` (one UAC prompt; declining changes nothing). The client
//! must be that very process (`GetNamedPipeClientProcessId` against the PID ShellExecuteEx
//! returned) running this very exe (`QueryFullProcessImageNameW`, compared by file identity); the
//! helper connects at identification level and checks the server the same way.
//!
//! The helper does one bounded job from the table: it says Hello, reads one request (the job
//! again, a nonce and the job's parameters), validates every parameter against its own fresh
//! read of the spooler, does the job, sends the result and exits. A watchdog ends it at the
//! job's hard limit; a broken pipe ends it at once. The app treats every byte from the pipe as
//! untrusted (`Decoder`: sizes capped per kind, order enforced, parsed strictly). No job takes a
//! free path or command.

use crate::ports::TcpConfig;
use crate::printers::Spooler;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// How long the app waits for the helper to connect (the UAC prompt may sit there).
pub const CONNECT_WAIT: Duration = Duration::from_secs(120);
pub const PIPE_PREFIX: &str = r"\\.\pipe\vibeprint-";

/// `Job` (its wire byte), `JOBS` and each job's `--helper` name from one list (review RRC-2), so
/// `JOBS` can't miss a job: `from_name`, `from_byte` and the tests all go through it. A variant
/// outside the list does not compile (`name` has no arm for it).
macro_rules! jobs {
    ($($job:ident = $byte:literal => $name:literal,)+) => {
        /// One admin step (the spec's table).
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum Job {
            $($job = $byte,)+
        }

        pub const JOBS: [Job; [$(stringify!($job)),+].len()] = [$(Job::$job),+];

        impl Job {
            pub fn name(self) -> &'static str {
                match self {
                    $(Job::$job => $name,)+
                }
            }
        }
    };
}

jobs! {
    QueueClear = 1 => "queue-clear",
    SpoolerRestart = 2 => "spooler-restart",
    PrinterOnline = 3 => "printer-online",
    PortToTcp = 4 => "port-to-tcp",
    PortSet = 5 => "port-set",
    PortAddress = 6 => "port-address",
    PortSnmpOff = 7 => "port-snmp-off",
    PortSnmpOn = 8 => "port-snmp-on",
    PrinterAdd = 9 => "printer-add",
    PrinterDelete = 10 => "printer-delete",
}

impl Job {
    pub fn from_name(s: &str) -> Option<Job> {
        JOBS.into_iter().find(|j| j.name() == s)
    }

    fn from_byte(b: u8) -> Option<Job> {
        JOBS.into_iter().find(|j| *j as u8 == b)
    }

    /// The helper ends itself at this age whatever happens. The jobs that stop the spooler
    /// also cover every dependent's stop and start at their full waits (AUDIT-1 R-PRINT-5): the
    /// watchdog never ends a helper that is starting the dependents again.
    pub fn hard_limit(self) -> Duration {
        let dependents = DEPENDENT_WAIT * 2 * MAX_DEPENDENTS as u32;
        match self {
            // And the further wait for a stop the spooler took but did not finish (FEC3).
            Job::QueueClear => Duration::from_secs(90) + SPOOLER_LATE_STOP_WAIT + dependents,
            Job::SpoolerRestart => Duration::from_secs(60) + SPOOLER_LATE_STOP_WAIT + dependents,
            Job::PrinterAdd => Duration::from_secs(60),
            Job::PortToTcp | Job::PrinterDelete => Duration::from_secs(30),
            _ => Duration::from_secs(20),
        }
    }

    /// The parameters it takes, exactly.
    pub fn params(self) -> &'static [Tag] {
        use Tag::*;
        match self {
            Job::QueueClear | Job::PrinterOnline => &[Printer],
            Job::SpoolerRestart => &[Enable],
            Job::PortToTcp => &[Printer, Port, Ipv4, Protocol, Snmp],
            Job::PortSet | Job::PrinterDelete => &[Printer, Port],
            Job::PortAddress => &[Port, Ipv4],
            Job::PortSnmpOff => &[Port],
            // The community to put back: the one recorded when the check was turned off.
            Job::PortSnmpOn => &[Port, Community],
            Job::PrinterAdd => &[Ipv4, Protocol, Snmp, Driver, Name],
        }
    }
}

/// A parameter's tag on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Tag {
    Printer = 1,
    Ipv4 = 2,
    Protocol = 3,
    Snmp = 4,
    Port = 5,
    Driver = 6,
    Name = 7,
    Enable = 8,
    Community = 9,
}

impl Tag {
    fn from_byte(b: u8) -> Option<Tag> {
        use Tag::*;
        [Printer, Ipv4, Protocol, Snmp, Port, Driver, Name, Enable, Community].into_iter().find(|t| *t as u8 == b)
    }
}

/// RAW 9100 or LPR 515 (queue `lp`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Raw,
    Lpr,
}

impl Protocol {
    pub fn word(self) -> &'static str {
        match self {
            Protocol::Raw => "raw",
            Protocol::Lpr => "lpr",
        }
    }

    pub fn words(self) -> &'static str {
        match self {
            Protocol::Raw => "RAW 9100",
            Protocol::Lpr => "LPR 515, queue lp",
        }
    }
}

/// A job's parameters (each as the spec types them).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Params {
    pub printer: Option<Vec<u16>>,
    pub ipv4: Option<Ipv4Addr>,
    pub protocol: Option<Protocol>,
    pub snmp: Option<bool>,
    pub port: Option<String>,
    pub driver: Option<String>,
    pub name: Option<Vec<u16>>,
    pub enable: Option<bool>,
    pub community: Option<String>,
}

// ---------- the parameter rules (pure) ----------

/// An IPv4 address a printer may have: a dotted quad, unicast, not loopback, link-local,
/// broadcast, "this network" or reserved.
pub fn valid_ipv4(s: &str) -> Option<Ipv4Addr> {
    let ip: Ipv4Addr = s.parse().ok()?;
    let o = ip.octets();
    let bad = ip.is_loopback() || ip.is_link_local() || ip.is_broadcast() || ip.is_multicast() || ip.is_unspecified() || o[0] == 0 || o[0] >= 240;
    // Rust's parser takes "1.2.3.4" only (no leading zeros, no shorthand); the text must be it.
    (!bad && ip.to_string() == s).then_some(ip)
}

/// A printer parameter: 1 to 220 units, not a shared connection's `\\server\printer`.
pub fn valid_printer(units: &[u16]) -> bool {
    !units.is_empty() && units.len() <= 220 && !units.starts_with(&[b'\\' as u16, b'\\' as u16]) && !units.contains(&0)
}

/// A new printer's name: 1 to 220 units, none of `\ , !` (Windows refuses those), no controls,
/// not only spaces.
pub fn valid_new_name(units: &[u16]) -> bool {
    valid_printer(units)
        && !units.iter().any(|&u| u == b'\\' as u16 || u == b',' as u16 || u == b'!' as u16 || u < 0x20 || u == 0x7F)
        && units.iter().any(|&u| u != b' ' as u16)
        && String::from_utf16(units).is_ok()
}

/// An SNMP community a port may be given: 1 to 32 printable ASCII characters (the TCP/IP port's
/// field), not only spaces.
pub fn valid_community(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.bytes().all(|b| (0x20..0x7F).contains(&b)) && s.bytes().any(|b| b != b' ')
}

/// A port name the helper may be handed: 1 to 63 characters (PORT_DATA_1's field), no `\`, no
/// controls.
pub fn valid_port_name(s: &str) -> bool {
    !s.is_empty() && s.chars().count() <= 63 && !s.contains('\\') && !s.chars().any(char::is_control)
}

// ---------- the wire ----------

const KIND_HELLO: u8 = 1;
const KIND_DONE: u8 = 2;
const KIND_REFUSED: u8 = 3;
const KIND_ERROR: u8 = 4;
const KIND_REQUEST: u8 = 0x10;

pub const MAX_RESULT_JSON: usize = 32 * 1024;
pub const MAX_REQUEST: usize = 4096;
const MAX_PARAM_UNITS: usize = 260;

fn header(kind: u8, len: usize) -> [u8; 5] {
    let l = (len as u32).to_le_bytes();
    [kind, l[0], l[1], l[2], l[3]]
}

/// A message: kind, length (u32 LE), payload.
pub fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = header(kind, payload.len()).to_vec();
    out.extend_from_slice(payload);
    out
}

pub fn hello(pid: u32) -> Vec<u8> {
    frame(KIND_HELLO, &pid.to_le_bytes())
}

pub fn done(nonce: &[u8; 16], r: &JobResult) -> Vec<u8> {
    let mut p = nonce.to_vec();
    p.extend_from_slice(&serde_json::to_vec(r).unwrap_or_default());
    frame(KIND_DONE, &p)
}

pub fn refused(reason: Reason) -> Vec<u8> {
    frame(KIND_REFUSED, &[reason as u8])
}

pub fn error(stage: Stage, code: u32) -> Vec<u8> {
    let c = code.to_le_bytes();
    frame(KIND_ERROR, &[stage as u8, c[0], c[1], c[2], c[3]])
}

/// An error with what the job did before it (the result as JSON after the stage and code), when
/// it did anything worth saying: dependents started again or not, spool files removed.
pub fn error_after(stage: Stage, code: u32, r: &JobResult) -> Vec<u8> {
    if r.restarted.is_empty() && r.not_restarted.is_empty() && r.removed_count == 0 {
        return error(stage, code);
    }
    let c = code.to_le_bytes();
    let mut p = vec![stage as u8, c[0], c[1], c[2], c[3]];
    p.extend_from_slice(&serde_json::to_vec(r).unwrap_or_default());
    frame(KIND_ERROR, &p)
}

fn put(out: &mut Vec<u8>, tag: Tag, units: &[u16]) {
    out.push(tag as u8);
    out.extend_from_slice(&(units.len() as u16).to_le_bytes());
    for u in units {
        out.extend_from_slice(&u.to_le_bytes());
    }
}

/// The app's request: job, nonce, the job's parameters (each tag once, UTF-16).
pub fn request(job: Job, nonce: &[u8; 16], p: &Params) -> Vec<u8> {
    let mut b = vec![job as u8];
    b.extend_from_slice(nonce);
    let mut items: Vec<(Tag, Vec<u16>)> = Vec::new();
    let w = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
    if let Some(x) = &p.printer {
        items.push((Tag::Printer, x.clone()));
    }
    if let Some(x) = p.ipv4 {
        items.push((Tag::Ipv4, w(&x.to_string())));
    }
    if let Some(x) = p.protocol {
        items.push((Tag::Protocol, w(x.word())));
    }
    if let Some(x) = p.snmp {
        items.push((Tag::Snmp, w(if x { "1" } else { "0" })));
    }
    if let Some(x) = &p.port {
        items.push((Tag::Port, w(x)));
    }
    if let Some(x) = &p.driver {
        items.push((Tag::Driver, w(x)));
    }
    if let Some(x) = &p.name {
        items.push((Tag::Name, x.clone()));
    }
    if let Some(x) = p.enable {
        items.push((Tag::Enable, w(if x { "1" } else { "0" })));
    }
    if let Some(x) = &p.community {
        items.push((Tag::Community, w(x)));
    }
    b.push(items.len() as u8);
    for (t, u) in items {
        put(&mut b, t, &u);
    }
    frame(KIND_REQUEST, &b)
}

/// The helper's reading of a request payload: the job it was started for, a nonce, and exactly
/// the job's parameters, each well-formed. None for anything else.
pub fn parse_request(b: &[u8], job: Job) -> Option<([u8; 16], Params)> {
    if b.len() < 18 || b.len() > MAX_REQUEST || Job::from_byte(b[0]) != Some(job) {
        return None;
    }
    let nonce: [u8; 16] = b[1..17].try_into().ok()?;
    let count = b[17] as usize;
    let mut at = 18;
    let mut p = Params::default();
    let mut seen: Vec<Tag> = Vec::new();
    for _ in 0..count {
        let tag = Tag::from_byte(*b.get(at)?)?;
        let n = u16::from_le_bytes([*b.get(at + 1)?, *b.get(at + 2)?]) as usize;
        if n > MAX_PARAM_UNITS || seen.contains(&tag) {
            return None;
        }
        let bytes = b.get(at + 3..at + 3 + n * 2)?;
        let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        at += 3 + n * 2;
        seen.push(tag);
        let text = || String::from_utf16(&units).ok();
        match tag {
            Tag::Printer => p.printer = valid_printer(&units).then(|| units.clone()),
            Tag::Ipv4 => p.ipv4 = text().and_then(|s| valid_ipv4(&s)),
            Tag::Protocol => {
                p.protocol = match text()?.as_str() {
                    "raw" => Some(Protocol::Raw),
                    "lpr" => Some(Protocol::Lpr),
                    _ => None,
                }
            }
            Tag::Snmp | Tag::Enable => {
                let v = match text()?.as_str() {
                    "1" => Some(true),
                    "0" => Some(false),
                    _ => None,
                };
                if tag == Tag::Snmp {
                    p.snmp = v;
                } else {
                    p.enable = v;
                }
            }
            Tag::Port => p.port = text().filter(|s| valid_port_name(s)),
            Tag::Driver => p.driver = text().filter(|s| !s.is_empty() && s.chars().count() <= 220 && !s.chars().any(char::is_control)),
            Tag::Name => p.name = valid_new_name(&units).then(|| units.clone()),
            Tag::Community => p.community = text().filter(|s| valid_community(s)),
        }
    }
    if at != b.len() {
        return None;
    }
    // Exactly the job's parameters, each present and valid.
    let mut want = job.params().to_vec();
    want.sort_by_key(|t| *t as u8);
    seen.sort_by_key(|t| *t as u8);
    if want != seen {
        return None;
    }
    let present = |t: &Tag| match t {
        Tag::Printer => p.printer.is_some(),
        Tag::Ipv4 => p.ipv4.is_some(),
        Tag::Protocol => p.protocol.is_some(),
        Tag::Snmp => p.snmp.is_some(),
        Tag::Port => p.port.is_some(),
        Tag::Driver => p.driver.is_some(),
        Tag::Name => p.name.is_some(),
        Tag::Enable => p.enable.is_some(),
        Tag::Community => p.community.is_some(),
    };
    job.params().iter().all(present).then_some((nonce, p))
}

/// Why the helper refused (a parameter did not hold against its own fresh read).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    NoPrinter = 1,
    Shared = 2,
    NoPort = 3,
    NotTcpPort = 4,
    PortChanged = 5,
    NoDriver = 6,
    NameTaken = 7,
    SpoolerDisabled = 8,
    PortTaken = 9,
    NotPrinterPort = 10,
}

pub const REASONS: [Reason; 10] = [
    Reason::NoPrinter,
    Reason::Shared,
    Reason::NoPort,
    Reason::NotTcpPort,
    Reason::PortChanged,
    Reason::NoDriver,
    Reason::NameTaken,
    Reason::SpoolerDisabled,
    Reason::PortTaken,
    Reason::NotPrinterPort,
];

impl Reason {
    pub fn words(self) -> &'static str {
        match self {
            Reason::NoPrinter => "the printer is not there any more",
            Reason::Shared => "a printer shared by another PC is never changed here",
            Reason::NoPort => "the port is not there any more",
            Reason::NotTcpPort => "the port is not a Standard TCP/IP port",
            Reason::PortChanged => "the printer's port changed since it was read",
            Reason::NoDriver => "that driver is not installed",
            Reason::NameTaken => "a printer with that name exists",
            Reason::SpoolerDisabled => "the Print Spooler is disabled, and turning it on was not asked for",
            Reason::PortTaken => "no free port name for that address",
            Reason::NotPrinterPort => "the printer does not use that port any more",
        }
    }
}

/// Where the helper failed (Windows refused a step).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Read = 1,
    AddPort = 2,
    ConfigPort = 3,
    SetPrinter = 4,
    AddPrinter = 5,
    DeletePrinter = 6,
    Purge = 7,
    StopSpooler = 8,
    StartSpooler = 9,
    ConfigSpooler = 10,
    /// The spooler took the stop but was still on its way down after the further wait (FEC3).
    StopLate = 11,
}

pub const STAGES: [Stage; 11] = [Stage::Read, Stage::AddPort, Stage::ConfigPort, Stage::SetPrinter, Stage::AddPrinter, Stage::DeletePrinter, Stage::Purge, Stage::StopSpooler, Stage::StartSpooler, Stage::ConfigSpooler, Stage::StopLate];

impl Stage {
    pub fn words(self, code: u32) -> String {
        let what = match self {
            Stage::Read => "the spooler could not be read",
            Stage::AddPort => "Windows refused to make the port",
            Stage::ConfigPort => "Windows refused to change the port",
            Stage::SetPrinter => "Windows refused to change the printer",
            Stage::AddPrinter => "Windows refused to add the printer",
            Stage::DeletePrinter => "Windows refused to delete the printer",
            Stage::Purge => "the spooler refused to clear the queue",
            Stage::StopSpooler => "the Print Spooler did not stop",
            Stage::StartSpooler => "the Print Spooler did not start",
            Stage::ConfigSpooler => "the Print Spooler's start type could not be set",
            Stage::StopLate => "the Print Spooler was told to stop but was still stopping after 90 seconds, so it was not started again. It may be stopped by now, and then no printer works: press Restart spooler",
        };
        if code == 0 { what.into() } else { format!("{what} ({})", code_words(code)) }
    }
}

/// A Win32 code in words, cleaned (it comes from the helper, over the pipe).
pub fn code_words(code: u32) -> String {
    crate::text::clean_max(&std::io::Error::from_raw_os_error(code as i32).to_string(), 120)
}

/// What a job did, as the helper reports it (JSON, strictly shaped).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct JobResult {
    /// The TCP/IP port used (port-to-tcp, printer-add).
    pub port: Option<String>,
    /// That port existed with the same address and was reused.
    pub reused: bool,
    /// A reused port as it was kept (its own protocol and SNMP check, not the planned ones:
    /// AUDIT-1 PRINT-8): "RAW 9100", "LPR queue 'lp'".
    pub reused_protocol: Option<String>,
    pub reused_snmp: Option<bool>,
    /// queue-clear: the spooler's own purge ran.
    pub purged: bool,
    /// queue-clear: jobs were still there after it (so the spooler was stopped).
    pub stopped: bool,
    /// queue-clear: how many spool files were removed and how many shadow files were left
    /// (with why), and the first `NAMES` of each by name (AUDIT-1 PRINT-10: the counts are
    /// whole, the names never more than the app takes).
    pub removed_count: u32,
    pub left_count: u32,
    pub removed: Vec<String>,
    pub left: Vec<String>,
    /// queue-clear: jobs still in the queue at the end; None when that could not be read.
    pub remaining: Option<u32>,
    /// queue-clear: the spool folder could not be listed (the Win32 code): nothing in it was
    /// deleted or looked at (FEC4).
    pub spool_unread: Option<u32>,
    /// spooler-restart: its start type was set to Automatic first.
    pub enabled: bool,
    /// The services that depended on the spooler and ran before it was stopped: started again,
    /// and those that did not start (AUDIT-1 PRINT-2).
    pub restarted: Vec<String>,
    pub not_restarted: Vec<String>,
}

/// The most names a result lists of each kind, and the longest name: whatever a clear did, the
/// result stays well under `MAX_RESULT_JSON`.
pub const NAMES: usize = 16;
pub const NAME_CHARS: usize = 120;
/// A service's name in `restarted` / `not_restarted` (16 at most: the dependents read).
pub const SERVICE_CHARS: usize = 80;
/// The most dependents of the spooler read (and so stopped and started again), and how long
/// each stop and each start is waited for.
pub const MAX_DEPENDENTS: usize = 16;
pub const DEPENDENT_WAIT: Duration = Duration::from_secs(10);
/// How long the spooler's own stop and start are waited for.
pub const SPOOLER_STOP_WAIT: Duration = Duration::from_secs(30);
pub const SPOOLER_START_WAIT: Duration = Duration::from_secs(25);
/// A stop the spooler took but did not finish within `SPOOLER_STOP_WAIT` (a hung driver or port
/// monitor) is waited for this much longer, then the spooler is started again (FEC3).
pub const SPOOLER_LATE_STOP_WAIT: Duration = Duration::from_secs(60);
/// What `stop` answers when the spooler took the stop but did not get there in time.
const ERROR_SERVICE_REQUEST_TIMEOUT: u32 = 1053;
/// How long a clear waits for the spooler's own purge (20 reads 500 ms apart).
pub const PURGE_WAIT: Duration = Duration::from_secs(10);

/// Count `s` and keep it when fewer than `NAMES` are kept.
fn note(list: &mut Vec<String>, count: &mut u32, s: &str) {
    *count = count.saturating_add(1);
    if list.len() < NAMES {
        list.push(crate::text::clean_max(s, NAME_CHARS));
    }
}

impl JobResult {
    /// The shape a real helper sends: bounded lists of short names.
    pub fn valid(&self) -> bool {
        let fits = |s: &String, max: usize| s.chars().count() <= max && !s.chars().any(|c| c.is_control());
        let list = |v: &Vec<String>, max: usize| v.len() <= NAMES && v.iter().all(|s| fits(s, max));
        self.port.as_ref().is_none_or(|p| valid_port_name(p))
            && self.reused_protocol.as_ref().is_none_or(|s| fits(s, NAME_CHARS))
            && list(&self.removed, NAME_CHARS)
            && list(&self.left, NAME_CHARS)
            && list(&self.restarted, SERVICE_CHARS)
            && list(&self.not_restarted, SERVICE_CHARS)
            && self.removed.len() as u32 <= self.removed_count
            && self.left.len() as u32 <= self.left_count
    }
}

/// A message from the helper as the app decodes it.
#[derive(Debug, PartialEq, Eq)]
pub enum Msg {
    Hello { pid: u32 },
    Done(JobResult),
    Refused(Reason),
    /// `after`: what the job did before the error (AUDIT-1 R-PRINT-6).
    Error { stage: Stage, code: u32, after: Option<Box<JobResult>> },
}

/// Reads the helper's messages out of the byte stream. Strict: an unknown kind, a size over its
/// cap or not its own, a message before Hello, a second Hello, an unknown reason or stage, a
/// Done with another nonce or a result not in shape, anything after the last message: the
/// stream is broken for good (the helper is ours, so anything else means someone else).
pub struct Decoder {
    nonce: [u8; 16],
    head: [u8; 5],
    hlen: usize,
    need: usize,
    body: Vec<u8>,
    hello: bool,
    ended: bool,
    broken: bool,
}

impl Decoder {
    pub fn new(nonce: [u8; 16]) -> Decoder {
        Decoder { nonce, head: [0; 5], hlen: 0, need: 0, body: Vec::new(), hello: false, ended: false, broken: false }
    }

    pub fn ended(&self) -> bool {
        self.ended
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Msg>, String> {
        if self.broken {
            return Err("the helper's stream was already broken".into());
        }
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if self.ended {
                return self.fail("bytes after its last message".into());
            }
            if self.hlen < 5 {
                let n = (5 - self.hlen).min(bytes.len() - i);
                self.head[self.hlen..self.hlen + n].copy_from_slice(&bytes[i..i + n]);
                self.hlen += n;
                i += n;
                if self.hlen < 5 {
                    break;
                }
                let kind = self.head[0];
                let len = u32::from_le_bytes(self.head[1..5].try_into().unwrap()) as usize;
                let fits = match kind {
                    KIND_HELLO => len == 4,
                    KIND_DONE => (18..=16 + MAX_RESULT_JSON).contains(&len),
                    KIND_REFUSED => len == 1,
                    KIND_ERROR => (5..=5 + MAX_RESULT_JSON).contains(&len),
                    k => return self.fail(format!("an unknown message ({k})")),
                };
                if !fits {
                    return self.fail(format!("a message of {len} bytes (kind {kind})"));
                }
                self.need = len;
                self.body.clear();
            }
            let n = (self.need - self.body.len()).min(bytes.len() - i);
            self.body.extend_from_slice(&bytes[i..i + n]);
            i += n;
            if self.body.len() < self.need {
                break;
            }
            self.hlen = 0;
            let kind = self.head[0];
            let m = self.message(kind)?;
            out.push(m);
        }
        Ok(out)
    }

    fn message(&mut self, kind: u8) -> Result<Msg, String> {
        let p = std::mem::take(&mut self.body);
        if kind != KIND_HELLO && !self.hello {
            return self.fail("a message before hello".into());
        }
        match kind {
            KIND_HELLO if !self.hello => {
                self.hello = true;
                Ok(Msg::Hello { pid: u32::from_le_bytes(p[..4].try_into().unwrap()) })
            }
            KIND_HELLO => self.fail("a second hello".into()),
            KIND_DONE => {
                if p[..16] != self.nonce {
                    return self.fail("an answer to another request".into());
                }
                match serde_json::from_slice::<JobResult>(&p[16..]) {
                    Ok(r) if r.valid() => {
                        self.ended = true;
                        Ok(Msg::Done(r))
                    }
                    _ => self.fail("a result that is not in shape".into()),
                }
            }
            KIND_REFUSED => match REASONS.into_iter().find(|r| *r as u8 == p[0]) {
                Some(r) => {
                    self.ended = true;
                    Ok(Msg::Refused(r))
                }
                None => self.fail(format!("an unknown refusal ({})", p[0])),
            },
            KIND_ERROR => match STAGES.into_iter().find(|s| *s as u8 == p[0]) {
                Some(stage) => {
                    let after = match &p[5..] {
                        [] => None,
                        json => match serde_json::from_slice::<JobResult>(json) {
                            Ok(r) if r.valid() => Some(Box::new(r)),
                            _ => return self.fail("an error with a result that is not in shape".into()),
                        },
                    };
                    self.ended = true;
                    Ok(Msg::Error { stage, code: u32::from_le_bytes(p[1..5].try_into().unwrap()), after })
                }
                None => self.fail(format!("an unknown stage ({})", p[0])),
            },
            k => self.fail(format!("a message out of order ({k})")),
        }
    }

    fn fail<T>(&mut self, why: String) -> Result<T, String> {
        self.broken = true;
        self.body.clear();
        Err(format!("the helper sent {why}"))
    }
}

/// The helper's command line, `--helper <job> <pipe>`: the one copy of its shape. The elevated
/// relaunch passes it (joined with spaces: no part has one) and the pe test starts the exe with
/// it, so the two can't drift apart (review RRC-1).
pub fn args(job: Job, pipe: &str) -> [String; 3] {
    ["--helper".into(), job.name().into(), pipe.into()]
}

/// The helper's arguments: `--helper <job> <pipe>`, the pipe exactly as the app makes it.
pub fn parse_args(args: &[String]) -> Option<(Job, String)> {
    let [flag, job, pipe] = args else { return None };
    if flag != "--helper" {
        return None;
    }
    let job = Job::from_name(job)?;
    let hex = pipe.strip_prefix(PIPE_PREFIX)?;
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    Some((job, pipe.clone()))
}

/// The pipe's name: 128 random bits from the system's generator, lower-case hex.
pub fn pipe_name(random: &[u8; 16]) -> String {
    format!("{PIPE_PREFIX}{}", random.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// A file identity: the volume serial and the 128-bit file id.
pub type FileIdent = (u64, [u8; 16]);

/// Two identities are one file: equal, and neither the serial nor the id is zero (a zero is
/// "unknown", never "the same").
pub(crate) fn same_id(a: FileIdent, b: FileIdent) -> bool {
    a == b && a.0 != 0 && a.1 != [0; 16]
}

/// The identity where a file system has no `FILE_ID_INFO` (FAT, exFAT: a USB stick): the 32-bit
/// serial and the 64-bit index in the low 8 bytes.
pub(crate) fn fallback_id(serial: u32, index_high: u32, index_low: u32) -> FileIdent {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&((u64::from(index_high) << 32) | u64::from(index_low)).to_le_bytes());
    (u64::from(serial), id)
}

/// A verbatim path's plain form: `\\?\C:\x` → `C:\x`, `\\?\UNC\srv\share\x` → `\\srv\share\x`.
pub(crate) fn strip_verbatim(p: &[u16]) -> Option<Vec<u16>> {
    let s = String::from_utf16(p).ok()?;
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return Some(format!(r"\\{rest}").encode_utf16().collect());
    }
    let rest = s.strip_prefix(r"\\?\")?;
    let b = rest.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\').then(|| rest.encode_utf16().collect())
}

// ---------- what a job gives the app ----------

/// How an admin step ended, as the controller sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The user said no at the UAC prompt.
    Declined,
    /// It did not happen (why, in words).
    Failed(String),
    /// It failed after it had stopped the spooler: why, and what it did till then (the
    /// dependents started again or not, the spool files removed: AUDIT-1 R-PRINT-6).
    FailedAfter(String, Box<JobResult>),
    /// The helper refused: a parameter did not hold against its fresh read.
    Refused(Reason),
    /// Nobody connected in time, or the helper ended before it did.
    NeverConnected(String),
    /// The helper went away before it finished: what it did is not known.
    Gone,
    Done(JobResult),
    /// The window closed meanwhile.
    Stopped,
}

/// Collects a job's messages; only a stream that ends in Done, Refused or Error answers.
pub struct Collect {
    pid: u32,
    pub outcome: Option<Outcome>,
}

impl Collect {
    pub fn new(pid: u32) -> Collect {
        Collect { pid, outcome: None }
    }

    /// One message; false once the stream has its outcome.
    pub fn take(&mut self, m: Msg) -> bool {
        self.outcome = match m {
            Msg::Hello { pid } if pid != self.pid => Some(Outcome::Failed("the helper said it was another process".into())),
            Msg::Hello { .. } => return true,
            Msg::Done(r) => Some(Outcome::Done(r)),
            Msg::Refused(r) => Some(Outcome::Refused(r)),
            Msg::Error { stage, code, after: None } => Some(Outcome::Failed(stage.words(code))),
            Msg::Error { stage, code, after: Some(r) } => Some(Outcome::FailedAfter(stage.words(code), r)),
        };
        false
    }
}

// ---------- the spooler, as the helper's jobs see it ----------

/// A local printer as the helper reads it afresh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Local {
    pub name: Vec<u16>,
    pub port: String,
    pub attributes: u32,
    /// A connection to another PC's printer.
    pub shared: bool,
}

/// A new or changed Standard TCP/IP port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortConfig {
    pub name: String,
    pub host: String,
    pub protocol: u32,
    pub port_number: u32,
    pub queue: String,
    pub snmp: bool,
    pub community: String,
    pub snmp_index: u32,
}

impl PortConfig {
    pub fn new(name: &str, ip: Ipv4Addr, protocol: Protocol, snmp: bool) -> PortConfig {
        PortConfig {
            name: name.into(),
            host: ip.to_string(),
            protocol: if protocol == Protocol::Raw { 1 } else { 2 },
            port_number: if protocol == Protocol::Raw { 9100 } else { 515 },
            queue: if protocol == Protocol::Lpr { "lp".into() } else { String::new() },
            snmp,
            community: if snmp { "public".into() } else { String::new() },
            snmp_index: u32::from(snmp),
        }
    }

    /// An existing port's configuration as it stands (the registry), to change one field of.
    pub fn from_tcp(name: &str, c: &TcpConfig) -> PortConfig {
        PortConfig {
            name: name.into(),
            host: c.target().to_string(),
            protocol: c.protocol,
            port_number: c.port_number,
            queue: c.queue.clone(),
            snmp: c.snmp,
            community: c.community.clone(),
            snmp_index: c.snmp_index,
        }
    }
}

/// The spool folder's files: each name, and for a shadow file the printer it names (or why it
/// was not read). Parsed as read: no file's bytes are held (AUDIT-1 PRINT-5).
pub type SpoolFiles = Vec<(String, Result<Vec<u16>, String>)>;

/// The spooler calls the jobs make (the helper's real one; the tests' scripted one).
pub trait Spool {
    fn printers(&self) -> Result<Vec<Local>, u32>;
    /// Every port: (name, monitor).
    fn ports(&self) -> Result<Vec<(String, String)>, u32>;
    fn tcp_config(&self, port: &str) -> Option<TcpConfig>;
    fn drivers(&self) -> Vec<String>;
    fn add_port(&self, c: &PortConfig) -> Result<(), u32>;
    fn config_port(&self, c: &PortConfig) -> Result<(), u32>;
    fn set_port(&self, printer: &[u16], port: &str) -> Result<(), u32>;
    /// Clear attribute bits.
    fn clear_attributes(&self, printer: &[u16], bits: u32) -> Result<(), u32>;
    fn add_printer(&self, name: &[u16], port: &str, driver: &str) -> Result<(), u32>;
    fn delete_printer(&self, name: &[u16]) -> Result<(), u32>;
    fn purge(&self, printer: &[u16]) -> Result<(), u32>;
    fn job_count(&self, printer: &[u16]) -> Result<u32, u32>;
    fn spooler(&self) -> Spooler;
    /// Stop the Print Spooler; each running service that depends on it goes into `stopped`
    /// before it is stopped (so exactly those are started again, on every path).
    fn stop_spooler(&self, wait: Duration, stopped: &mut Vec<String>) -> Result<(), u32>;
    /// Wait up to `wait` for a stop already asked for to finish (only the spooler's state is
    /// read: nothing is asked of it).
    fn wait_spooler_stopped(&self, wait: Duration) -> Result<(), u32>;
    fn start_spooler(&self, wait: Duration) -> Result<(), u32>;
    /// Start one of the services that depended on the spooler again.
    fn start_service(&self, name: &str, wait: Duration) -> Result<(), u32>;
    fn set_auto_start(&self) -> Result<(), u32>;
    /// The spool folder: every file's name, and the printer each shadow file names (or why not).
    fn spool_files(&self) -> Result<SpoolFiles, u32>;
    fn delete_spool_file(&self, name: &str) -> Result<(), u32>;
    /// Wait (the real one sleeps; the scripted one moves its clock).
    fn pause(&self, d: Duration);
}

/// The local printer named `name` (case-insensitive, as Windows names printers).
fn find_printer<'a>(list: &'a [Local], name: &[u16]) -> Option<&'a Local> {
    list.iter().find(|p| p.name == name).or_else(|| list.iter().find(|p| crate::shd::same_printer(&p.name, name)))
}

/// Start the services that depended on the spooler and ran before it was stopped, in the
/// reverse of the order they were stopped (best effort: those that do not start are named).
fn restart_dependents(spool: &dyn Spool, deps: &[String], r: &mut JobResult) {
    for d in deps.iter().rev() {
        let list = if spool.start_service(d, DEPENDENT_WAIT).is_ok() { &mut r.restarted } else { &mut r.not_restarted };
        if list.len() < NAMES {
            list.push(crate::text::clean_max(d, SERVICE_CHARS));
        }
    }
}

/// Stop the spooler (its running dependents first, into `deps`). A stop it took but did not
/// finish within `SPOOLER_STOP_WAIT` (a hung driver or port monitor: the very case a stuck queue
/// comes from) is waited for further, so the caller starts it again once it is down; never
/// left on its way down with the words "did not stop" (FEC3).
fn stop_spooler(spool: &dyn Spool, deps: &mut Vec<String>) -> Result<(), Fail> {
    match spool.stop_spooler(SPOOLER_STOP_WAIT, deps) {
        Err(ERROR_SERVICE_REQUEST_TIMEOUT) => spool.wait_spooler_stopped(SPOOLER_LATE_STOP_WAIT).map_err(|_| Fail::Error(Stage::StopLate, 0)),
        r => r.map_err(|e| Fail::Error(Stage::StopSpooler, e)),
    }
}

/// The job's work, once the request checked out, over `spool`; the message to send back.
pub fn work(spool: &dyn Spool, job: Job, nonce: &[u8; 16], p: &Params) -> Vec<u8> {
    match run_job(spool, job, p) {
        Ok(r) => done(nonce, &r),
        Err(Fail::Refused(r)) => refused(r),
        Err(Fail::Error(s, c)) => error(s, c),
        Err(Fail::ErrorAfter(s, c, r)) => error_after(s, c, &r),
    }
}

enum Fail {
    Refused(Reason),
    Error(Stage, u32),
    /// An error after the spooler was stopped: what was done till then goes with it (the
    /// dependents started again or not, the spool files removed: AUDIT-1 R-PRINT-6).
    ErrorAfter(Stage, u32, Box<JobResult>),
}

/// An error on the way, with what the job did before it.
fn after(f: Fail, r: JobResult) -> Fail {
    match f {
        Fail::Error(s, c) => Fail::ErrorAfter(s, c, Box::new(r)),
        f => f,
    }
}

fn run_job(spool: &dyn Spool, job: Job, p: &Params) -> Result<JobResult, Fail> {
    use crate::ports::{MONITOR_TCP, MONITOR_WSD};
    let read = |e: u32| Fail::Error(Stage::Read, e);
    let printers = || spool.printers().map_err(read);
    // A printer parameter: a local printer the helper itself lists, never a shared one.
    let printer = |list: &[Local]| -> Result<Local, Fail> {
        let name = p.printer.as_ref().ok_or(Fail::Refused(Reason::NoPrinter))?;
        let l = find_printer(list, name).ok_or(Fail::Refused(Reason::NoPrinter))?;
        if l.shared {
            return Err(Fail::Refused(Reason::Shared));
        }
        Ok(l.clone())
    };
    let ports = || spool.ports().map_err(read);
    let tcp_port = |name: &str| -> Result<TcpConfig, Fail> {
        let all = ports()?;
        let (_, mon) = all.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).ok_or(Fail::Refused(Reason::NoPort))?;
        if !mon.eq_ignore_ascii_case(MONITOR_TCP) {
            return Err(Fail::Refused(Reason::NotTcpPort));
        }
        spool.tcp_config(name).ok_or(Fail::Error(Stage::Read, 2))
    };
    // A TCP/IP port to `ip`: an existing one with the same address (kept as it is: its own
    // protocol and SNMP check go into the result), else a new name.
    let port_for = |ip: Ipv4Addr, protocol: Protocol, snmp: bool, r: &mut JobResult| -> Result<String, Fail> {
        let all = ports()?;
        let existing: Vec<(String, String)> = all
            .iter()
            .map(|(n, mon)| {
                let target = if mon.eq_ignore_ascii_case(MONITOR_TCP) { spool.tcp_config(n).map(|c| c.target().to_string()).unwrap_or_default() } else { format!("\u{0}{mon}") };
                (n.clone(), target)
            })
            .collect();
        let (name, reused) = crate::ports::port_name_for(ip, &existing);
        if existing.iter().any(|(n, _)| n.eq_ignore_ascii_case(&name)) && !reused {
            return Err(Fail::Refused(Reason::PortTaken));
        }
        if reused {
            let kept = spool.tcp_config(&name);
            r.reused_protocol = kept.as_ref().map(|c| crate::text::clean_max(&c.protocol_words(), NAME_CHARS));
            r.reused_snmp = kept.map(|c| c.snmp);
        } else {
            spool.add_port(&PortConfig::new(&name, ip, protocol, snmp)).map_err(|e| Fail::Error(Stage::AddPort, e))?;
        }
        r.port = Some(name.clone());
        r.reused = reused;
        Ok(name)
    };
    match job {
        Job::PrinterOnline => {
            let l = printer(&printers()?)?;
            spool.clear_attributes(&l.name, crate::printers::ATTR_WORK_OFFLINE).map_err(|e| Fail::Error(Stage::SetPrinter, e))?;
            Ok(JobResult::default())
        }
        Job::PortToTcp => {
            let l = printer(&printers()?)?;
            if !l.port.eq_ignore_ascii_case(p.port.as_deref().unwrap_or("")) {
                return Err(Fail::Refused(Reason::PortChanged));
            }
            let mut r = JobResult::default();
            let name = port_for(p.ipv4.unwrap(), p.protocol.unwrap(), p.snmp.unwrap(), &mut r)?;
            spool.set_port(&l.name, &name).map_err(|e| Fail::Error(Stage::SetPrinter, e))?;
            Ok(r)
        }
        Job::PortSet => {
            let l = printer(&printers()?)?;
            let port = p.port.clone().unwrap();
            let all = ports()?;
            let (name, mon) = all.iter().find(|(n, _)| n.eq_ignore_ascii_case(&port)).ok_or(Fail::Refused(Reason::NoPort))?;
            if !(mon.eq_ignore_ascii_case(MONITOR_TCP) || mon.eq_ignore_ascii_case(MONITOR_WSD)) {
                return Err(Fail::Refused(Reason::NotTcpPort));
            }
            spool.set_port(&l.name, name).map_err(|e| Fail::Error(Stage::SetPrinter, e))?;
            Ok(JobResult { port: Some(name.clone()), ..JobResult::default() })
        }
        Job::PortAddress => {
            let port = p.port.clone().unwrap();
            let c = tcp_port(&port)?;
            let new = PortConfig { host: p.ipv4.unwrap().to_string(), ..PortConfig::from_tcp(&port, &c) };
            spool.config_port(&new).map_err(|e| Fail::Error(Stage::ConfigPort, e))?;
            Ok(JobResult { port: Some(port), ..JobResult::default() })
        }
        Job::PortSnmpOff | Job::PortSnmpOn => {
            let port = p.port.clone().unwrap();
            let c = tcp_port(&port)?;
            let on = job == Job::PortSnmpOn;
            let mut new = PortConfig::from_tcp(&port, &c);
            new.snmp = on;
            if on {
                // The recorded community, never `public` over a custom one (AUDIT-1 PRINT-12).
                new.community = p.community.clone().unwrap();
                new.snmp_index = new.snmp_index.max(1);
            }
            spool.config_port(&new).map_err(|e| Fail::Error(Stage::ConfigPort, e))?;
            Ok(JobResult { port: Some(port), ..JobResult::default() })
        }
        Job::PrinterAdd => {
            let list = printers()?;
            let name = p.name.clone().unwrap();
            if find_printer(&list, &name).is_some() {
                return Err(Fail::Refused(Reason::NameTaken));
            }
            let driver = p.driver.clone().unwrap();
            let Some(drv) = spool.drivers().into_iter().find(|d| d.eq_ignore_ascii_case(&driver)) else { return Err(Fail::Refused(Reason::NoDriver)) };
            let mut r = JobResult::default();
            let port = port_for(p.ipv4.unwrap(), p.protocol.unwrap(), p.snmp.unwrap(), &mut r)?;
            spool.add_printer(&name, &port, &drv).map_err(|e| Fail::Error(Stage::AddPrinter, e))?;
            Ok(r)
        }
        Job::PrinterDelete => {
            let l = printer(&printers()?)?;
            if !l.port.eq_ignore_ascii_case(p.port.as_deref().unwrap_or("")) {
                return Err(Fail::Refused(Reason::NotPrinterPort));
            }
            spool.delete_printer(&l.name).map_err(|e| Fail::Error(Stage::DeletePrinter, e))?;
            Ok(JobResult::default())
        }
        Job::SpoolerRestart => {
            let mut r = JobResult::default();
            if spool.spooler() == Spooler::Disabled {
                if !p.enable.unwrap_or(false) {
                    return Err(Fail::Refused(Reason::SpoolerDisabled));
                }
                spool.set_auto_start().map_err(|e| Fail::Error(Stage::ConfigSpooler, e))?;
                r.enabled = true;
            }
            let mut deps = Vec::new();
            let done = stop_spooler(spool, &mut deps).and_then(|()| spool.start_spooler(SPOOLER_START_WAIT).map_err(|e| Fail::Error(Stage::StartSpooler, e)));
            // Exactly the dependents that ran before, on every path; an error says them too.
            restart_dependents(spool, &deps, &mut r);
            match done {
                Ok(()) => Ok(r),
                Err(f) => Err(after(f, r)),
            }
        }
        Job::QueueClear => {
            let l = printer(&printers()?)?;
            let mut r = JobResult::default();
            // Dev builds in Windows Sandbox can skip the purge to reach the spool-file path.
            #[cfg(feature = "dev-hooks")]
            let skip = crate::dev::no_purge();
            #[cfg(not(feature = "dev-hooks"))]
            let skip = false;
            if !skip {
                spool.purge(&l.name).map_err(|e| Fail::Error(Stage::Purge, e))?;
                r.purged = true;
            }
            // Up to 10 s for the spooler's own way to finish. A count that cannot be read is
            // told: the spooler is never stopped on it (AUDIT-1 PRINT-15).
            let mut left = spool.job_count(&l.name).map_err(read)?;
            for _ in 0..20 {
                if left == 0 {
                    break;
                }
                spool.pause(Duration::from_millis(500));
                left = spool.job_count(&l.name).map_err(read)?;
            }
            if left == 0 {
                r.remaining = Some(0);
                return Ok(r);
            }
            // Still there: stop the spooler, delete only this printer's SHD/SPL pairs, start it.
            r.stopped = true;
            let mut deps = Vec::new();
            let done = stop_spooler(spool, &mut deps).and_then(|()| {
                // A folder that cannot be listed is said, never taken for an empty one (FEC4).
                let files = spool.spool_files().unwrap_or_else(|e| {
                    r.spool_unread = Some(e);
                    Vec::new()
                });
                let plan = crate::shd::plan(&l.name, &files);
                for stem in &plan.ours {
                    for ext in ["SHD", "SPL"] {
                        let name = files.iter().map(|f| f.0.as_str()).find(|n| n.rsplit_once('.').is_some_and(|(s, e)| s == stem && e.eq_ignore_ascii_case(ext)));
                        if let Some(n) = name {
                            match spool.delete_spool_file(n) {
                                Ok(()) => note(&mut r.removed, &mut r.removed_count, n),
                                Err(e) => note(&mut r.left, &mut r.left_count, &format!("{n}: {}", code_words(e))),
                            }
                        }
                    }
                }
                for (n, why) in plan.left {
                    note(&mut r.left, &mut r.left_count, &format!("{n}: {}", crate::text::clean_max(&why, 120)));
                }
                spool.start_spooler(SPOOLER_START_WAIT).map_err(|e| Fail::Error(Stage::StartSpooler, e))
            });
            // Exactly the dependents that ran before, on every path; an error says them and
            // the files removed too.
            restart_dependents(spool, &deps, &mut r);
            if let Err(f) = done {
                return Err(after(f, r));
            }
            // Unreadable after the start: said as not known, never as an empty queue.
            r.remaining = spool.job_count(&l.name).ok();
            Ok(r)
        }
    }
}

#[cfg(windows)]
mod sys {
    use super::*;
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::Storage::FileSystem::*;
    use windows_sys::Win32::System::IO::*;
    use windows_sys::Win32::System::Pipes::*;
    use windows_sys::Win32::System::Threading::*;

    /// This exe's path, as Windows has it (exact UTF-16 units).
    pub fn own_exe() -> Option<Vec<u16>> {
        use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
        let mut buf = vec![0u16; 32_768];
        // SAFETY: a buffer and its length in units.
        let n = unsafe { GetModuleFileNameW(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32) } as usize;
        (n > 0 && n < buf.len()).then(|| buf[..n].to_vec())
    }

    /// The image path of process `pid` (None when it cannot be opened or asked).
    pub fn image_of(pid: u32) -> Option<Vec<u16>> {
        // SAFETY: a query-only open of a process by id; closed below.
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 32_768];
        let mut n = buf.len() as u32;
        // SAFETY: a buffer and its length in units.
        let ok = unsafe { QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut n) } != 0;
        unsafe { CloseHandle(h) };
        ok.then(|| buf[..n as usize].to_vec())
    }

    /// A file's identity (`FILE_ID_INFO`, else the serial and 64-bit index).
    pub fn file_id(path: &[u16]) -> Option<FileIdent> {
        let mut p = path.to_vec();
        p.push(0);
        // SAFETY: a NUL-terminated path, attributes only, sharing everything; closed below.
        let h = unsafe { CreateFileW(p.as_ptr(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, std::ptr::null(), OPEN_EXISTING, 0, std::ptr::null_mut()) };
        if h == INVALID_HANDLE_VALUE {
            return None;
        }
        // SAFETY: plain structs filled by the calls, sizes given.
        let id = unsafe {
            let mut info: FILE_ID_INFO = std::mem::zeroed();
            if GetFileInformationByHandleEx(h, FileIdInfo, (&mut info as *mut FILE_ID_INFO).cast(), size_of::<FILE_ID_INFO>() as u32) != 0 {
                Some((info.VolumeSerialNumber, info.FileId.Identifier))
            } else {
                let mut bh: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
                (GetFileInformationByHandle(h, &mut bh) != 0).then(|| fallback_id(bh.dwVolumeSerialNumber, bh.nFileIndexHigh, bh.nFileIndexLow))
            }
        };
        unsafe { CloseHandle(h) };
        id
    }

    /// Two paths name the same file, by identity (a zero id never does).
    pub fn same_file(a: &[u16], b: &[u16]) -> bool {
        match (file_id(a), file_id(b)) {
            (Some(x), Some(y)) => same_id(x, y),
            _ => false,
        }
    }

    /// The path the helper is started from: this exe's final path (VibeLink R-LINK-1: the
    /// elevated session has its own drive letters).
    pub fn launch_path() -> Option<Vec<u16>> {
        own_exe().map(|p| launch_path_of(&p))
    }

    pub(super) fn launch_path_of(p: &[u16]) -> Vec<u16> {
        final_path(p).map(plain_if_valid).unwrap_or_else(|| p.to_vec())
    }

    fn final_path(path: &[u16]) -> Option<Vec<u16>> {
        let mut p = path.to_vec();
        p.push(0);
        // SAFETY: a NUL-terminated path, attributes only, sharing everything; closed below.
        let h = unsafe { CreateFileW(p.as_ptr(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, std::ptr::null(), OPEN_EXISTING, 0, std::ptr::null_mut()) };
        if h == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut buf = vec![0u16; 32_768];
        // SAFETY: a buffer and its length in units.
        let n = unsafe { GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), buf.len() as u32, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) } as usize;
        unsafe { CloseHandle(h) };
        (n > 0 && n < buf.len()).then(|| buf[..n].to_vec())
    }

    fn plain_if_valid(verbatim: Vec<u16>) -> Vec<u16> {
        let Some(plain) = super::strip_verbatim(&verbatim) else { return verbatim };
        let mut z = plain.clone();
        z.push(0);
        let mut buf = vec![0u16; 32_768];
        // SAFETY: a NUL-terminated path, a buffer and its length in units.
        let n = unsafe { GetFullPathNameW(z.as_ptr(), buf.len() as u32, buf.as_mut_ptr(), std::ptr::null_mut()) } as usize;
        if plain.len() < MAX_PATH as usize && n > 0 && n < buf.len() && buf[..n] == plain[..] { plain } else { verbatim }
    }

    pub fn random16() -> Option<[u8; 16]> {
        use windows_sys::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};
        let mut b = [0u8; 16];
        // SAFETY: a 16-byte buffer; the system's preferred generator.
        (unsafe { BCryptGenRandom(std::ptr::null_mut(), b.as_mut_ptr(), 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG) } == 0).then_some(b)
    }

    /// The process runs elevated (its token's TokenElevation).
    pub fn elevated() -> bool {
        let mut tok: HANDLE = std::ptr::null_mut();
        // SAFETY: the current process's token, query only; closed below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) } == 0 {
            return false;
        }
        let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut n = 0u32;
        let ok = unsafe { GetTokenInformation(tok, TokenElevation, (&mut e as *mut TOKEN_ELEVATION).cast(), size_of::<TOKEN_ELEVATION>() as u32, &mut n) } != 0;
        unsafe { CloseHandle(tok) };
        ok && e.TokenIsElevated != 0
    }

    /// A security descriptor whose DACL allows only the current user (read and write).
    struct UserOnly {
        _token_user: Vec<u64>,
        _acl: Vec<u64>,
        sd: Box<SECURITY_DESCRIPTOR>,
    }

    fn user_only() -> Option<UserOnly> {
        let mut tok: HANDLE = std::ptr::null_mut();
        // SAFETY: the current process's token, query only; closed below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) } == 0 {
            return None;
        }
        let mut need = 0u32;
        unsafe { GetTokenInformation(tok, TokenUser, std::ptr::null_mut(), 0, &mut need) };
        let mut tu = vec![0u64; (need as usize).div_ceil(8).max(8)];
        let ok = unsafe { GetTokenInformation(tok, TokenUser, tu.as_mut_ptr().cast(), (tu.len() * 8) as u32, &mut need) } != 0;
        unsafe { CloseHandle(tok) };
        if !ok {
            return None;
        }
        // SAFETY: the buffer holds a TOKEN_USER written by the call above.
        let sid = unsafe { (*(tu.as_ptr() as *const TOKEN_USER)).User.Sid };
        let sid_len = unsafe { GetLengthSid(sid) } as usize;
        let acl_len = size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() + sid_len;
        let mut acl = vec![0u64; acl_len.div_ceil(8)];
        let pacl = acl.as_mut_ptr() as *mut ACL;
        // SAFETY: an ACL buffer of `acl_len` bytes; one ACE for the user's SID.
        unsafe {
            if InitializeAcl(pacl, acl_len as u32, ACL_REVISION) == 0 || AddAccessAllowedAce(pacl, ACL_REVISION, GENERIC_READ | GENERIC_WRITE, sid) == 0 {
                return None;
            }
        }
        let mut sd: Box<SECURITY_DESCRIPTOR> = Box::new(unsafe { std::mem::zeroed() });
        let psd = (&mut *sd as *mut SECURITY_DESCRIPTOR).cast();
        // SAFETY: a descriptor in our memory, the DACL above (both outlive the pipe's creation).
        unsafe {
            if InitializeSecurityDescriptor(psd, 1 /* SECURITY_DESCRIPTOR_REVISION */) == 0 || SetSecurityDescriptorDacl(psd, 1, pacl, 0) == 0 {
                return None;
            }
        }
        Some(UserOnly { _token_user: tu, _acl: acl, sd })
    }

    /// The app's end of the pipe: one instance, overlapped, user-only, no remote clients.
    pub struct Server {
        pub h: HANDLE,
        pub name: String,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            // SAFETY: created in `create`, closed once.
            unsafe { CloseHandle(self.h) };
        }
    }

    // SAFETY: the handle is used by one thread at a time (the job's worker).
    unsafe impl Send for Server {}

    pub fn create() -> Result<Server, String> {
        let r = random16().ok_or("no random numbers from the system")?;
        let name = pipe_name(&r);
        let sec = user_only().ok_or("the pipe's access rules could not be made")?;
        let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: (&*sec.sd as *const SECURITY_DESCRIPTOR) as *mut _, bInheritHandle: 0 };
        let w = crate::host::wide(&name);
        // SAFETY: a NUL-terminated name and attributes that live through the call.
        let h = unsafe {
            CreateNamedPipeW(w.as_ptr(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 0, &sa)
        };
        drop(sec);
        if h == INVALID_HANDLE_VALUE {
            return Err(format!("the pipe did not open ({})", std::io::Error::last_os_error()));
        }
        Ok(Server { h, name })
    }

    /// How an overlapped wait ended.
    pub enum End {
        Done(u32),
        Deadline,
        Stopped,
        ProcessGone,
        Error(u32),
    }

    /// Wait for an overlapped operation in 100 ms steps until done, `deadline`, `stop`, or
    /// `process` ends; anything but done cancels it first.
    pub fn wait(h: HANDLE, ov: &mut OVERLAPPED, deadline: Instant, stop: &AtomicBool, process: HANDLE) -> End {
        loop {
            let mut n = 0u32;
            // SAFETY: the operation started on `h` with `ov`; a 100 ms wait.
            if unsafe { GetOverlappedResultEx(h, ov, &mut n, 100, 0) } != 0 {
                return End::Done(n);
            }
            let e = unsafe { GetLastError() };
            if e != WAIT_TIMEOUT && e != WAIT_IO_COMPLETION && e != ERROR_IO_INCOMPLETE {
                return End::Error(e);
            }
            let why = if Instant::now() >= deadline {
                Some(End::Deadline)
            } else if stop.load(Ordering::SeqCst) {
                Some(End::Stopped)
            } else if !process.is_null() && unsafe { WaitForSingleObject(process, 0) } == WAIT_OBJECT_0 {
                Some(End::ProcessGone)
            } else {
                None
            };
            if let Some(w) = why {
                // SAFETY: cancel our own operation, then wait for it to finish with `ov`.
                unsafe {
                    CancelIoEx(h, ov);
                    let mut n = 0u32;
                    GetOverlappedResult(h, ov, &mut n, 1);
                }
                return w;
            }
        }
    }

    pub struct Event(pub HANDLE);
    impl Drop for Event {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    pub fn event() -> Event {
        // SAFETY: an unnamed manual-reset event.
        Event(unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) })
    }

    pub fn overlapped(ev: &Event) -> OVERLAPPED {
        // SAFETY: all-zero is a valid OVERLAPPED.
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = ev.0;
        ov
    }

    /// The relaunch: this exe (from its final path), elevated, with the job's arguments. Blocks
    /// until the UAC prompt is answered. Ok(process handle), or Err(Win32 code): 1223 is "the
    /// user said no".
    pub fn relaunch(job: Job, pipe: &str, hwnd: isize) -> Result<HANDLE, u32> {
        use windows_sys::Win32::System::Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx};
        use windows_sys::Win32::UI::Shell::{SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
        let mut file = launch_path().ok_or(2u32)?;
        file.push(0);
        let params = crate::host::wide(&super::args(job, pipe).join(" "));
        let verb = crate::host::wide("runas");
        // SAFETY: COM for the shell on this thread; the struct's strings outlive the call.
        unsafe {
            CoInitializeEx(std::ptr::null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32);
            let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
            info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
            info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
            info.hwnd = hwnd as *mut _;
            info.lpVerb = verb.as_ptr();
            info.lpFile = file.as_ptr();
            info.lpParameters = params.as_ptr();
            info.nShow = 0; // SW_HIDE: the helper has no window anyway
            if ShellExecuteExW(&mut info) == 0 {
                return Err(GetLastError());
            }
            if info.hProcess.is_null() {
                return Err(ERROR_INVALID_HANDLE);
            }
            Ok(info.hProcess)
        }
    }

    /// One admin step, start to end, on the calling (worker) thread. `stop` ends it early (the
    /// window closed): the pipe closes, the helper sees it and exits.
    pub fn run(job: Job, p: &Params, hwnd: isize, stop: &AtomicBool) -> Outcome {
        let started = Instant::now();
        let server = match create() {
            Ok(s) => s,
            Err(e) => return Outcome::Failed(e),
        };
        let process = match relaunch(job, &server.name, hwnd) {
            Ok(p) => p,
            Err(1223) => return Outcome::Declined,
            Err(e) => return Outcome::Failed(format!("the helper did not start ({})", code_words(e))),
        };
        struct Proc(HANDLE);
        impl Drop for Proc {
            fn drop(&mut self) {
                unsafe { CloseHandle(self.0) };
            }
        }
        let proc_ = Proc(process);
        let pid = unsafe { GetProcessId(process) };
        if stop.load(Ordering::SeqCst) {
            return Outcome::Stopped;
        }
        let nonce = random16().unwrap_or([7; 16]);
        serve(&server, proc_.0, pid, job, p, nonce, started + CONNECT_WAIT, stop)
    }

    /// Wait for the helper (`pid`, started as `process`) to connect until `deadline`, check it
    /// is that process running this exe, send the request, then read what it says until it is
    /// done, refuses, fails, goes away, or passes its hard limit.
    #[allow(clippy::too_many_arguments)]
    pub fn serve(server: &Server, process: HANDLE, pid: u32, job: Job, p: &Params, nonce: [u8; 16], deadline: Instant, stop: &AtomicBool) -> Outcome {
        let ev = event();
        let mut ov = overlapped(&ev);
        // SAFETY: an overlapped connect on our pipe.
        let r = unsafe { ConnectNamedPipe(server.h, &mut ov) };
        let err = unsafe { GetLastError() };
        if r == 0 && err != ERROR_PIPE_CONNECTED {
            if err != ERROR_IO_PENDING {
                return Outcome::Failed(format!("the pipe did not wait ({})", code_words(err)));
            }
            match wait(server.h, &mut ov, deadline, stop, process) {
                End::Done(_) => {}
                End::Deadline => return Outcome::NeverConnected("the helper did not connect within 2 minutes".into()),
                End::Stopped => return Outcome::Stopped,
                End::ProcessGone => return Outcome::NeverConnected("the helper ended before it connected".into()),
                End::Error(e) => return Outcome::Failed(format!("the pipe failed ({})", code_words(e))),
            }
        }
        // Who connected: the process we started, running this exe.
        let mut client = 0u32;
        let ok = unsafe { GetNamedPipeClientProcessId(server.h, &mut client) } != 0;
        let same = match (own_exe(), image_of(client)) {
            (Some(a), Some(b)) => same_file(&a, &b),
            _ => false,
        };
        if !ok || client != pid || !same {
            return Outcome::Failed("something else connected to the helper's pipe: it was closed".into());
        }
        let never = AtomicBool::new(false);
        let end = Instant::now() + job.hard_limit() + Duration::from_secs(5);
        {
            let req = request(job, &nonce, p);
            let ev = event();
            let mut ov = overlapped(&ev);
            // SAFETY: an overlapped write of `req`, waited for before `req` goes.
            let r = unsafe { WriteFile(server.h, req.as_ptr(), req.len() as u32, std::ptr::null_mut(), &mut ov) };
            if r == 0 && unsafe { GetLastError() } == ERROR_IO_PENDING {
                if !matches!(wait(server.h, &mut ov, end, &never, std::ptr::null_mut()), End::Done(_)) {
                    return Outcome::Gone;
                }
            } else if r == 0 {
                return Outcome::Gone;
            }
        }
        let mut dec = Decoder::new(nonce);
        let mut got = Collect::new(pid);
        let mut buf = vec![0u8; 4096];
        loop {
            let ev = event();
            let mut ov = overlapped(&ev);
            // SAFETY: an overlapped read into `buf`, waited for below before `buf` is touched.
            let r = unsafe { ReadFile(server.h, buf.as_mut_ptr(), buf.len() as u32, std::ptr::null_mut(), &mut ov) };
            let err = unsafe { GetLastError() };
            let n = if r != 0 {
                let mut n = 0u32;
                unsafe { GetOverlappedResult(server.h, &ov, &mut n, 1) };
                n
            } else if err == ERROR_IO_PENDING {
                match wait(server.h, &mut ov, end, stop, std::ptr::null_mut()) {
                    End::Done(n) => n,
                    End::Stopped => return Outcome::Stopped,
                    _ => return Outcome::Gone,
                }
            } else {
                return Outcome::Gone; // ERROR_BROKEN_PIPE: the helper is gone
            };
            match dec.push(&buf[..n as usize]) {
                Ok(msgs) => {
                    for m in msgs {
                        if !got.take(m) {
                            return got.outcome.take().unwrap_or(Outcome::Gone);
                        }
                    }
                }
                Err(e) => return Outcome::Failed(e),
            }
            if n == 0 {
                return Outcome::Gone;
            }
        }
    }

    // ---------- the helper's side ----------

    /// The helper's end of the pipe (synchronous: one thread reads and writes).
    pub struct Client(pub HANDLE);
    impl Drop for Client {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    impl Client {
        pub fn send(&self, b: &[u8]) -> bool {
            let mut n = 0u32;
            // SAFETY: a synchronous write of `b`.
            unsafe { WriteFile(self.0, b.as_ptr(), b.len() as u32, &mut n, std::ptr::null_mut()) != 0 && n as usize == b.len() }
        }

        fn read_exact(&self, out: &mut [u8]) -> bool {
            let mut have = 0usize;
            while have < out.len() {
                let mut n = 0u32;
                // SAFETY: a synchronous read into the rest of `out`.
                if unsafe { ReadFile(self.0, out[have..].as_mut_ptr(), (out.len() - have) as u32, &mut n, std::ptr::null_mut()) } == 0 || n == 0 {
                    return false;
                }
                have += n as usize;
            }
            true
        }

        /// The app's request payload (None when the pipe breaks first or it is not one).
        pub fn read_request(&self) -> Option<Vec<u8>> {
            let mut h = [0u8; 5];
            if !self.read_exact(&mut h) || h[0] != KIND_REQUEST {
                return None;
            }
            let len = u32::from_le_bytes(h[1..5].try_into().unwrap()) as usize;
            if !(18..=MAX_REQUEST).contains(&len) {
                return None;
            }
            let mut b = vec![0u8; len];
            self.read_exact(&mut b).then_some(b)
        }
    }

    /// Connect to the app's pipe, identification-level only (the app cannot act as us), and
    /// check that its server is this exe.
    pub fn connect(pipe: &str) -> Option<Client> {
        let w = crate::host::wide(pipe);
        for _ in 0..3 {
            // SAFETY: a NUL-terminated name; the handle is ours.
            let h = unsafe { CreateFileW(w.as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, std::ptr::null(), OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, std::ptr::null_mut()) };
            if h == INVALID_HANDLE_VALUE {
                if unsafe { GetLastError() } == ERROR_PIPE_BUSY {
                    unsafe { WaitNamedPipeW(w.as_ptr(), 2000) };
                    continue;
                }
                return None;
            }
            let c = Client(h);
            let mut server = 0u32;
            if unsafe { GetNamedPipeServerProcessId(h, &mut server) } == 0 {
                return None;
            }
            let (mine, theirs) = (own_exe()?, image_of(server)?);
            return same_file(&mine, &theirs).then_some(c);
        }
        None
    }
}

#[cfg(windows)]
pub use sys::{Client, connect, elevated, file_id, run, same_file, serve};

/// The helper's whole life (`VibePrint.exe --helper <job> <pipe>`): the exit code.
/// 2: bad arguments, 3: not elevated, 4: the hard limit, 5: the pipe or its server was wrong (or
/// broke), 6: the request did not match the job.
#[cfg(windows)]
pub fn run_helper(args: &[String]) -> i32 {
    let Some((job, pipe)) = parse_args(args) else { return 2 };
    if !elevated() {
        return 3;
    }
    let limit = job.hard_limit();
    std::thread::spawn(move || {
        std::thread::sleep(limit);
        // SAFETY: ends this process; Windows closes its handles with it.
        unsafe { windows_sys::Win32::System::Threading::ExitProcess(4) };
    });
    let Some(client) = connect(&pipe) else { return 5 };
    if !client.send(&hello(std::process::id())) {
        return 5;
    }
    let Some(req) = client.read_request() else { return 5 };
    let Some((nonce, params)) = parse_request(&req, job) else { return 6 };
    let msg = work(&crate::xcv::RealSpool, job, &nonce, &params);
    if client.send(&msg) { 0 } else { 5 }
}
