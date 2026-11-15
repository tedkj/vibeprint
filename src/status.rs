//! The real status: one line per printer, the first rule that applies (SPEC section 2), and the
//! fix it points at. Pure: the facts in, the words out.
//!
//! 1. The Print Spooler is stopped or disabled.
//! 2. Windows was told to use this printer offline.
//! 3. The device answers (IPP, SNMP, 9100 or 515): when Windows thinks it is offline, why (by the
//!    port's kind); when the device reports a fault, the fault. A device that answers and is fine
//!    lets a stuck job (rule 5) speak first, then says its own state (deviation, DECISIONS.md: a
//!    stuck job is worth more than "Ready").
//! 4. The device answers nothing: off, asleep, or a new address.
//! 5. A stuck job.
//! 6. Windows' own state.
//!
//! "Checking…" while a network printer's probe has not answered (green waits for every answer).

use crate::ports::Kind;
use crate::printers::{Printer, Read, Spooler};
use crate::probe::{Answers, Probe};
use crate::queue::Stuck;

/// The family's state codes: 0 checking, 1 ok, 2 quiet, 3 warning, 4 broken, 5 unknown.
pub const CHECKING: i32 = 0;
pub const OK: i32 = 1;
pub const QUIET: i32 = 2;
pub const WARN: i32 = 3;
pub const BROKEN: i32 = 4;
pub const UNKNOWN: i32 = 5;

/// The fix a line points at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fix {
    RestartSpooler,
    UseOnline,
    SwitchToTcp,
    SnmpOff,
    Find,
    ClearQueue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub text: String,
    pub state: i32,
    pub fix: Option<Fix>,
}

impl Line {
    fn new(text: impl Into<String>, state: i32, fix: Option<Fix>) -> Line {
        Line { text: text.into(), state, fix }
    }
}

/// What Windows (and VibePrint's journal) knows of a printer's device, to tell it from another
/// device at the same address (AUDIT-1 PRINT-3, DECISIONS.md "Which device answers").
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Known {
    /// Its MAC: the WSD record's (PnP-X), else the one recorded when VibePrint set it up.
    pub mac: Option<crate::net::Mac>,
    /// Its printer-uuid: the WSD record's (equal to the IPP printer-uuid, measured on Ted's
    /// Canon), else the IPP printer-uuid recorded when VibePrint set it up (AUDIT-1 R-PRINT-2).
    pub uuid: Option<String>,
    /// Recorded when VibePrint set it up: the Printer MIB serial number and the model (IPP's
    /// make and model, else SNMP's sysDescr).
    pub serial: Option<String>,
    pub model: Option<String>,
    /// The port names the device by its mDNS name (`*.local`): whatever answers there is it.
    pub mdns_name: bool,
    /// The maker its driver names, when the driver is a maker's own (class drivers name none).
    pub driver_maker: Option<&'static str>,
}

/// What a device that answered says it is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Device<'a> {
    pub mac: Option<crate::net::Mac>,
    pub uuid: Option<&'a str>,
    pub serial: Option<&'a str>,
    pub model: Option<&'a str>,
}

impl<'a> Device<'a> {
    pub fn of(a: &'a Answers, model: Option<&'a str>) -> Device<'a> {
        let uuid = match &a.ipp {
            Some(crate::ipp::Outcome::Answered(x)) => x.uuid.as_deref(),
            _ => None,
        };
        let serial = match &a.snmp {
            crate::snmp::Outcome::Answered(s) => s.serial.as_deref(),
            _ => None,
        };
        Device { mac: a.mac, uuid, serial, model }
    }
}

/// Whether the device that answers at a printer's address is that printer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ident {
    /// Its identity matches what Windows knows.
    Same,
    /// It does not: what it is instead ("a Canon GX6000 series", "MAC F4:81:39:00:53:C9").
    Other(String),
    /// Windows knows nothing it could be compared with.
    Unconfirmed,
}

fn uuid_key(s: &str) -> String {
    let l = s.trim().to_ascii_lowercase();
    l.strip_prefix("urn:uuid:").unwrap_or(&l).chars().filter(|c| c.is_ascii_hexdigit()).collect()
}

/// A serial number as compared: its letters and digits, upper case.
fn serial_key(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect()
}

/// The device against what Windows knows, strongest first (Ted's order, AUDIT-1 R-PRINT-1): the
/// printer-uuid (per printer, whatever interface answers), the serial number, the MAC (per
/// interface), the mDNS name, the model (each side's normalised: `drivers::model_of`), the
/// driver's maker. The first that both sides have decides.
pub fn ident(k: &Known, d: &Device) -> Ident {
    let model = || d.model.map(|m| format!("a {}", crate::text::clean_max(m, 60)));
    if let (Some(a), Some(b)) = (&k.uuid, d.uuid)
        && !uuid_key(a).is_empty()
        && !uuid_key(b).is_empty()
    {
        return if uuid_key(a) == uuid_key(b) { Ident::Same } else { Ident::Other(model().unwrap_or_else(|| "another printer-uuid".into())) };
    }
    if let (Some(a), Some(b)) = (&k.serial, d.serial)
        && !serial_key(a).is_empty()
        && !serial_key(b).is_empty()
    {
        return if serial_key(a) == serial_key(b) { Ident::Same } else { Ident::Other(model().unwrap_or_else(|| "another serial number".into())) };
    }
    if let (Some(a), Some(b)) = (k.mac, d.mac) {
        return if a == b { Ident::Same } else { Ident::Other(model().unwrap_or_else(|| format!("MAC {}", crate::net::mac_text(&b)))) };
    }
    if k.mdns_name {
        return Ident::Same;
    }
    if let (Some(a), Some(b)) = (k.model.as_deref().and_then(crate::drivers::model_of), d.model.and_then(crate::drivers::model_of)) {
        return if crate::drivers::same_model(&a, &b) { Ident::Same } else { Ident::Other(model().unwrap_or_default()) };
    }
    if let (Some(a), Some(b)) = (k.driver_maker, d.model.and_then(crate::drivers::maker_of)) {
        return if a == b { Ident::Same } else { Ident::Other(model().unwrap_or_default()) };
    }
    Ident::Unconfirmed
}

/// What the rules look at, for one printer.
pub struct Facts<'a> {
    pub spooler: &'a Spooler,
    pub printer: &'a Printer,
    pub kind: Kind,
    /// The address as shown ("192.168.1.50", "printer.local (192.168.1.50)").
    pub address: &'a str,
    /// The address is IPv4 (the TCP/IP switch needs one).
    pub ipv4: bool,
    /// A Standard TCP/IP port with its SNMP check on.
    pub snmp_on: bool,
    /// What Windows knows of the printer's device (to tell another device at its address).
    pub known: &'a Known,
    pub probe: &'a Probe,
    pub stuck: Option<&'a Stuck>,
    pub now: i64,
}

/// The spooler's own line (rule 1), if it is not running.
pub fn spooler_line(s: &Spooler) -> Option<Line> {
    match s {
        Spooler::Running | Spooler::Unknown(_) => None,
        Spooler::Stopped => Some(Line::new("The Print Spooler service is stopped.", BROKEN, Some(Fix::RestartSpooler))),
        Spooler::Disabled => Some(Line::new("The Print Spooler service is disabled (someone turned it off, maybe after PrintNightmare).", BROKEN, Some(Fix::RestartSpooler))),
        Spooler::Changing(w) => Some(Line::new(format!("The Print Spooler service is {w}."), WARN, None)),
        Spooler::Silent(secs) => Some(Line::new(format!("The Print Spooler did not answer in {secs} s. A stuck print job or printer driver can hang it; restarting it usually helps."), BROKEN, Some(Fix::RestartSpooler))),
    }
}

/// Why Windows thinks an answering printer is offline, by the port's kind, and the fix.
fn offline_cause(f: &Facts, a: &Answers) -> (String, Option<Fix>) {
    match f.kind {
        Kind::Wsd if f.ipv4 => ("WSD ports drop out; switch to a TCP/IP port.".into(), Some(Fix::SwitchToTcp)),
        Kind::Wsd => ("WSD ports drop out (a TCP/IP port needs an IPv4 address).".into(), None),
        // VibePrint's own SNMP question could not be sent: whether SNMP is the cause is not
        // known, so the check is never blamed on it (AUDIT-1 PRINT-4).
        Kind::Tcp if f.snmp_on && matches!(a.snmp, crate::snmp::Outcome::Failed(_)) => (
            "whether its SNMP check is the cause is not known (VibePrint's own SNMP question could not be sent): restart the print spooler.".into(),
            Some(Fix::RestartSpooler),
        ),
        // Silent to the port's own community (the probe asks with it), and only while 9100 or
        // 515 answers: a port whose printing protocol is silent too would not print with the
        // check off either.
        Kind::Tcp if f.snmp_on && matches!(a.snmp, crate::snmp::Outcome::Silent) && (a.open(9100) || a.open(515)) => (
            "Windows asks the printer over SNMP and gets no answer, so it shows offline: turn the SNMP check off for this port.".into(),
            Some(Fix::SnmpOff),
        ),
        _ => ("restart the print spooler.".into(), Some(Fix::RestartSpooler)),
    }
}

/// Rule 6: Windows' own state.
fn windows_line(p: &Printer) -> Line {
    let words = p.windows_words();
    let state = if p.status & crate::printers::FAULTS != 0 {
        BROKEN
    } else if p.status & (crate::printers::PRINTER_STATUS_TONER_LOW | crate::printers::PRINTER_STATUS_PAUSED | crate::printers::PRINTER_STATUS_DRIVER_UPDATE_NEEDED) != 0 {
        WARN
    } else {
        OK
    };
    Line::new(if state == OK && words == "Ready" { "Ready".to_string() } else { format!("{words} (as Windows sees it)") }, state, None)
}

/// The real status of one printer.
pub fn real_status(f: &Facts) -> Line {
    // 1. The spooler.
    if let Some(l) = spooler_line(f.spooler) {
        return l;
    }
    let p = f.printer;
    // A shared printer whose server did not answer: nothing more is known.
    match &p.read {
        Read::ServerSilent => {
            let server = crate::text::clean_max(p.server.trim_start_matches('\\'), 60);
            return Line::new(format!("The PC sharing it ({server}) did not answer in 5 s: its state is unknown."), UNKNOWN, None);
        }
        Read::Failed(why) => return Line::new(format!("Its state could not be read: {}.", crate::text::clean_max(why, 120)), UNKNOWN, None),
        Read::Ok => {}
    }
    // 2. Use printer offline.
    if p.work_offline() {
        return Line::new("Windows was told to use this printer offline.", WARN, Some(Fix::UseOnline));
    }
    match f.probe {
        Probe::Checking => return Line::new(format!("Checking {}…", f.address), CHECKING, None),
        Probe::Done(a) if a.answers() => {
            // 3. The device answers. It counts as this printer only when its identity matches
            // what Windows knows (AUDIT-1 PRINT-3): another device there is said as such, with
            // no port fix; one nothing can be compared with is said unconfirmed.
            let model = a.model();
            let id = ident(f.known, &Device::of(a, model.as_deref()));
            if let Ident::Other(what) = &id {
                let what = if what.is_empty() { String::new() } else { format!(" ({what})") };
                return Line::new(format!("A different device answers at {}{what}: '{}' is not there. Search the LAN.", f.address, crate::text::clean_max(&p.display(), 80)), BROKEN, Some(Fix::Find));
            }
            let (words, fault) = a.state();
            if id == Ident::Unconfirmed {
                if p.windows_offline() {
                    return Line::new(
                        format!("A device answers at {} ({}), but Windows thinks it is offline, and nothing Windows knows confirms the device is this printer: restart the print spooler, or Search the LAN.", f.address, words.to_lowercase()),
                        WARN,
                        Some(Fix::RestartSpooler),
                    );
                }
                if let Some(s) = f.stuck {
                    return Line::new(s.line(f.now), BROKEN, Some(Fix::ClearQueue));
                }
                let state = if fault { BROKEN } else if words == "Ready" || words == "Printing" || words.starts_with("Answers") { QUIET } else { WARN };
                return Line::new(format!("{words} (not confirmed as this printer)"), state, None);
            }
            if p.windows_offline() {
                let (cause, fix) = offline_cause(f, a);
                return Line::new(format!("The printer answers at {} ({}), but Windows thinks it is offline: {cause}", f.address, words.to_lowercase()), WARN, fix);
            }
            if fault {
                return Line::new(words, BROKEN, None);
            }
            if let Some(s) = f.stuck {
                return Line::new(s.line(f.now), BROKEN, Some(Fix::ClearQueue));
            }
            // Ready, printing, or answering without saying more: fine; a warning (toner low) says so.
            let state = if words == "Ready" || words == "Printing" || words.starts_with("Answers") { OK } else { WARN };
            return Line::new(words, state, None);
        }
        Probe::Done(a) => {
            // 4. Nothing answers.
            if a.ping.replies.is_empty() {
                return Line::new(format!("No answer at {}: the printer is off, asleep, or got a new address. Search the LAN.", f.address), BROKEN, Some(Fix::Find));
            }
            return Line::new(
                format!("Something answers ping at {}, but not as a printer (no 9100, 631, 515 or SNMP): it may have a new address. Search the LAN.", f.address),
                BROKEN,
                Some(Fix::Find),
            );
        }
        Probe::NoAddress(why) if p.windows_offline() => {
            return Line::new(format!("Windows thinks it is offline, and its address is not known ({}). Search the LAN.", why.to_lowercase()), BROKEN, Some(Fix::Find));
        }
        Probe::NoAddress(_) | Probe::NotNetwork => {}
    }
    // 5. A stuck job.
    if let Some(s) = f.stuck {
        return Line::new(s.line(f.now), BROKEN, Some(Fix::ClearQueue));
    }
    // 6. Windows' own state. A network printer whose device could not be asked (a WSD device
    // with no address) is never green: green waits for every answer (AUDIT-1 PRINT-7).
    if let Probe::NoAddress(why) = f.probe {
        let l = windows_line(p);
        let state = if l.state == OK { UNKNOWN } else { l.state };
        return Line::new(format!("{} as Windows sees it; the device could not be asked ({}).", p.windows_words(), why.to_lowercase()), state, None);
    }
    let l = windows_line(p);
    if f.kind == Kind::Virtual && l.state == OK {
        return Line::new("Ready", QUIET, None);
    }
    l
}

/// The tip every network printer's details end with.
pub const FIXED_ADDRESS_TIP: &str = "Give the printer a fixed address (a DHCP reservation in the router) so it keeps working after the router restarts.";
