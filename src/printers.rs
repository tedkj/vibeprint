//! The printers as Windows has them: `EnumPrintersW(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS)`,
//! the default printer, each printer's `PRINTER_INFO_2` (status bits, attributes, port, driver,
//! jobs), and the Print Spooler service. The model and the words are plain Rust; `sys` reads.
//!
//! Level 4 lists the printers without asking any server (it is cached); level 2 is then read per
//! printer: at once for local ones, and for connections on a thread of their own with a 5 s
//! budget, so a shared printer whose server is down never holds the list (SPEC section 9).

use crate::ports::Kind;

pub const PRINTER_STATUS_PAUSED: u32 = 0x1;
pub const PRINTER_STATUS_ERROR: u32 = 0x2;
pub const PRINTER_STATUS_PENDING_DELETION: u32 = 0x4;
pub const PRINTER_STATUS_PAPER_JAM: u32 = 0x8;
pub const PRINTER_STATUS_PAPER_OUT: u32 = 0x10;
pub const PRINTER_STATUS_MANUAL_FEED: u32 = 0x20;
pub const PRINTER_STATUS_PAPER_PROBLEM: u32 = 0x40;
pub const PRINTER_STATUS_OFFLINE: u32 = 0x80;
pub const PRINTER_STATUS_IO_ACTIVE: u32 = 0x100;
pub const PRINTER_STATUS_BUSY: u32 = 0x200;
pub const PRINTER_STATUS_PRINTING: u32 = 0x400;
pub const PRINTER_STATUS_OUTPUT_BIN_FULL: u32 = 0x800;
pub const PRINTER_STATUS_NOT_AVAILABLE: u32 = 0x1000;
pub const PRINTER_STATUS_WAITING: u32 = 0x2000;
pub const PRINTER_STATUS_PROCESSING: u32 = 0x4000;
pub const PRINTER_STATUS_INITIALIZING: u32 = 0x8000;
pub const PRINTER_STATUS_WARMING_UP: u32 = 0x10000;
pub const PRINTER_STATUS_TONER_LOW: u32 = 0x20000;
pub const PRINTER_STATUS_NO_TONER: u32 = 0x40000;
pub const PRINTER_STATUS_PAGE_PUNT: u32 = 0x80000;
pub const PRINTER_STATUS_USER_INTERVENTION: u32 = 0x100000;
pub const PRINTER_STATUS_OUT_OF_MEMORY: u32 = 0x200000;
pub const PRINTER_STATUS_DOOR_OPEN: u32 = 0x400000;
pub const PRINTER_STATUS_SERVER_UNKNOWN: u32 = 0x800000;
pub const PRINTER_STATUS_POWER_SAVE: u32 = 0x1000000;
pub const PRINTER_STATUS_SERVER_OFFLINE: u32 = 0x2000000;
pub const PRINTER_STATUS_DRIVER_UPDATE_NEEDED: u32 = 0x4000000;

pub const ATTR_DEFAULT: u32 = 0x4;
pub const ATTR_SHARED: u32 = 0x8;
pub const ATTR_NETWORK: u32 = 0x10;
pub const ATTR_LOCAL: u32 = 0x40;
pub const ATTR_WORK_OFFLINE: u32 = 0x400;

/// The status bits in words, the ones that stop printing first. Empty: nothing set.
pub fn status_words(s: u32) -> Vec<&'static str> {
    const WORDS: [(u32, &str); 27] = [
        (PRINTER_STATUS_OFFLINE, "Offline"),
        (PRINTER_STATUS_ERROR, "Error"),
        (PRINTER_STATUS_PAPER_JAM, "Paper jam"),
        (PRINTER_STATUS_PAPER_OUT, "Out of paper"),
        (PRINTER_STATUS_DOOR_OPEN, "Door open"),
        (PRINTER_STATUS_NO_TONER, "Out of toner"),
        (PRINTER_STATUS_PAPER_PROBLEM, "Paper problem"),
        (PRINTER_STATUS_OUTPUT_BIN_FULL, "Output tray full"),
        (PRINTER_STATUS_USER_INTERVENTION, "Needs attention"),
        (PRINTER_STATUS_OUT_OF_MEMORY, "Out of memory"),
        (PRINTER_STATUS_NOT_AVAILABLE, "Not available"),
        (PRINTER_STATUS_SERVER_OFFLINE, "Server offline"),
        (PRINTER_STATUS_SERVER_UNKNOWN, "Server unknown"),
        (PRINTER_STATUS_PAUSED, "Paused"),
        (PRINTER_STATUS_PENDING_DELETION, "Being deleted"),
        (PRINTER_STATUS_PAGE_PUNT, "Cannot print the page"),
        (PRINTER_STATUS_MANUAL_FEED, "Manual feed"),
        (PRINTER_STATUS_DRIVER_UPDATE_NEEDED, "Driver update needed"),
        (PRINTER_STATUS_TONER_LOW, "Toner low"),
        (PRINTER_STATUS_WARMING_UP, "Warming up"),
        (PRINTER_STATUS_INITIALIZING, "Initializing"),
        (PRINTER_STATUS_POWER_SAVE, "Power save"),
        (PRINTER_STATUS_PRINTING, "Printing"),
        (PRINTER_STATUS_PROCESSING, "Processing"),
        (PRINTER_STATUS_BUSY, "Busy"),
        (PRINTER_STATUS_IO_ACTIVE, "Sending"),
        (PRINTER_STATUS_WAITING, "Waiting"),
    ];
    WORDS.iter().filter(|(b, _)| s & b != 0).map(|(_, w)| *w).collect()
}

/// Bits that mean Windows cannot print there now.
pub const FAULTS: u32 = PRINTER_STATUS_OFFLINE
    | PRINTER_STATUS_ERROR
    | PRINTER_STATUS_PAPER_JAM
    | PRINTER_STATUS_PAPER_OUT
    | PRINTER_STATUS_DOOR_OPEN
    | PRINTER_STATUS_NO_TONER
    | PRINTER_STATUS_PAPER_PROBLEM
    | PRINTER_STATUS_OUTPUT_BIN_FULL
    | PRINTER_STATUS_USER_INTERVENTION
    | PRINTER_STATUS_OUT_OF_MEMORY
    | PRINTER_STATUS_NOT_AVAILABLE
    | PRINTER_STATUS_SERVER_OFFLINE
    | PRINTER_STATUS_SERVER_UNKNOWN;

/// The groups the window shows, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Group {
    Network,
    Usb,
    Shared,
    Virtual,
    Cloud,
    /// A port no rule knows (a vendor's own monitor): shown last, never guessed into another.
    Other,
}

impl Group {
    pub fn title(self) -> &'static str {
        match self {
            Group::Network => "Network",
            Group::Usb => "USB and cable",
            Group::Shared => "Shared (from another PC)",
            Group::Virtual => "Virtual",
            Group::Cloud => "Cloud",
            Group::Other => "Other",
        }
    }

    pub fn of(kind: Kind, connection: bool) -> Group {
        if connection {
            return Group::Shared;
        }
        match kind {
            Kind::Wsd | Kind::Tcp | Kind::Ipp => Group::Network,
            Kind::Usb | Kind::Cable => Group::Usb,
            Kind::Shared => Group::Shared,
            Kind::Virtual => Group::Virtual,
            Kind::Cloud => Group::Cloud,
            Kind::Other => Group::Other,
        }
    }
}

/// How a printer's own record was read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Read {
    Ok,
    /// A connection whose server did not answer in time (its fields are what level 4 had).
    ServerSilent,
    /// Read, but refused or failed: why.
    Failed(String),
}

/// One printer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Printer {
    /// The name exactly as Windows has it (what every call is given).
    pub name: Vec<u16>,
    /// The port(s): pooled printers list several, comma-separated.
    pub port: String,
    pub driver: String,
    /// A connection's server ("\\\\PC-KONTOR").
    pub server: String,
    pub share: String,
    pub location: String,
    pub comment: String,
    pub status: u32,
    pub attributes: u32,
    pub jobs: u32,
    pub default: bool,
    /// A connection to a printer shared by another PC.
    pub connection: bool,
    pub read: Read,
}

impl Default for Printer {
    fn default() -> Self {
        Printer {
            name: Vec::new(),
            port: String::new(),
            driver: String::new(),
            server: String::new(),
            share: String::new(),
            location: String::new(),
            comment: String::new(),
            status: 0,
            attributes: 0,
            jobs: 0,
            default: false,
            connection: false,
            read: Read::Ok,
        }
    }
}

impl Printer {
    /// The name as shown (cleaned; a lone surrogate shown as U+FFFD).
    pub fn display(&self) -> String {
        crate::text::clean_wide(&self.name, 220)
    }

    pub fn name_string(&self) -> String {
        String::from_utf16_lossy(&self.name)
    }

    /// The first port of a pooled printer (the one checked).
    pub fn first_port(&self) -> &str {
        self.port.split(',').map(str::trim).find(|p| !p.is_empty()).unwrap_or("")
    }

    pub fn pooled(&self) -> bool {
        self.port.split(',').filter(|p| !p.trim().is_empty()).count() > 1
    }

    pub fn work_offline(&self) -> bool {
        self.attributes & ATTR_WORK_OFFLINE != 0
    }

    pub fn paused(&self) -> bool {
        self.status & PRINTER_STATUS_PAUSED != 0
    }

    /// Windows says it cannot print there now.
    pub fn windows_offline(&self) -> bool {
        self.status & (PRINTER_STATUS_OFFLINE | PRINTER_STATUS_NOT_AVAILABLE | PRINTER_STATUS_SERVER_OFFLINE) != 0
    }

    /// Windows' own state in words: "Offline, Toner low", or "Ready" when no bit is set.
    pub fn windows_words(&self) -> String {
        let w = status_words(self.status);
        if w.is_empty() { "Ready".into() } else { w.join(", ") }
    }
}

/// The Print Spooler service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Spooler {
    Running,
    /// Stopped (or never started) with a start type that would start it.
    Stopped,
    /// Its start type is Disabled.
    Disabled,
    /// Starting, stopping, pausing: on its way somewhere.
    Changing(&'static str),
    /// Its state could not be read: why.
    Unknown(String),
    /// A read of the printers did not come back within this many seconds: a stuck job, port
    /// monitor or driver hangs it (X15CON-3).
    Silent(u64),
}

impl Spooler {
    pub fn running(&self) -> bool {
        matches!(self, Spooler::Running)
    }

    /// The status line's last words ("spooler running").
    pub fn short(&self) -> String {
        match self {
            Spooler::Running => "spooler running".into(),
            Spooler::Stopped => "spooler stopped".into(),
            Spooler::Disabled => "spooler disabled".into(),
            Spooler::Changing(w) => format!("spooler {w}"),
            Spooler::Unknown(_) => "spooler unknown".into(),
            Spooler::Silent(_) => "spooler not answering".into(),
        }
    }

    /// From the service's current state and start type (SERVICE_* values).
    pub fn from_service(state: u32, start_type: u32) -> Spooler {
        const SERVICE_DISABLED: u32 = 4;
        match state {
            4 => Spooler::Running,
            1 if start_type == SERVICE_DISABLED => Spooler::Disabled,
            1 => Spooler::Stopped,
            2 => Spooler::Changing("starting"),
            3 => Spooler::Changing("stopping"),
            5..=7 => Spooler::Changing("pausing"),
            s => Spooler::Unknown(format!("state {s}")),
        }
    }
}

/// The list as read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum List {
    Printers(Vec<Printer>),
    /// The spooler did not answer the list (it is stopped): nothing is known of the printers.
    NoSpooler,
    /// Refused or failed otherwise: why.
    Failed(String),
}

/// Order for the window: by group, then the default first, then by name (a total order: the
/// lower-cased name, then the exact units).
pub fn sort_key(p: &Printer, kind: Kind) -> (Group, bool, String, Vec<u16>) {
    (Group::of(kind, p.connection), !p.default, p.display().to_lowercase(), p.name.clone())
}

#[cfg(windows)]
pub mod sys {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Graphics::Printing::*;

    /// A NUL-terminated wide string from the spooler.
    unsafe fn wstr(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        // SAFETY: the caller hands a NUL-terminated string inside a buffer it owns.
        unsafe {
            let len = (0..).take_while(|&i| *p.add(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
        }
    }

    unsafe fn wunits(p: *const u16) -> Vec<u16> {
        if p.is_null() {
            return Vec::new();
        }
        // SAFETY: as above.
        unsafe {
            let len = (0..).take_while(|&i| *p.add(i) != 0).count();
            std::slice::from_raw_parts(p, len).to_vec()
        }
    }

    /// The default printer's name (exact units), if one is set.
    pub fn default_printer() -> Option<Vec<u16>> {
        let mut n = 0u32;
        // SAFETY: a size query, then a buffer of that size.
        unsafe { GetDefaultPrinterW(std::ptr::null_mut(), &mut n) };
        if n == 0 || n > 4096 {
            return None;
        }
        let mut b = vec![0u16; n as usize];
        (unsafe { GetDefaultPrinterW(b.as_mut_ptr(), &mut n) } != 0).then(|| {
            let len = b.iter().position(|&c| c == 0).unwrap_or(b.len());
            b[..len].to_vec()
        })
    }

    /// `EnumPrintersW` at `level` for `flags` into an 8-aligned buffer: (buffer, count), or the
    /// error code.
    fn enum_printers(flags: u32, level: u32) -> Result<(Vec<u64>, u32), u32> {
        let mut need = 0u32;
        let mut count = 0u32;
        // SAFETY: a size query.
        unsafe { EnumPrintersW(flags, std::ptr::null(), level, std::ptr::null_mut(), 0, &mut need, &mut count) };
        for _ in 0..4 {
            let mut buf = vec![0u64; (need as usize).div_ceil(8).max(1)];
            let size = (buf.len() * 8) as u32;
            // SAFETY: a buffer of `size` bytes, 8-aligned.
            if unsafe { EnumPrintersW(flags, std::ptr::null(), level, buf.as_mut_ptr().cast(), size, &mut need, &mut count) } != 0 {
                return Ok((buf, count));
            }
            let e = unsafe { GetLastError() };
            if e != ERROR_INSUFFICIENT_BUFFER {
                return Err(e);
            }
        }
        Err(ERROR_INSUFFICIENT_BUFFER)
    }

    /// An open printer handle, closed on drop.
    pub struct Handle(pub PRINTER_HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: opened by `open`, closed once.
            unsafe { ClosePrinter(self.0) };
        }
    }
    // SAFETY: a spooler handle may be used from any one thread at a time.
    unsafe impl Send for Handle {}

    /// Open a printer for reading (PRINTER_ACCESS_USE), or with `access`.
    pub fn open(name: &[u16], access: u32) -> Result<Handle, u32> {
        let mut z = name.to_vec();
        z.push(0);
        let defaults = PRINTER_DEFAULTSW { pDatatype: std::ptr::null_mut(), pDevMode: std::ptr::null_mut(), DesiredAccess: access };
        let mut h = PRINTER_HANDLE { Value: std::ptr::null_mut() };
        // SAFETY: a NUL-terminated name, defaults that live through the call.
        if unsafe { OpenPrinterW(z.as_ptr(), &mut h, &defaults) } == 0 {
            return Err(unsafe { GetLastError() });
        }
        Ok(Handle(h))
    }

    /// The local print server itself (OpenPrinterW with no name).
    pub fn open_server() -> Result<Handle, u32> {
        let mut h = PRINTER_HANDLE { Value: std::ptr::null_mut() };
        // SAFETY: no name, no defaults: the local server.
        if unsafe { OpenPrinterW(std::ptr::null(), &mut h, std::ptr::null()) } == 0 {
            return Err(unsafe { GetLastError() });
        }
        Ok(Handle(h))
    }

    /// `GetPrinterW` at `level` into an 8-aligned buffer.
    pub fn get_printer(h: &Handle, level: u32) -> Result<Vec<u64>, u32> {
        let mut need = 0u32;
        // SAFETY: a size query.
        unsafe { GetPrinterW(h.0, level, std::ptr::null_mut(), 0, &mut need) };
        if need == 0 {
            return Err(unsafe { GetLastError() });
        }
        let mut buf = vec![0u64; (need as usize).div_ceil(8)];
        // SAFETY: a buffer of at least `need` bytes.
        if unsafe { GetPrinterW(h.0, level, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut need) } == 0 {
            return Err(unsafe { GetLastError() });
        }
        Ok(buf)
    }

    /// One printer's level 2 record.
    pub fn read_info2(name: &[u16]) -> Result<Printer, u32> {
        let h = open(name, PRINTER_ACCESS_USE)?;
        let buf = get_printer(&h, 2)?;
        // SAFETY: the buffer holds a PRINTER_INFO_2W written by GetPrinterW.
        let i = unsafe { &*(buf.as_ptr() as *const PRINTER_INFO_2W) };
        // SAFETY: the strings point into `buf`.
        unsafe {
            Ok(Printer {
                name: name.to_vec(),
                port: wstr(i.pPortName),
                driver: wstr(i.pDriverName),
                server: wstr(i.pServerName),
                share: wstr(i.pShareName),
                location: wstr(i.pLocation),
                comment: wstr(i.pComment),
                status: i.Status,
                attributes: i.Attributes,
                jobs: i.cJobs,
                default: false,
                connection: false,
                read: Read::Ok,
            })
        }
    }

    /// Every printer: level 4 for the list (no server asked), then level 2 per printer. Local
    /// printers are read here; each connection on a thread of its own, given 5 s.
    pub fn list() -> List {
        list_reading(true)
    }

    /// `list`, with the connections' level 2 reads (each asks its connection's server) only when
    /// `connections` is set; without, a connection keeps what level 4 had. The default test reads
    /// none, so it asks no server (review RX3).
    pub fn list_reading(connections: bool) -> List {
        let (buf, count) = match enum_printers(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS, 4) {
            Ok(x) => x,
            // RPC_S_SERVER_UNAVAILABLE: the spooler is not running.
            Err(1722) => return List::NoSpooler,
            Err(e) => return List::Failed(format!("Windows did not list the printers ({})", std::io::Error::from_raw_os_error(e as i32))),
        };
        // SAFETY: `count` PRINTER_INFO_4W records at the start of `buf`.
        let rows = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const PRINTER_INFO_4W, count as usize) };
        let default = default_printer();
        let mut out = Vec::new();
        let mut pending = Vec::new();
        for r in rows.iter().take(1000) {
            // SAFETY: strings inside `buf`.
            let name = unsafe { wunits(r.pPrinterName) };
            let server = unsafe { wstr(r.pServerName) };
            let connection = r.Attributes & ATTR_NETWORK != 0 && r.Attributes & ATTR_LOCAL == 0;
            let is_default = default.as_deref() == Some(&name[..]);
            let base = Printer { name: name.clone(), server, attributes: r.Attributes, default: is_default, connection, ..Printer::default() };
            if connection && !connections {
                out.push(base);
            } else if connection {
                let (tx, rx) = mpsc::channel();
                let n = name.clone();
                let _ = std::thread::Builder::new().name("connection".into()).stack_size(256 * 1024).spawn(move || {
                    let _ = tx.send(read_info2(&n));
                });
                pending.push((base, rx));
            } else {
                out.push(match read_info2(&name) {
                    Ok(p) => Printer { default: is_default, ..p },
                    Err(e) => Printer { read: Read::Failed(format!("its details could not be read ({})", std::io::Error::from_raw_os_error(e as i32))), ..base },
                });
            }
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        for (base, rx) in pending {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            out.push(match rx.recv_timeout(left) {
                Ok(Ok(p)) => Printer { default: base.default, connection: true, server: if p.server.is_empty() { base.server.clone() } else { p.server.clone() }, ..p },
                Ok(Err(e)) => Printer { read: Read::Failed(format!("the server refused ({})", std::io::Error::from_raw_os_error(e as i32))), ..base },
                Err(_) => Printer { read: Read::ServerSilent, ..base },
            });
        }
        List::Printers(out)
    }

    /// The Print Spooler's state and start type.
    pub fn spooler() -> Spooler {
        use windows_sys::Win32::System::Services::*;
        let name = crate::host::wide("Spooler");
        // SAFETY: plain service manager calls on handles closed below.
        unsafe {
            let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
            if scm.is_null() {
                return Spooler::Unknown(format!("the service manager refused ({})", std::io::Error::last_os_error()));
            }
            let svc = OpenServiceW(scm, name.as_ptr(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
            if svc.is_null() {
                let e = std::io::Error::last_os_error();
                CloseServiceHandle(scm);
                return Spooler::Unknown(format!("the Print Spooler service could not be opened ({e})"));
            }
            let mut st: SERVICE_STATUS = std::mem::zeroed();
            let ok = QueryServiceStatus(svc, &mut st) != 0;
            let mut need = 0u32;
            QueryServiceConfigW(svc, std::ptr::null_mut(), 0, &mut need);
            let mut cfg = vec![0u64; (need as usize).div_ceil(8).max(8)];
            let start = if QueryServiceConfigW(svc, cfg.as_mut_ptr().cast(), (cfg.len() * 8) as u32, &mut need) != 0 { (*(cfg.as_ptr() as *const QUERY_SERVICE_CONFIGW)).dwStartType } else { u32::MAX };
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            if !ok {
                return Spooler::Unknown("its state could not be read".into());
            }
            Spooler::from_service(st.dwCurrentState, start)
        }
    }
}
