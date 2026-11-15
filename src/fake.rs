//! The scripted office the tests run on: a spooler (`FakeSpool`, what the helper's jobs see),
//! a network (`FakeNet`, what the probes and Find see) and a whole PC (`FakeSystem`, what the
//! controller sees). Compiled into the library so the window tests can use it; nothing here
//! touches the real system.

use crate::drivers::Driver;
use crate::helper::{Job, JobResult, Local, Outcome, Params, PortConfig, Spool};
use crate::mdns::Announced;
use crate::net::{Adapter, Mac};
use crate::ports::{Port, TcpConfig, WsdDevice};
use crate::printers::{ATTR_LOCAL, ATTR_NETWORK, ATTR_WORK_OFFLINE, List, Printer, Read, Spooler};
use crate::probe::{Net, Ping, PortState};
use crate::queue::Job as QJob;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A shadow file of the measured layout naming `printer` (see `shd.rs`).
pub fn shadow(job: u32, printer: &str) -> Vec<u8> {
    let mut b = vec![0u8; 0xE0];
    b[0..4].copy_from_slice(&crate::shd::SIGNATURE.to_le_bytes());
    b[4..8].copy_from_slice(&0xE0u32.to_le_bytes());
    b[0x0C..0x10].copy_from_slice(&job.to_le_bytes());
    let put = |field: usize, s: &str, b: &mut Vec<u8>| {
        let at = b.len();
        b[field..field + 8].copy_from_slice(&(at as u64).to_le_bytes());
        for u in s.encode_utf16() {
            b.extend_from_slice(&u.to_le_bytes());
        }
        b.extend_from_slice(&[0, 0]);
    };
    put(0x20, "Ola", &mut b);
    put(0x28, "Faktura 1043.pdf", &mut b);
    put(0x38, printer, &mut b);
    b[0x80..0x84].copy_from_slice(&120_000u32.to_le_bytes());
    b
}

// ---------- the spooler ----------

#[derive(Clone, Debug)]
struct SpoolState {
    printers: Vec<Local>,
    ports: Vec<(String, String)>,
    tcp: HashMap<String, TcpConfig>,
    drivers: Vec<String>,
    /// printer -> (jobs, the purge removes them)
    jobs: HashMap<String, (u32, bool)>,
    spooler: Spooler,
    files: BTreeMap<String, Vec<u8>>,
    calls: Vec<String>,
    waited: Duration,
    fail_next: Option<u32>,
    /// Services that depend on the spooler: (name, running, starts when asked).
    dependents: Vec<(String, bool, bool)>,
    /// The spooler refuses to stop (code) or to start (code).
    stop_fails: Option<u32>,
    start_fails: Option<u32>,
    /// The spooler takes the stop but does not reach stopped within the stop's wait: it gets
    /// there after this much more (None: never). `stopping`: it is on its way down now.
    stop_late: Option<Option<Duration>>,
    stopping: bool,
    /// It reached stopped after a late wait (its jobs are gone, as after a stop).
    went_down: bool,
    /// The spool folder cannot be listed (code).
    spool_list_fails: Option<u32>,
    /// job_count answers this error (always, or once the spooler was started again).
    count_fails: Option<u32>,
    count_fails_after_start: Option<u32>,
}

/// A spooler the helper's jobs run on.
pub struct FakeSpool {
    s: Mutex<SpoolState>,
}

impl FakeSpool {
    /// Kontor on `IP_192.168.1.50` (whose registry says 192.168.1.77: names lie), offline by
    /// "Use printer offline"; the Canon on WSD; a connection to another PC's printer.
    pub fn office() -> FakeSpool {
        let tcp = TcpConfig { host_name: "192.168.1.77".into(), protocol: 1, port_number: 9100, snmp: true, community: "public".into(), snmp_index: 1, ..TcpConfig::default() };
        FakeSpool {
            s: Mutex::new(SpoolState {
                printers: vec![
                    Local { name: w("Kontor"), port: "IP_192.168.1.50".into(), attributes: ATTR_LOCAL | ATTR_WORK_OFFLINE, shared: false },
                    Local { name: w("Canon GX6000 series"), port: "WSD-621e8831".into(), attributes: ATTR_LOCAL, shared: false },
                    Local { name: w("Kontor (fra PC-EIER)"), port: "\\\\PC-EIER\\Kontor".into(), attributes: ATTR_NETWORK, shared: true },
                ],
                ports: vec![("IP_192.168.1.50".into(), crate::ports::MONITOR_TCP.into()), ("WSD-621e8831".into(), crate::ports::MONITOR_WSD.into()), ("USB001".into(), crate::ports::MONITOR_USB.into())],
                tcp: HashMap::from([("IP_192.168.1.50".to_string(), tcp)]),
                drivers: vec!["Brother HL-L2350DW series".into(), "Canon GX6000 series".into(), "HP LaserJet Pro M404-M405 PCL-6 (V4)".into(), "Microsoft IPP Class Driver".into()],
                jobs: HashMap::new(),
                spooler: Spooler::Running,
                files: BTreeMap::new(),
                calls: Vec::new(),
                waited: Duration::ZERO,
                fail_next: None,
                dependents: Vec::new(),
                stop_fails: None,
                start_fails: None,
                stop_late: None,
                stopping: false,
                went_down: false,
                spool_list_fails: None,
                count_fails: None,
                count_fails_after_start: None,
            }),
        }
    }

    pub fn port_of(&self, printer: &str) -> String {
        lock(&self.s).printers.iter().find(|p| p.name == w(printer)).map(|p| p.port.clone()).unwrap_or_default()
    }

    pub fn set_port_of(&self, printer: &str, port: &str) {
        if let Some(p) = lock(&self.s).printers.iter_mut().find(|p| p.name == w(printer)) {
            p.port = port.into();
        }
    }

    pub fn attributes_of(&self, printer: &str) -> u32 {
        lock(&self.s).printers.iter().find(|p| p.name == w(printer)).map(|p| p.attributes).unwrap_or(0)
    }

    pub fn tcp(&self, port: &str) -> Option<TcpConfig> {
        lock(&self.s).tcp.get(port).cloned()
    }

    /// The next change fails with `code`.
    pub fn fail_next(&self, code: u32) {
        lock(&self.s).fail_next = Some(code);
    }

    pub fn set_jobs(&self, printer: &str, n: u32, purge_works: bool) {
        lock(&self.s).jobs.insert(printer.into(), (n, purge_works));
    }

    /// Spool files: 00002 and 00004 for `ours`, 00003 for `other`, 00009 of an older layout.
    pub fn put_spool_files(&self, ours: &str, other: &str) {
        let mut s = lock(&self.s);
        for (n, p) in [(2, ours), (3, other), (4, ours)] {
            s.files.insert(format!("{n:05}.SHD"), shadow(n, p));
            s.files.insert(format!("{n:05}.SPL"), vec![0x25; 64]);
        }
        let mut old = shadow(9, ours);
        old[0..4].copy_from_slice(&0x4968u32.to_le_bytes());
        s.files.insert("00009.SHD".into(), old);
        s.files.insert("00009.SPL".into(), vec![0x25; 64]);
    }

    pub fn spool_left(&self) -> Vec<String> {
        lock(&self.s).files.keys().cloned().collect()
    }

    pub fn calls(&self) -> Vec<String> {
        lock(&self.s).calls.clone()
    }

    pub fn waited(&self) -> Duration {
        lock(&self.s).waited
    }

    /// A service that depends on the spooler (Fax, LPD), running or not; `starts`: it starts
    /// again when asked.
    pub fn add_dependent(&self, name: &str, running: bool, starts: bool) {
        lock(&self.s).dependents.push((name.into(), running, starts));
    }

    /// The dependents now running.
    pub fn running_dependents(&self) -> Vec<String> {
        lock(&self.s).dependents.iter().filter(|d| d.1).map(|d| d.0.clone()).collect()
    }

    /// The spooler refuses to stop / to start with `code`.
    pub fn stop_fails(&self, code: u32) {
        lock(&self.s).stop_fails = Some(code);
    }

    pub fn start_fails(&self, code: u32) {
        lock(&self.s).start_fails = Some(code);
    }

    /// The spooler takes the stop and reaches stopped only `after` the stop's wait (a hung
    /// driver or port monitor); None: it never gets there while the job runs.
    pub fn stop_late(&self, after: Option<Duration>) {
        lock(&self.s).stop_late = Some(after);
    }

    /// The spooler is on its way down already when it is asked to stop (a stop asked for before:
    /// the state the StopLate words leave it in) and reaches stopped only `after` the stop's
    /// wait; None: never while the job runs. Like the real one, it refuses a stop control
    /// meanwhile (1061).
    pub fn stopping_already(&self, after: Option<Duration>) {
        let mut s = lock(&self.s);
        s.stop_late = Some(after);
        s.stopping = true;
    }

    /// The spool folder cannot be listed (`code`).
    pub fn spool_list_fails(&self, code: u32) {
        lock(&self.s).spool_list_fails = Some(code);
    }

    /// The queue's count cannot be read.
    pub fn count_fails(&self, code: u32) {
        lock(&self.s).count_fails = Some(code);
    }

    /// The queue's count cannot be read once the spooler was started again.
    pub fn count_fails_after_start(&self, code: u32) {
        lock(&self.s).count_fails_after_start = Some(code);
    }

    /// A TCP/IP port's settings, as set by hand.
    pub fn set_tcp(&self, port: &str, c: TcpConfig) {
        lock(&self.s).tcp.insert(port.into(), c);
    }

    /// `n` jobs of `printer` in the spool folder (a pair each), numbered from 100.
    pub fn put_many_spool_files(&self, printer: &str, n: u32) {
        let mut s = lock(&self.s);
        for i in 0..n {
            s.files.insert(format!("{:05}.SHD", 100 + i), shadow(100 + i, printer));
            s.files.insert(format!("{:05}.SPL", 100 + i), vec![0x25; 16]);
        }
    }

    pub fn disable_spooler(&self) {
        lock(&self.s).spooler = Spooler::Disabled;
    }

    fn change(&self, what: impl FnOnce(&mut SpoolState) -> Result<(), u32>) -> Result<(), u32> {
        let mut s = lock(&self.s);
        if let Some(c) = s.fail_next.take() {
            return Err(c);
        }
        what(&mut s)
    }
}

fn tcp_of(c: &PortConfig) -> TcpConfig {
    TcpConfig { host_name: c.host.clone(), ip_address: String::new(), protocol: c.protocol, port_number: c.port_number, queue: c.queue.clone(), snmp: c.snmp, community: c.community.clone(), snmp_index: c.snmp_index }
}

impl Spool for FakeSpool {
    fn printers(&self) -> Result<Vec<Local>, u32> {
        let s = lock(&self.s);
        if !s.spooler.running() { Err(1722) } else { Ok(s.printers.clone()) }
    }
    fn ports(&self) -> Result<Vec<(String, String)>, u32> {
        Ok(lock(&self.s).ports.clone())
    }
    fn tcp_config(&self, port: &str) -> Option<TcpConfig> {
        lock(&self.s).tcp.iter().find(|(k, _)| k.eq_ignore_ascii_case(port)).map(|(_, v)| v.clone())
    }
    fn drivers(&self) -> Vec<String> {
        lock(&self.s).drivers.clone()
    }
    fn add_port(&self, c: &PortConfig) -> Result<(), u32> {
        self.change(|s| {
            s.ports.push((c.name.clone(), crate::ports::MONITOR_TCP.into()));
            s.tcp.insert(c.name.clone(), tcp_of(c));
            s.calls.push(format!("add port {}", c.name));
            Ok(())
        })
    }
    fn config_port(&self, c: &PortConfig) -> Result<(), u32> {
        self.change(|s| {
            s.tcp.insert(c.name.clone(), tcp_of(c));
            Ok(())
        })
    }
    fn set_port(&self, printer: &[u16], port: &str) -> Result<(), u32> {
        self.change(|s| {
            let p = s.printers.iter_mut().find(|p| p.name == printer).ok_or(1801u32)?;
            p.port = port.into();
            Ok(())
        })
    }
    fn clear_attributes(&self, printer: &[u16], bits: u32) -> Result<(), u32> {
        self.change(|s| {
            let p = s.printers.iter_mut().find(|p| p.name == printer).ok_or(1801u32)?;
            p.attributes &= !bits;
            Ok(())
        })
    }
    fn add_printer(&self, name: &[u16], port: &str, _driver: &str) -> Result<(), u32> {
        self.change(|s| {
            s.printers.push(Local { name: name.to_vec(), port: port.into(), attributes: ATTR_LOCAL, shared: false });
            Ok(())
        })
    }
    fn delete_printer(&self, name: &[u16]) -> Result<(), u32> {
        self.change(|s| {
            s.printers.retain(|p| p.name != name);
            Ok(())
        })
    }
    fn purge(&self, printer: &[u16]) -> Result<(), u32> {
        self.change(|s| {
            let n = String::from_utf16_lossy(printer);
            s.calls.push(format!("purge {n}"));
            if let Some(j) = s.jobs.get_mut(&n)
                && j.1
            {
                j.0 = 0;
            }
            Ok(())
        })
    }
    fn job_count(&self, printer: &[u16]) -> Result<u32, u32> {
        let s = lock(&self.s);
        if let Some(c) = s.count_fails {
            return Err(c);
        }
        if let Some(c) = s.count_fails_after_start
            && s.calls.iter().any(|c| c == "start")
        {
            return Err(c);
        }
        let n = String::from_utf16_lossy(printer);
        // Once its files are gone (after a stop), its jobs are too.
        let files = s.files.values().any(|b| crate::shd::parse(b).is_ok_and(|x| x.printer == printer));
        Ok(match s.jobs.get(&n) {
            Some(j) if j.1 || files || !(s.went_down || s.calls.iter().any(|c| c == "stop")) => j.0,
            _ => 0,
        })
    }
    fn spooler(&self) -> Spooler {
        lock(&self.s).spooler.clone()
    }
    fn stop_spooler(&self, _: Duration, stopped: &mut Vec<String>) -> Result<(), u32> {
        use windows_sys::Win32::System::Services::{SERVICE_RUNNING, SERVICE_STOP_PENDING, SERVICE_STOPPED};
        self.change(|s| {
            // The same steps as the real stop (`xcv::stop_steps`), over this spooler.
            let s = std::cell::RefCell::new(s);
            crate::xcv::stop_steps(
                &|| {
                    let s = s.borrow();
                    Ok(if s.stopping {
                        SERVICE_STOP_PENDING
                    } else if s.spooler.running() {
                        SERVICE_RUNNING
                    } else {
                        SERVICE_STOPPED
                    })
                },
                &mut || {
                    let mut s = s.borrow_mut();
                    let s = &mut **s;
                    // The running dependents first (as the real one), each recorded before it stops.
                    for d in s.dependents.iter_mut().filter(|d| d.1) {
                        stopped.push(d.0.clone());
                        s.calls.push(format!("stop {}", d.0));
                        d.1 = false;
                    }
                    if let Some(c) = s.stop_fails {
                        return Err(c);
                    }
                    if s.stopping {
                        return Err(1061);
                    }
                    s.calls.push("stop".into());
                    if s.stop_late.is_some() {
                        // Taken, not done within the wait: on its way down.
                        s.stopping = true;
                    } else {
                        s.spooler = Spooler::Stopped;
                    }
                    Ok(())
                },
                // On its way down: not stopped within the stop's wait (the real one's timeout).
                &mut || if s.borrow().stopping { Err(1053) } else { Ok(()) },
            )
        })
    }
    fn wait_spooler_stopped(&self, wait: Duration) -> Result<(), u32> {
        let mut s = lock(&self.s);
        if !s.stopping {
            return if s.spooler.running() { Err(1053) } else { Ok(()) };
        }
        match s.stop_late {
            Some(Some(after)) if after <= wait => {
                s.waited += after;
                s.stopping = false;
                s.spooler = Spooler::Stopped;
                s.went_down = true;
                Ok(())
            }
            _ => {
                s.waited += wait;
                Err(1053)
            }
        }
    }
    fn start_spooler(&self, _: Duration) -> Result<(), u32> {
        self.change(|s| {
            if let Some(c) = s.start_fails {
                return Err(c);
            }
            s.calls.push("start".into());
            s.spooler = Spooler::Running;
            Ok(())
        })
    }
    fn start_service(&self, name: &str, _: Duration) -> Result<(), u32> {
        let mut s = lock(&self.s);
        s.calls.push(format!("start {name}"));
        match s.dependents.iter_mut().find(|d| d.0 == name) {
            Some(d) if d.2 => {
                d.1 = true;
                Ok(())
            }
            _ => Err(1058),
        }
    }
    fn set_auto_start(&self) -> Result<(), u32> {
        self.change(|s| {
            s.spooler = Spooler::Stopped;
            Ok(())
        })
    }
    fn spool_files(&self) -> Result<crate::helper::SpoolFiles, u32> {
        if let Some(c) = lock(&self.s).spool_list_fails {
            return Err(c);
        }
        // Parsed as listed, as the real one: the printer each shadow file names.
        Ok(lock(&self.s).files.iter().map(|(n, b)| (n.clone(), if crate::shd::shadow_stem(n).is_some() { crate::shd::printer_of(b) } else { Ok(Vec::new()) })).collect())
    }
    fn delete_spool_file(&self, name: &str) -> Result<(), u32> {
        lock(&self.s).files.remove(name).map(|_| ()).ok_or(2)
    }
    fn pause(&self, d: Duration) {
        lock(&self.s).waited += d;
    }
}

// ---------- the network ----------

/// One scripted device.
#[derive(Clone, Debug, Default)]
pub struct Device {
    pub ip: Option<IpAddr>,
    pub ping: bool,
    pub ports: Vec<u16>,
    pub ipp: Option<crate::ipp::Outcome>,
    pub snmp: Option<crate::snmp::Answer>,
    pub mac: Option<Mac>,
}

/// A network the probes and Find run on.
pub struct FakeNet {
    pub devices: Mutex<Vec<Device>>,
    pub announced: Mutex<Vec<Announced>>,
    pub adapters: Vec<Adapter>,
    /// What the sweep was asked.
    pub swept: Mutex<Vec<(Ipv4Addr, u16)>>,
    pub hosts: HashMap<String, Vec<IpAddr>>,
    /// Pings sent so far (each probe sends one per printer here).
    pub pings: std::sync::atomic::AtomicUsize,
    /// A device's SNMP community other than `public` (it answers only that), and every
    /// community asked, in order.
    pub communities: Mutex<HashMap<IpAddr, String>>,
    pub asked_communities: Mutex<Vec<String>>,
    /// The SNMP question cannot be sent (no socket) to these.
    pub snmp_fails: Mutex<Vec<IpAddr>>,
}

pub fn ipp_ready(model: &str) -> crate::ipp::Outcome {
    crate::ipp::Outcome::Answered(crate::ipp::Attrs { state: Some(3), make_model: Some(model.into()), markers: vec![("Black Toner".into(), 62)], ..crate::ipp::Attrs::default() })
}

impl FakeNet {
    /// The office: Kontor's Brother moved from .50 to .77 (it announces itself there), the
    /// Canon answers everything at .142, an HP answers 9100 and SNMP at .30, an IPv6-only
    /// printer answers at 2001:db8::50.
    pub fn office() -> FakeNet {
        let ip = |s: &str| Some(s.parse().unwrap());
        let mut txt = BTreeMap::new();
        txt.insert("ty".to_string(), "Brother HL-L2350DW series".to_string());
        txt.insert("rp".to_string(), "ipp/print".to_string());
        txt.insert("adminurl".to_string(), "http://192.168.1.77/".to_string());
        FakeNet {
            devices: Mutex::new(vec![
                Device { ip: ip("192.168.1.77"), ping: true, ports: vec![631, 9100], ipp: Some(ipp_ready("Brother HL-L2350DW series")), snmp: None, mac: Some([0x1c, 0x7d, 0x22, 0xa1, 0xb2, 0xc3]) },
                Device {
                    ip: ip("192.168.1.142"),
                    ping: true,
                    ports: vec![9100, 631, 515],
                    ipp: Some(crate::ipp::Outcome::Answered(crate::ipp::Attrs {
                        state: Some(3),
                        reasons: vec!["marker-supply-low-warning".into()],
                        make_model: Some("Canon GX6000 series".into()),
                        // The WSD record's uuid, as a Canon's has it (AUDIT-1 R-PRINT-2; a made-up one, with a
                        // documentation MAC as its node).
                        uuid: Some("urn:uuid:00000000-0000-1000-8000-00005e0053c9".into()),
                        markers: vec![("Black".into(), 40), ("Cyan".into(), 12), ("Magenta".into(), 70), ("Yellow".into(), 66)],
                        ..crate::ipp::Attrs::default()
                    })),
                    snmp: Some(crate::snmp::Answer { descr: Some("Canon GX6000 series".into()), status: Some(3), index: Some(1), serial: Some("KMX12345".into()), ..crate::snmp::Answer::default() }),
                    mac: Some([0xf4, 0x81, 0x39, 0x00, 0x53, 0xc9]),
                },
                Device { ip: ip("192.168.1.30"), ping: false, ports: vec![9100], ipp: None, snmp: Some(crate::snmp::Answer { descr: Some("HP ETHERNET MULTI-ENVIRONMENT".into()), status: Some(3), ..crate::snmp::Answer::default() }), mac: Some([0x00, 0x00, 0x00, 0x12, 0x34, 0x56]) },
                Device { ip: ip("2001:db8::50"), ping: true, ports: vec![631], ipp: Some(ipp_ready("EPSON ET-2850 Series")), snmp: None, mac: None },
            ]),
            announced: Mutex::new(vec![Announced { instance: "Brother HL-L2350DW series".into(), services: vec!["_ipp._tcp".into()], host: Some("BRW1C7D22A1B2C3.local".into()), port: Some(631), v4: vec!["192.168.1.77".parse().unwrap()], txt, from: ip("192.168.1.77"), ..Announced::default() }]),
            adapters: vec![Adapter { index: 1, name: "Wi-Fi".into(), addr: "192.168.1.91".parse().unwrap(), prefix: 24, metric: 10 }],
            swept: Mutex::new(Vec::new()),
            hosts: HashMap::from([("printer.kontor.local".to_string(), vec!["192.168.1.142".parse().unwrap()])]),
            pings: std::sync::atomic::AtomicUsize::new(0),
            communities: Mutex::new(HashMap::new()),
            asked_communities: Mutex::new(Vec::new()),
            snmp_fails: Mutex::new(Vec::new()),
        }
    }

    fn device(&self, ip: IpAddr) -> Option<Device> {
        lock(&self.devices).iter().find(|d| d.ip == Some(ip)).cloned()
    }

    /// The device at `ip` goes quiet (off, asleep, moved).
    pub fn silence(&self, ip: &str) {
        let ip: IpAddr = ip.parse().unwrap();
        lock(&self.devices).retain(|d| d.ip != Some(ip));
    }

    pub fn add(&self, d: Device) {
        lock(&self.devices).push(d);
    }
}

impl Net for FakeNet {
    fn ping(&self, ip: IpAddr) -> Ping {
        self.pings.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let up = self.device(ip).is_some_and(|d| d.ping);
        Ping { sent: 3, replies: if up { vec![1800, 2100, 1950] } else { vec![] }, error: None }
    }
    fn connect(&self, addr: SocketAddr, _: Duration) -> PortState {
        match self.device(addr.ip()) {
            Some(d) if d.ports.contains(&addr.port()) => PortState::Open,
            Some(_) => PortState::Closed,
            None => PortState::Silent,
        }
    }
    fn ipp(&self, addr: SocketAddr, _: &str) -> crate::ipp::Outcome {
        self.device(addr.ip()).and_then(|d| d.ipp).unwrap_or(crate::ipp::Outcome::NoAnswer("no answer at the IPP port in 5 s".into()))
    }
    fn snmp(&self, addr: SocketAddr, community: &str) -> crate::snmp::Outcome {
        lock(&self.asked_communities).push(community.to_string());
        if lock(&self.snmp_fails).contains(&addr.ip()) {
            return crate::snmp::Outcome::Failed("no SNMP socket (An operation on a socket could not be performed)".into());
        }
        let own = lock(&self.communities).get(&addr.ip()).cloned().unwrap_or_else(|| crate::snmp::COMMUNITY.to_string());
        match self.device(addr.ip()).and_then(|d| d.snmp) {
            // A v1 agent asked with another community stays silent.
            Some(a) if own == community => crate::snmp::Outcome::Answered(a),
            _ => crate::snmp::Outcome::Silent,
        }
    }
    fn arp(&self, ip: Ipv4Addr) -> Option<Mac> {
        self.device(IpAddr::V4(ip)).and_then(|d| d.mac)
    }
    fn browse(&self, _: Ipv4Addr, _: &dyn Fn() -> bool) -> Vec<Announced> {
        lock(&self.announced).clone()
    }
    fn sweep(&self, pairs: &[(Ipv4Addr, u16)], _: &dyn Fn() -> bool) -> Vec<(Ipv4Addr, u16)> {
        lock(&self.swept).extend_from_slice(pairs);
        pairs.iter().filter(|(ip, p)| self.device(IpAddr::V4(*ip)).is_some_and(|d| d.ports.contains(p))).copied().collect()
    }
    fn adapters(&self) -> Vec<Adapter> {
        self.adapters.clone()
    }
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        self.hosts.get(&host.to_ascii_lowercase()).cloned().ok_or_else(|| format!("{host} did not resolve (No such host is known.)"))
    }
}

// ---------- the PC ----------

/// One printer of the scripted PC, with its port and driver.
#[derive(Clone, Debug)]
pub struct Installed {
    pub printer: Printer,
    pub port: Port,
    pub driver: Result<Driver, String>,
    pub jobs: Result<Vec<QJob>, String>,
}

/// What the fake PC answers when a fix runs through the helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobAnswer {
    /// Run the job over the PC's own scripted spooler.
    Run,
    /// Answer this instead (Declined, Gone, ...).
    Give(Outcome),
    /// The helper stopped the spooler and was killed before it started it again.
    KilledWithTheSpoolerStopped,
}

#[derive(Default)]
struct PcState {
    spooler: Option<Spooler>,
    printers: Vec<Installed>,
    /// The first read fails this way (then reads work again).
    jobs_asked: Vec<(Job, Params)>,
    job_answers: Vec<JobAnswer>,
    deleted_jobs: Vec<(Vec<u16>, u32)>,
    test_pages: Vec<(Vec<u16>, Vec<String>)>,
    online_refused: bool,
    reads: u32,
    /// Ports no printer uses now (a WSD port a switch left behind): they still exist.
    spare_ports: Vec<Port>,
    /// The printers cannot be listed.
    list_fails: bool,
}

/// The whole PC as the controller sees it.
pub struct FakeSystem {
    s: Mutex<PcState>,
    pub net: std::sync::Arc<FakeNet>,
    pub drivers: Vec<String>,
}

pub fn driver(name: &str, maker: &str) -> Driver {
    Driver { name: name.into(), version: Some("10.0.26100.1".into()), date: Some(1_150_848_000), provider: maker.into(), maker: maker.into() }
}

pub fn tcp_port(name: &str, host: &str, snmp: bool) -> Port {
    Port { name: name.into(), monitor: crate::ports::MONITOR_TCP.into(), description: "Standard TCP/IP Port".into(), tcp: Some(TcpConfig { host_name: host.into(), protocol: 1, port_number: 9100, snmp, community: if snmp { "public".into() } else { String::new() }, snmp_index: u32::from(snmp), ..TcpConfig::default() }), wsd: None }
}

impl FakeSystem {
    /// The office: Kontor (a Brother on a TCP/IP port to .50, which moved to .77), the Canon on
    /// WSD (offline in Windows, answering at .142), a USB Brother with a stuck job, Microsoft
    /// Print to PDF, a shared printer from another PC, and a Universal Print printer.
    pub fn office() -> FakeSystem {
        let p = |name: &str, port: &str, driver: &str, status: u32, attributes: u32| Printer {
            name: w(name),
            port: port.into(),
            driver: driver.into(),
            status,
            attributes: attributes | ATTR_LOCAL,
            ..Printer::default()
        };
        let canon_wsd = Port {
            name: "WSD-621e8831-987e-45e5-9ef6-fcc22c4ab5d5".into(),
            monitor: crate::ports::MONITOR_WSD.into(),
            description: "WSD Port".into(),
            tcp: None,
            wsd: Some(WsdDevice { ips: vec!["192.168.1.142".parse().unwrap()], mac: Some([0xf4, 0x81, 0x39, 0x00, 0x53, 0xc9]), uuid: "00000000-0000-1000-8000-00005e0053c9".into(), ipp_url: Some("http://192.168.1.142:631/ipp/print".into()), present: true }),
        };
        let stuck = QJob { id: 7, document: "Faktura 1043.pdf".into(), owner: "Ola".into(), pages_printed: 2, total_pages: 3, size: 2_147_483_648, status: crate::queue::JOB_STATUS_ERROR | crate::queue::JOB_STATUS_PRINTING, submitted: crate::fake::NOW - 14 * 60, position: 1, mine: false, ..QJob::default() };
        let mine = QJob { id: 8, document: "Handleliste.docx".into(), owner: "Ted".into(), pages_printed: 0, total_pages: 1, size: 48_000, status: 0, submitted: crate::fake::NOW - 60, position: 2, mine: true, ..QJob::default() };
        let printers = vec![
            Installed { printer: Printer { default: true, ..p("Kontor", "IP_192.168.1.50", "Brother HL-L2350DW series", crate::printers::PRINTER_STATUS_OFFLINE, 0) }, port: tcp_port("IP_192.168.1.50", "192.168.1.50", true), driver: Ok(driver("Brother HL-L2350DW series", "Brother")), jobs: Ok(vec![]) },
            Installed { printer: p("Canon GX6000 series", &canon_wsd.name, "Canon GX6000 series", crate::printers::PRINTER_STATUS_OFFLINE, 0), port: canon_wsd, driver: Ok(driver("Canon GX6000 series", "Canon")), jobs: Ok(vec![]) },
            Installed {
                printer: p("Brother USB", "USB001", "Brother HL-L2350DW series", crate::printers::PRINTER_STATUS_PRINTING, 0),
                port: Port { name: "USB001".into(), monitor: crate::ports::MONITOR_USB.into(), description: "Virtual printer port for USB".into(), tcp: None, wsd: None },
                driver: Ok(driver("Brother HL-L2350DW series", "Brother")),
                jobs: Ok(vec![stuck, mine]),
            },
            Installed {
                printer: p("Microsoft Print to PDF", "PORTPROMPT:", "Microsoft Print To PDF", 0, 0),
                port: Port { name: "PORTPROMPT:".into(), monitor: crate::ports::MONITOR_LOCAL.into(), description: "Local Port".into(), tcp: None, wsd: None },
                driver: Ok(driver("Microsoft Print To PDF", "Microsoft")),
                jobs: Ok(vec![]),
            },
            Installed {
                printer: Printer { server: "\\\\PC-EIER".into(), connection: true, attributes: ATTR_NETWORK, read: Read::ServerSilent, ..p("\\\\PC-EIER\\Kontor", "", "", 0, 0) },
                port: Port::default(),
                driver: Err("not read".into()),
                jobs: Err("the server did not answer".into()),
            },
            Installed {
                printer: p("Kontor (Universal Print)", "UP:3f2a", "Universal Print Class Driver", 0, 0),
                port: Port { name: "UP:3f2a".into(), monitor: "Virtual Port Monitor".into(), description: "Virtual Port".into(), tcp: None, wsd: None },
                driver: Ok(Driver { name: "Universal Print Class Driver".into(), provider: "Microsoft".into(), ..Driver::default() }),
                jobs: Ok(vec![]),
            },
        ];
        FakeSystem {
            s: Mutex::new(PcState { spooler: Some(Spooler::Running), printers, ..PcState::default() }),
            net: std::sync::Arc::new(FakeNet::office()),
            drivers: vec!["Brother HL-L2350DW series".into(), "Canon GX6000 series".into(), "HP LaserJet Pro M404-M405 PCL-6 (V4)".into(), "Microsoft IPP Class Driver".into()],
        }
    }

    /// An office of `n` network printers (the 40-printer case), each answering.
    pub fn many(n: usize) -> FakeSystem {
        let f = FakeSystem::office();
        {
            let mut s = lock(&f.s);
            for i in 0..n {
                let host = format!("10.0.{}.{}", i / 200, 10 + i % 200);
                let name = format!("Etasje {} skriver {i:02} æøå", i / 10 + 1);
                s.printers.push(Installed {
                    printer: Printer { name: w(&name), port: format!("IP_{host}"), driver: "HP LaserJet Pro M404-M405 PCL-6 (V4)".into(), attributes: ATTR_LOCAL, ..Printer::default() },
                    port: tcp_port(&format!("IP_{host}"), &host, false),
                    driver: Ok(driver("HP LaserJet Pro M404-M405 PCL-6 (V4)", "HP")),
                    jobs: Ok(vec![]),
                });
                f.net.add(Device { ip: Some(host.parse().unwrap()), ping: true, ports: vec![9100], ipp: None, snmp: None, mac: None });
            }
        }
        f
    }

    /// No printers at all.
    pub fn empty() -> FakeSystem {
        let f = FakeSystem::office();
        lock(&f.s).printers.clear();
        f
    }

    pub fn set_spooler(&self, s: Spooler) {
        lock(&self.s).spooler = Some(s);
    }

    pub fn push_printer(&self, i: Installed) {
        lock(&self.s).printers.push(i);
    }

    pub fn remove_printer(&self, name: &str) {
        lock(&self.s).printers.retain(|p| p.printer.name != w(name));
    }

    pub fn edit(&self, name: &str, f: impl FnOnce(&mut Installed)) {
        if let Some(p) = lock(&self.s).printers.iter_mut().find(|p| p.printer.name == w(name)) {
            f(p);
        }
    }

    pub fn answer_jobs(&self, a: JobAnswer) {
        lock(&self.s).job_answers.push(a);
    }

    pub fn jobs_asked(&self) -> Vec<(Job, Params)> {
        lock(&self.s).jobs_asked.clone()
    }

    pub fn deleted_jobs(&self) -> Vec<(Vec<u16>, u32)> {
        lock(&self.s).deleted_jobs.clone()
    }

    pub fn test_pages(&self) -> Vec<(Vec<u16>, Vec<String>)> {
        lock(&self.s).test_pages.clone()
    }

    /// The printers cannot be listed (with the spooler's state unknown: nothing tells it is up).
    pub fn fail_list(&self) {
        lock(&self.s).list_fails = true;
    }

    pub fn refuse_online(&self) {
        lock(&self.s).online_refused = true;
    }

    pub fn reads(&self) -> u32 {
        lock(&self.s).reads
    }

    /// The PC's printers as the helper's spooler (to run a job over).
    fn spool(&self) -> FakeSpool {
        let s = lock(&self.s);
        let f = FakeSpool::office();
        {
            let mut st = lock(&f.s);
            st.printers = s.printers.iter().filter(|i| !i.printer.connection).map(|i| Local { name: i.printer.name.clone(), port: i.printer.port.clone(), attributes: i.printer.attributes, shared: false }).collect();
            st.ports = s.printers.iter().map(|i| &i.port).chain(s.spare_ports.iter()).filter(|p| !p.name.is_empty()).map(|p| (p.name.clone(), p.monitor.clone())).collect();
            st.tcp = s.printers.iter().map(|i| &i.port).chain(s.spare_ports.iter()).filter_map(|p| p.tcp.clone().map(|t| (p.name.clone(), t))).collect();
            st.drivers = self.drivers.clone();
            st.spooler = s.spooler.clone().unwrap_or(Spooler::Running);
        }
        f
    }

    /// Take a job's effect on the scripted spooler back into the PC.
    fn take_back(&self, spool: &FakeSpool) {
        let sp = lock(&spool.s);
        let mut s = lock(&self.s);
        s.spooler = Some(sp.spooler.clone());
        // Printers removed or changed.
        s.printers.retain(|i| i.printer.connection || sp.printers.iter().any(|l| l.name == i.printer.name));
        for l in &sp.printers {
            let port = sp.ports.iter().find(|p| p.0 == l.port).cloned();
            let tcp = sp.tcp.get(&l.port).cloned();
            let st = &mut *s;
            match st.printers.iter_mut().find(|i| i.printer.name == l.name) {
                Some(i) => {
                    if i.printer.port != l.port {
                        // The old port stays (a WSD port a switch left behind); a spare one
                        // comes back with what it knew.
                        let old = std::mem::take(&mut i.port);
                        let back = st.spare_ports.iter().position(|p| p.name == l.port).map(|k| st.spare_ports.remove(k));
                        if !old.name.is_empty() {
                            st.spare_ports.push(old);
                        }
                        i.printer.port = l.port.clone();
                        i.port = back.unwrap_or(Port { name: l.port.clone(), monitor: port.map(|p| p.1).unwrap_or_default(), description: String::new(), tcp: tcp.clone(), wsd: None });
                        // Windows sees a TCP/IP port that answers as online.
                        if i.port.tcp.is_some() {
                            i.printer.status &= !crate::printers::PRINTER_STATUS_OFFLINE;
                        }
                    } else if let Some(t) = tcp {
                        i.port.tcp = Some(t);
                    }
                    i.printer.attributes = l.attributes | (i.printer.attributes & ATTR_LOCAL);
                }
                None => st.printers.push(Installed {
                    printer: Printer { name: l.name.clone(), port: l.port.clone(), driver: "HP LaserJet Pro M404-M405 PCL-6 (V4)".into(), attributes: ATTR_LOCAL, ..Printer::default() },
                    port: Port { name: l.port.clone(), monitor: crate::ports::MONITOR_TCP.into(), description: String::new(), tcp, wsd: None },
                    driver: Ok(driver("HP LaserJet Pro M404-M405 PCL-6 (V4)", "HP")),
                    jobs: Ok(vec![]),
                }),
            }
        }
        // New ports no printer uses (a printer deleted) stay too.
        for (name, monitor) in &sp.ports {
            let used = s.printers.iter().any(|i| &i.port.name == name) || s.spare_ports.iter().any(|p| &p.name == name);
            if !used {
                let tcp = sp.tcp.get(name).cloned();
                s.spare_ports.push(Port { name: name.clone(), monitor: monitor.clone(), description: String::new(), tcp, wsd: None });
            }
        }
    }
}

/// The rigs' clock: 2026-10-22 14:02:11 UTC.
pub const NOW: i64 = 1_792_677_731;

impl crate::controller::System for FakeSystem {
    fn read(&self) -> crate::controller::Snapshot {
        let mut s = lock(&self.s);
        s.reads += 1;
        let spooler = s.spooler.clone().unwrap_or(Spooler::Running);
        // A hung spooler: what `Real::read` hands back when its read does not come back in time.
        if matches!(spooler, Spooler::Silent(_)) {
            return crate::controller::Snapshot::silent(crate::controller::READ_LIMIT);
        }
        // An unknown state with the list answering (the SCM refused a query, the spooler is up).
        if !spooler.running() && !matches!(spooler, Spooler::Unknown(_)) {
            return crate::controller::Snapshot { spooler, list: List::NoSpooler, ..crate::controller::Snapshot::default() };
        }
        if s.list_fails {
            return crate::controller::Snapshot { spooler, list: List::Failed("Windows did not list the printers (The RPC server is unavailable.)".into()), ..crate::controller::Snapshot::default() };
        }
        crate::controller::Snapshot {
            spooler,
            list: List::Printers(s.printers.iter().map(|i| i.printer.clone()).collect()),
            ports: s.printers.iter().filter(|i| !i.port.name.is_empty()).map(|i| i.port.clone()).collect(),
            drivers: s.printers.iter().map(|i| (i.printer.name.clone(), i.driver.clone())).collect(),
            queues: s.printers.iter().map(|i| (i.printer.name.clone(), i.jobs.clone())).collect(),
            neighbours: Vec::new(),
        }
    }

    fn net(&self) -> std::sync::Arc<dyn Net> {
        self.net.clone()
    }

    fn delete_job(&self, printer: &[u16], id: u32) -> Result<(), u32> {
        let mut s = lock(&self.s);
        let i = s.printers.iter_mut().find(|i| i.printer.name == printer).ok_or(1801u32)?;
        if let Ok(j) = &mut i.jobs {
            let Some(pos) = j.iter().position(|x| x.id == id) else { return Err(87) };
            if !j[pos].mine {
                return Err(5);
            }
            j.remove(pos);
        }
        s.deleted_jobs.push((printer.to_vec(), id));
        Ok(())
    }

    fn set_online(&self, printer: &[u16]) -> Result<(), u32> {
        let mut s = lock(&self.s);
        if s.online_refused {
            return Err(5);
        }
        let i = s.printers.iter_mut().find(|i| i.printer.name == printer).ok_or(1801u32)?;
        i.printer.attributes &= !ATTR_WORK_OFFLINE;
        Ok(())
    }

    fn job(&self, job: Job, p: &Params, _hwnd: isize, _stop: &AtomicBool) -> Outcome {
        let answer = {
            let mut s = lock(&self.s);
            s.jobs_asked.push((job, p.clone()));
            if s.job_answers.is_empty() { JobAnswer::Run } else { s.job_answers.remove(0) }
        };
        match answer {
            JobAnswer::Give(o) => o,
            JobAnswer::KilledWithTheSpoolerStopped => {
                lock(&self.s).spooler = Some(Spooler::Stopped);
                Outcome::Gone
            }
            JobAnswer::Run => {
                let spool = self.spool();
                // Through the real wire: the request as the helper parses it, the answer as the
                // app decodes it.
                let nonce = [5u8; 16];
                let req = crate::helper::request(job, &nonce, p);
                let Some((n, parsed)) = crate::helper::parse_request(&req[5..], job) else { return Outcome::Failed("the request was not valid".into()) };
                let bytes = [crate::helper::hello(1), crate::helper::work(&spool, job, &n, &parsed)].concat();
                let mut c = crate::helper::Collect::new(1);
                let mut out = Outcome::Gone;
                if let Ok(msgs) = crate::helper::Decoder::new(nonce).push(&bytes) {
                    for m in msgs {
                        if !c.take(m) {
                            out = c.outcome.take().unwrap_or(Outcome::Gone);
                            break;
                        }
                    }
                }
                if matches!(out, Outcome::Done(_)) {
                    self.take_back(&spool);
                    // A purge empties the scripted queue.
                    if job == Job::QueueClear
                        && let Some(name) = &p.printer
                    {
                        let mut s = lock(&self.s);
                        if let Some(i) = s.printers.iter_mut().find(|i| &i.printer.name == name) {
                            i.jobs = Ok(vec![]);
                            i.printer.status &= !crate::printers::PRINTER_STATUS_ERROR;
                        }
                    }
                }
                out
            }
        }
    }

    fn test_page(&self, printer: &[u16], lines: &[String]) -> Result<(), String> {
        lock(&self.s).test_pages.push((printer.to_vec(), lines.to_vec()));
        Ok(())
    }

    fn drivers(&self) -> Vec<String> {
        self.drivers.clone()
    }

    fn computer_name(&self) -> String {
        "PC-TED".into()
    }
}

/// A result helper for the tests: a JobResult with a port.
pub fn port_result(port: &str) -> JobResult {
    JobResult { port: Some(port.into()), ..JobResult::default() }
}
