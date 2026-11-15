//! The window's brain. It lives on the UI thread: it keeps the prefs (in memory, saved on the
//! prefs thread), the toasts, the newest read of the spooler and what each printer said, and
//! makes every decision. The .slint files lay out what it hands them; every word is made here.
//!
//! Reads, probes, Find and every fix run on workers; each answer carries the epoch (seq) it was
//! asked under, and an answer for an older epoch does nothing. The spooler is watched, not polled
//! (`watch.rs`); network printers are asked again every 60 s while the window is not minimized.

use crate::check::{Dot, Fetched, Local, Release, Rows};
use crate::drivers::Driver;
use crate::find::{self, Found, Installed, Match};
use crate::helper::{Job, Outcome, Params, Protocol};
use crate::journal::{self, Entry, Journal};
use crate::net::Mac;
use crate::portable::Mode;
use crate::ports::{self, Address, Kind, Port};
use crate::prefs::{Change, Store};
use crate::printers::{Group, List, Printer, Read, Spooler};
use crate::probe::{Answers, Net, Probe};
use crate::queue::{Job as QJob, Stuck, Tracker};
use crate::status::{self, Facts, Fix, Line};
use crate::text::clean_max;
use crate::{AddInfo, AppWindow, CheckDot, CheckRow, ConfirmInfo, DetailInfo, DetailPair, FixButton, FoundRow, JobRow, JournalRow, Prefs, PrinterRow, Theme, ToastItem, ToastKind};
use slint::{ComponentHandle, Model, ModelRc, SharedString, Timer, TimerMode, VecModel, Weak};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, TryRecvError, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Network printers are asked again this often while the window is not minimized.
pub const PROBE_EVERY: Duration = Duration::from_secs(60);
/// While any queue has jobs, it is read again this often (a stuck job needs time to show).
pub const QUEUE_EVERY: Duration = Duration::from_secs(30);
/// Probes run at most this many printers at once.
pub const PROBE_PARALLEL: usize = 8;

/// One read of the spooler: its state, the printers, the ports they use (with their TCP/IP
/// settings and WSD devices), each printer's driver and queue, and the neighbour cache.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub spooler: Spooler,
    pub list: List,
    pub ports: Vec<Port>,
    pub drivers: HashMap<Vec<u16>, Result<Driver, String>>,
    pub queues: HashMap<Vec<u16>, Result<Vec<QJob>, String>>,
    pub neighbours: Vec<(IpAddr, Mac)>,
}

impl Default for Spooler {
    fn default() -> Self {
        Spooler::Unknown("not read yet".into())
    }
}

/// How long one read of the spooler may take before the window says it did not answer
/// (X15CON-3). A healthy read takes a second or two; the PCs sharing printers get 5 s for the
/// list and 3 s for all their queues together, so slow print servers stay well inside it.
pub const READ_LIMIT: Duration = Duration::from_secs(20);

impl Snapshot {
    /// What is known when a read did not come back within `limit`: nothing but that.
    pub fn silent(limit: Duration) -> Snapshot {
        let secs = limit.as_secs();
        Snapshot { spooler: Spooler::Silent(secs), list: List::Failed(format!("the Print Spooler did not answer in {secs} s")), ..Snapshot::default() }
    }
}

/// `read` on a thread of its own, waited for at most `limit`; past it, a silent snapshot, and the
/// thread ends on its own once the spooler answers. One read at a time (`busy`): one still stuck
/// from before is waited for within the same limit, never joined by a second (X15CON-3).
pub fn read_within(limit: Duration, busy: &'static AtomicBool, read: impl FnOnce() -> Snapshot + Send + 'static) -> Snapshot {
    let deadline = Instant::now() + limit;
    while busy.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        if Instant::now() >= deadline {
            return Snapshot::silent(limit);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let _ = tx.send(read());
        busy.store(false, Ordering::SeqCst);
    });
    rx.recv_timeout(deadline.saturating_duration_since(Instant::now())).unwrap_or_else(|_| Snapshot::silent(limit))
}

impl Default for List {
    fn default() -> Self {
        List::Printers(Vec::new())
    }
}

/// The PC as the app reads and changes it; the tests hand it a script (`fake::FakeSystem`).
pub trait System: Send + Sync {
    fn read(&self) -> Snapshot;
    fn net(&self) -> Arc<dyn Net>;
    /// Delete one job of the user's own (no admin).
    fn delete_job(&self, printer: &[u16], id: u32) -> Result<(), u32>;
    /// Clear "Use printer offline" without admin rights (refused: the helper does it).
    fn set_online(&self, printer: &[u16]) -> Result<(), u32>;
    /// One admin step through the elevated helper (blocks while the UAC prompt is up).
    fn job(&self, job: Job, p: &Params, hwnd: isize, stop: &AtomicBool) -> Outcome;
    fn test_page(&self, printer: &[u16], lines: &[String]) -> Result<(), String>;
    fn drivers(&self) -> Vec<String>;
    fn computer_name(&self) -> String;
}

/// This PC.
pub struct Real;

/// One read of this PC's spooler, unbounded (`Real::read` bounds it).
fn read_now() -> Snapshot {
    let spooler = crate::printers::sys::spooler();
    let list = crate::printers::sys::list();
    let mut snap = Snapshot { spooler, list, neighbours: crate::net::system_neighbours(), ..Snapshot::default() };
    let List::Printers(printers) = &snap.list else { return snap };
    let all_ports = crate::ports::sys::list().unwrap_or_default();
    let me = crate::queue::sys::user_name();
    let mut remote: Vec<Vec<u16>> = Vec::new();
    for p in printers {
        let first = p.first_port().to_string();
        if let Some(port) = all_ports.iter().find(|x| x.name.eq_ignore_ascii_case(&first))
            && !snap.ports.iter().any(|x| x.name.eq_ignore_ascii_case(&first))
        {
            let mut port = port.clone();
            let kind = ports::classify(&port.name, &port.monitor, &p.driver);
            if port.monitor.eq_ignore_ascii_case(ports::MONITOR_TCP) {
                port.tcp = crate::ports::sys::tcp_config(&port.name);
            }
            if matches!(kind, Kind::Wsd | Kind::Ipp) && port.monitor.eq_ignore_ascii_case(ports::MONITOR_WSD) {
                port.wsd = crate::ports::sys::wsd_device(&port.name);
            }
            snap.ports.push(port);
        }
        if p.connection {
            // A connection's driver and queue ask its server: never here when it is silent;
            // its queue below, with the others', within one shared 3 s.
            if p.read == Read::Ok {
                remote.push(p.name.clone());
            }
            continue;
        }
        snap.drivers.insert(p.name.clone(), crate::drivers::sys::of(&p.name).map_err(|e| format!("not read ({})", crate::helper::code_words(e))));
        snap.queues.insert(p.name.clone(), crate::queue::sys::jobs(&p.name, &me).map_err(|e| format!("the queue could not be read ({})", crate::helper::code_words(e))));
    }
    let me = Arc::new(me);
    for (name, q) in connection_queues(remote, CONNECTION_WAIT, move |n| crate::queue::sys::jobs(n, &me)) {
        snap.queues.insert(name, q);
    }
    snap
}

/// How long the PCs sharing printers get to hand over their queues, all of them together.
pub const CONNECTION_WAIT: Duration = Duration::from_secs(3);

/// Each shared printer's queue asked on a thread of its own, all within one shared `wait`
/// (X15RFAMBC-1): asked one after another, six slow print-server connections took 18 s, which
/// with the list's own wait ran past READ_LIMIT and read as a hung spooler. A queue not back in
/// time says its server did not answer.
pub fn connection_queues<T: Send + 'static>(names: Vec<Vec<u16>>, wait: Duration, ask: impl Fn(&[u16]) -> Result<T, u32> + Send + Sync + 'static) -> Vec<(Vec<u16>, Result<T, String>)> {
    let ask = Arc::new(ask);
    let deadline = Instant::now() + wait;
    let asked: Vec<_> = names
        .into_iter()
        .map(|n| {
            let (tx, rx) = channel();
            let (ask, n2) = (ask.clone(), n.clone());
            let _ = std::thread::Builder::new().stack_size(256 * 1024).spawn(move || {
                let _ = tx.send(ask(&n2));
            });
            (n, rx)
        })
        .collect();
    asked
        .into_iter()
        .map(|(n, rx)| {
            let q = match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(Ok(j)) => Ok(j),
                Ok(Err(e)) => Err(format!("the queue could not be read ({})", crate::helper::code_words(e))),
                Err(_) => Err(format!("the PC sharing it did not answer in {} s", wait.as_secs())),
            };
            (n, q)
        })
        .collect()
}

impl System for Real {
    /// Bounded: a hung spooler never leaves a read (the window's, or a fix's before and after)
    /// waiting forever (X15CON-3).
    fn read(&self) -> Snapshot {
        static READING: AtomicBool = AtomicBool::new(false);
        read_within(READ_LIMIT, &READING, read_now)
    }

    fn net(&self) -> Arc<dyn Net> {
        Arc::new(crate::probe::RealNet)
    }

    fn delete_job(&self, printer: &[u16], id: u32) -> Result<(), u32> {
        crate::queue::sys::delete_job(printer, id)
    }

    fn set_online(&self, printer: &[u16]) -> Result<(), u32> {
        use crate::helper::Spool;
        crate::xcv::RealSpool.clear_attributes(printer, crate::printers::ATTR_WORK_OFFLINE)
    }

    fn job(&self, job: Job, p: &Params, hwnd: isize, stop: &AtomicBool) -> Outcome {
        crate::helper::run(job, p, hwnd, stop)
    }

    fn test_page(&self, printer: &[u16], lines: &[String]) -> Result<(), String> {
        crate::testpage::print(printer, lines)
    }

    fn drivers(&self) -> Vec<String> {
        crate::drivers::sys::installed()
    }

    fn computer_name(&self) -> String {
        crate::host::computer_name()
    }
}

/// Something the app opens outside itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Opening {
    /// Windows' Printers & scanners (Add printer fetches drivers).
    Settings,
    /// A printer's web page (mDNS `adminurl`).
    Web(String),
    /// The VibeWare website (About's link).
    Site,
}

/// A blocking call the check's worker makes.
pub type Fetcher<A, R> = Arc<dyn Fn(&A) -> R + Send + Sync>;

/// What the controller needs from the outside world; the tests hand it fakes.
pub struct Services {
    pub copy: Box<dyn Fn(&str) -> bool>,
    pub reveal: Box<dyn Fn(&Path)>,
    /// A shell call (on its own thread in the real app).
    pub open: Box<dyn Fn(Opening)>,
    pub system: Arc<dyn System>,
    /// Unix seconds now.
    pub now: Box<dyn Fn() -> i64>,
    /// The local time's offset from UTC at a moment, in seconds.
    pub utc_offset: Arc<dyn Fn(i64) -> i64 + Send + Sync>,
    /// The window to put the UAC prompt over.
    pub hwnd: Box<dyn Fn() -> isize>,
    /// The window is minimized (the timed probes wait).
    pub minimized: Box<dyn Fn() -> bool>,
    /// Tests: work runs on the UI thread, at once or held (`hold`) until `release`.
    pub manual: bool,
    pub hold: Cell<bool>,
    /// Watch the spooler for changes (not in the tests).
    pub watch: bool,
    pub mode: Mode,
    /// Where journal.json lives (None: a read-only stick, in memory only).
    pub journal_dir: Option<PathBuf>,
    /// This PC's MachineGuid (the journal's key).
    pub machine: String,
    /// The install check's offline half, on its worker: this copy's files, their signatures and
    /// hashes (`trust::inspect_from`; true: installed, so the uninstaller too).
    pub inspect: Fetcher<bool, Local>,
    /// The install check's online half, on its worker: the release list at a path on the site,
    /// waited for at most `release.wait`. Only `main` hands in the real one (the exe's
    /// `site::fetch_release_list`, in no test build); the tests hand in fakes.
    pub fetch: Fetcher<str, Fetched>,
    /// What the check holds the list to: the app, its version, the list's key, the code signer.
    pub release: Release,
}

impl Services {
    /// The real services. `fetch` is the release-list fetcher: `main` hands in the exe's
    /// `site::fetch_release_list`, and is the only place that names it.
    pub fn system(mode: Mode, journal_dir: Option<PathBuf>, fetch: Fetcher<str, Fetched>) -> Services {
        // The exe's identity as this process started from it, taken now, before an install
        // could replace it, and handed to every check (FED3, RVD7).
        let started = crate::trust::exe_identity();
        Services {
            copy: Box::new(|t| crate::host::copy_text(t).is_ok()),
            reveal: Box::new(|p| {
                let _ = crate::host::reveal(p, true);
            }),
            open: Box::new(|o| {
                std::thread::spawn(move || {
                    let r = match &o {
                        Opening::Settings => crate::host::open_printer_settings(),
                        Opening::Web(u) => crate::host::open_web(u),
                        Opening::Site => crate::host::open_url(crate::check::SITE),
                    };
                    if let Err(e) = r {
                        let _ = slint::invoke_from_event_loop(move || {
                            APP.with(|a| {
                                if let Some(app) = a.borrow().upgrade() {
                                    app.toast(&clean_max(&e, 200), ToastKind::Error, None);
                                }
                            })
                        });
                    }
                });
            }),
            system: Arc::new(Real),
            now: Box::new(crate::host::now_unix),
            utc_offset: Arc::new(crate::host::utc_offset),
            hwnd: Box::new(crate::host::active_window),
            minimized: Box::new(crate::host::minimized),
            manual: false,
            hold: Cell::new(false),
            watch: true,
            mode,
            journal_dir,
            machine: crate::host::machine_guid(),
            inspect: Arc::new(move |installed: &bool| crate::trust::inspect_from(started, &crate::trust::own_exe(), *installed)),
            fetch,
            release: Release::this(),
        }
    }
}

/// How often the window looks whether a running check has its answer.
const CHECK_POLL_MS: u64 = 50;

/// The journal's list shows the newest this many entries.
const JOURNAL_SHOWN: usize = 300;

/// Up/Down/Home/End in a list of `n` rows with `cur` selected (None: none yet, so Down picks
/// the first): the row to select, or None for any other key or an empty list (X15A11Y-2).
fn list_step(t: &str, cur: Option<usize>, n: usize) -> Option<usize> {
    use slint::platform::Key;
    let k = |key: Key| SharedString::from(key) == t;
    if n == 0 {
        return None;
    }
    let last = n - 1;
    Some(if k(Key::UpArrow) {
        cur.map_or(0, |c| c.saturating_sub(1).min(last))
    } else if k(Key::DownArrow) {
        cur.map_or(0, |c| (c + 1).min(last))
    } else if k(Key::Home) {
        0
    } else if k(Key::End) {
        last
    } else {
        return None;
    })
}

/// `fetch` on a thread of its own, waited for at most `deadline` (FETCH_DEADLINE, review RAB-3):
/// past it the answer is `TimedOut`, whatever the site or a proxy is doing, and the thread is
/// left to end by itself (the real fetcher's read loop stops at the same deadline, and WinHTTP's
/// own timeouts bound each step); its late answer goes nowhere.
fn fetch_within(fetch: Fetcher<str, Fetched>, path: String, deadline: Duration) -> Fetched {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let _ = tx.send(fetch(&path));
    });
    match rx.recv_timeout(deadline) {
        Ok(f) => f,
        Err(RecvTimeoutError::Timeout) => Fetched::TimedOut,
        Err(RecvTimeoutError::Disconnected) => Fetched::Failed("the fetch stopped before it answered".into()),
    }
}

/// What Windows records of any program it runs, and what VibePrint writes to this PC anyway:
/// said where portable mode is (the chip's tip; it was About's portable paragraph).
const PORTABLE_TRACE: &str = "Nothing goes to this PC's profile or registry but the fixes you make, and Windows still records that a program ran (Prefetch, recent-programs lists).";

thread_local! {
    /// The window's controller, for workers' answers (they come back on this thread).
    static APP: RefCell<std::rc::Weak<App>> = const { RefCell::new(std::rc::Weak::new()) };
}

type PrefsChange = Change<Prefs>;
const PREFS_TELL_MS: u64 = 500;

/// The thread that saves prefs changes, in order (VibeTemplate's).
fn prefs_writer(store: Store<Prefs>, pending: Arc<AtomicUsize>) -> Sender<PrefsChange> {
    let (tx, rx) = channel::<PrefsChange>();
    std::thread::spawn(move || {
        while let Ok(f) = rx.recv() {
            store.change(Arc::new(move |p: &mut Prefs| {
                *p = std::mem::take(p).sanitized();
                f(p);
            }));
            pending.fetch_sub(1, Ordering::SeqCst);
        }
    });
    tx
}

fn s(t: impl AsRef<str>) -> SharedString {
    t.as_ref().into()
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn w(t: &str) -> Vec<u16> {
    t.encode_utf16().collect()
}

/// An address as typed or pasted: spaces and surrounding quotes go (one normaliser for typing,
/// pasting and Find's Add).
pub fn typed_ip(t: &str) -> String {
    t.trim().trim_matches(['"', '\'']).trim().to_string()
}

/// What one probe of one printer came back with.
#[derive(Clone, Debug)]
pub enum Probed {
    Answers(Box<Answers>, Option<Vec<IpAddr>>),
    /// The host name did not resolve.
    NoAddress(String),
}

/// A fix the user can start (the window's buttons and the confirm dialog).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FixKind {
    ClearQueue,
    RestartSpooler,
    UseOnline,
    SwitchToTcp { ip: Ipv4Addr, protocol: Protocol, snmp: bool },
    PointAt { ip: Ipv4Addr },
    SnmpOff,
    TestPage,
    AddByIp { ip: Ipv4Addr, name: Vec<u16>, driver: String, protocol: Protocol, snmp: bool },
    Undo { entry: u64 },
    /// Not a fix: the status line's "Search the LAN" (Find).
    Search,
}

/// A fix waiting for its confirm, with what it was planned against.
#[derive(Clone, Debug)]
struct Planned {
    kind: FixKind,
    printer: Option<Vec<u16>>,
    /// The port the plan read (a switch, an address change: still the same before it acts).
    port: String,
    /// The address the plan read (PointAt: still the old one before it acts).
    old_address: String,
    /// The identity of the device the fix points the printer at (recorded in the journal:
    /// AUDIT-1 PRINT-3).
    device: BTreeMap<String, String>,
}

/// A worker's answer, with the epoch it belongs to.
enum Msg {
    Read { seq: u64, snap: Box<Snapshot> },
    Probed { seq: u64, results: Vec<(Vec<u16>, Probed)> },
    Found { seq: u64, results: find::Results },
    AddChecked { seq: u64, ip: Ipv4Addr, answers: Box<Answers> },
    Drivers { list: Vec<String> },
    Fixed { seq: u64, kind: FixKind, printer: Option<Vec<u16>>, outcome: FixOutcome, journal: Option<Journal>, garbled: bool, snap: Box<Snapshot> },
    Journal { journal: Journal, broken: bool },
    Changed,
}

/// How a fix ended, in the app's terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FixOutcome {
    /// Done; what is now true, in words.
    Done(String),
    /// Not done: why (changed since, refused, failed, declined), in words.
    NotDone(String),
    /// The helper went away: what it did is not known.
    Unknown(String),
}

/// The Add by IP dialog.
#[derive(Default)]
struct AddState {
    seq: u64,
    ip_text: String,
    name: String,
    /// What the fields held when the dialog opened (Escape puts it back).
    ip_first: String,
    name_first: String,
    name_edited: bool,
    drivers: Vec<String>,
    driver: Option<usize>,
    checking: bool,
    answers: Option<(Ipv4Addr, Answers)>,
}

#[derive(Default)]
struct State {
    prefs: Prefs,
    toast_seq: i32,
    toast_paths: HashMap<i32, PathBuf>,
    toast_time: HashMap<i32, (u64, u64)>,
    // ---- the read ----
    read_seq: u64,
    reading: bool,
    snap: Option<Snapshot>,
    read_at: Option<i64>,
    // ---- the probes ----
    probe_seq: u64,
    probing: bool,
    /// The read in flight was asked for by Refresh: the printers are asked again after it.
    probe_next_read: bool,
    probes: HashMap<Vec<u16>, (Probe, Option<Vec<IpAddr>>)>,
    tracker: Tracker,
    stuck: HashMap<Vec<u16>, Stuck>,
    // ---- the window ----
    selected: Option<Vec<u16>>,
    scroll_seq: i32,
    find_open: bool,
    // ---- Find ----
    find_seq: u64,
    finding: bool,
    find_started: Option<Instant>,
    find: Option<find::Results>,
    found_selected: Option<usize>,
    // ---- fixes ----
    fix_seq: u64,
    fix_running: Option<FixKind>,
    planned: Option<Planned>,
    add: AddState,
    // ---- the journal ----
    journal: Vec<Entry>,
    journal_selected: Option<u64>,
    machine: String,
    // ---- About's install check ----
    /// Its number (an answer for another one does nothing), and while it runs, where its answer
    /// comes from.
    check_seq: u64,
    check_rx: Option<Receiver<(u64, Rows)>>,
}

/// One row of the list, as computed from the state.
struct Entry0 {
    printer: Printer,
    kind: Kind,
    group: Group,
    port: Option<Port>,
    address: Address,
    line: Line,
}

/// Work the tests hold back until `release`.
type Held = Box<dyn FnOnce(&dyn Fn(Msg))>;

pub struct App {
    ui: Weak<AppWindow>,
    svc: Services,
    store: Store<Prefs>,
    journal: Option<journal::Store>,
    st: RefCell<State>,
    prefs_tx: Sender<PrefsChange>,
    prefs_pending: Arc<AtomicUsize>,
    toasts: Rc<VecModel<ToastItem>>,
    me: RefCell<std::rc::Weak<App>>,
    inbox: Arc<Mutex<Vec<Msg>>>,
    held_jobs: RefCell<Vec<Held>>,
    /// Asks running work to end (the window closed, Find stopped).
    stop: Arc<AtomicBool>,
    find_stop: RefCell<Arc<AtomicBool>>,
    probe_timer: Timer,
    queue_timer: Timer,
    find_timer: Timer,
    watch: RefCell<Option<std::thread::JoinHandle<()>>>,
    check_rows: Rc<VecModel<CheckRow>>,
    check_timer: Timer,
}

impl App {
    /// Wire the controller to a window made by `crate::window`.
    pub fn attach(ui: &AppWindow, store: Store<Prefs>, svc: Services) -> Rc<App> {
        let prefs = store.load().sanitized();
        let prefs_pending = Arc::new(AtomicUsize::new(0));
        let prefs_tx = prefs_writer(store.clone(), prefs_pending.clone());
        let machine = if svc.machine.is_empty() { "this-pc".to_string() } else { svc.machine.clone() };
        let journal = Some(match &svc.journal_dir {
            Some(d) => journal::open(d.join("journal.json"), &machine),
            None => journal::Store::memory(),
        });
        let app = Rc::new(App {
            ui: ui.as_weak(),
            svc,
            store,
            journal,
            st: RefCell::new(State { prefs, machine, ..State::default() }),
            prefs_tx,
            prefs_pending,
            toasts: Rc::new(VecModel::default()),
            me: RefCell::new(std::rc::Weak::new()),
            inbox: Arc::new(Mutex::new(Vec::new())),
            held_jobs: RefCell::new(Vec::new()),
            stop: Arc::new(AtomicBool::new(false)),
            find_stop: RefCell::new(Arc::new(AtomicBool::new(false))),
            probe_timer: Timer::default(),
            queue_timer: Timer::default(),
            find_timer: Timer::default(),
            watch: RefCell::new(None),
            check_rows: Rc::new(VecModel::default()),
            check_timer: Timer::default(),
        });
        *app.me.borrow_mut() = Rc::downgrade(&app);
        APP.with(|a| *a.borrow_mut() = Rc::downgrade(&app));
        ui.set_toasts(ModelRc::from(app.toasts.clone()));
        ui.set_check_rows(ModelRc::from(app.check_rows.clone()));
        app.show_rows(&Rows::idle());
        let bits = if cfg!(target_pointer_width = "64") { "64-bit" } else { "32-bit" };
        let how = if app.svc.mode.portable() { "portable" } else { "installed for you" };
        ui.set_about_line(s(format!("version {} · {bits} · {how}", crate::VERSION)));
        app.wire(ui);
        if app.store.broken() {
            app.toast("prefs.json could not be read: the settings are back to their defaults, and the old file will be kept as prefs.json.broken.", ToastKind::Error, None);
        }
        if matches!(app.svc.mode, Mode::ReadOnly { .. }) {
            app.toast("Portable, read-only: settings and the journal will not be kept; Undo works until VibePrint closes.", ToastKind::Info, None);
        }
        app.render();
        // The keys (Up, Down, F5, Ctrl+C) work from the start.
        ui.invoke_focus_list();
        app.load_journal();
        app.refresh();
        app.start_timers();
        if app.svc.watch {
            let stop = app.stop.clone();
            *app.watch.borrow_mut() = Some(crate::watch::start(stop, || {
                let _ = slint::invoke_from_event_loop(|| {
                    APP.with(|a| {
                        if let Some(app) = a.borrow().upgrade() {
                            app.handle(Msg::Changed);
                        }
                    })
                });
            }));
        }
        app
    }

    fn wire(self: &Rc<Self>, ui: &AppWindow) {
        macro_rules! on {
            ($setter:ident, |$a:ident $(, $arg:ident)*| $body:expr) => {{
                let w = Rc::downgrade(self);
                ui.$setter(move |$($arg),*| {
                    let Some($a) = w.upgrade() else { return Default::default() };
                    $body
                });
            }};
        }
        on!(on_toggle_theme, |a| a.toggle_theme());
        on!(on_copy_text, |a, t| (a.svc.copy)(&t));
        on!(on_toast_dismissed, |a, id| a.drop_toast(id));
        on!(on_toast_action, |a, id| a.toast_action(id));
        on!(on_dialogs_closed, |a| a.dialogs_closed());
        on!(on_refresh, |a| a.refresh_all());
        on!(on_find, |a| a.find());
        on!(on_find_stop, |a| a.find_stop());
        on!(on_find_close, |a| a.find_close());
        on!(on_add_by_ip, |a| a.add_open(None));
        on!(on_restart_spooler, |a| a.plan_fix(FixKind::RestartSpooler, None));
        on!(on_journal, |a| a.journal_open());
        on!(on_copy_report, |a| a.copy_report());
        on!(on_row_clicked, |a, i| a.row_clicked(i));
        on!(on_key, |a, t, c, sh| a.key(&t, c, sh));
        on!(on_fix_clicked, |a, id| a.fix_clicked(id));
        on!(on_found_clicked, |a, i| a.found_clicked(i));
        on!(on_found_action, |a, id| a.found_action(id));
        on!(on_confirm_ok, |a| a.confirm_ok());
        on!(on_confirm_cancel, |a| a.confirm_cancel());
        on!(on_add_ip_edited, |a, t| a.add_ip_edited(&t));
        on!(on_add_name_edited, |a, t| a.add_name_edited(&t));
        on!(on_add_ip_escaped, |a| a.add_escaped(true));
        on!(on_add_name_escaped, |a| a.add_escaped(false));
        on!(on_add_driver_changed, |a, i| a.add_driver_changed(i));
        on!(on_add_settings, |a| (a.svc.open)(Opening::Settings));
        on!(on_add_confirm, |a| a.add_confirm());
        on!(on_add_cancel, |a| a.add_close());
        on!(on_journal_clicked, |a, i| a.journal_clicked(i));
        on!(on_found_key, |a, t| a.found_key(&t));
        on!(on_journal_key, |a, t| a.journal_key(&t));
        on!(on_journal_undo, |a| a.journal_undo());
        on!(on_journal_close, |a| a.journal_close());
        on!(on_check_install, |a| a.check_install());
        on!(on_open_site, |a| (a.svc.open)(Opening::Site));
    }

    fn ui(&self) -> Option<AppWindow> {
        self.ui.upgrade()
    }

    fn me(&self) -> std::rc::Weak<App> {
        self.me.borrow().clone()
    }

    fn dialog_open(&self) -> bool {
        self.ui().is_some_and(|ui| ui.get_about_open() || ui.get_confirm_open() || ui.get_add_open() || ui.get_journal_open())
    }

    fn now(&self) -> i64 {
        (self.svc.now)()
    }

    fn clock(&self, t: i64) -> String {
        crate::host::clock(t, (self.svc.utc_offset)(t))
    }

    fn date_time(&self, t: i64) -> String {
        crate::host::date_time(t, (self.svc.utc_offset)(t))
    }

    // ---------- prefs ----------

    pub fn prefs(&self) -> Prefs {
        self.st.borrow().prefs.clone()
    }

    pub fn save_prefs(&self, change: impl Fn(&mut Prefs) + Send + Sync + 'static) {
        let f: PrefsChange = Arc::new(change);
        f(&mut self.st.borrow_mut().prefs);
        self.prefs_pending.fetch_add(1, Ordering::SeqCst);
        if self.prefs_tx.send(f).is_err() {
            self.prefs_pending.fetch_sub(1, Ordering::SeqCst);
        }
        let w = self.me();
        Timer::single_shot(Duration::from_millis(PREFS_TELL_MS), move || {
            if let Some(a) = w.upgrade() {
                a.tell_garbled();
            }
        });
    }

    fn tell_garbled(&self) {
        if self.store.take_garbled() {
            self.toast("prefs.json was damaged: it is kept as prefs.json.broken, and this window's settings are saved in its place.", ToastKind::Error, None);
        }
    }

    /// At exit (and in tests): running work is told to end, the watch stops, the prefs thread
    /// hands its last change to the store (at most two seconds), then what is unwritten is
    /// written (the journal first) on a thread of its own, waited for at most two seconds too: a
    /// prefs file on a share that stopped answering never holds the window's thread for good
    /// (VibePing PING-8, review X15CON-4). A prefs thread still busy then is not waited for (the
    /// journal is still written): at exit the process ends it, and the changes it had not
    /// written are lost, unsaid. The watch is waited for two seconds at most as well (a hung
    /// spooler can hold its notification calls).
    pub fn finish_prefs(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.find_stop.borrow().store(true, Ordering::SeqCst);
        let start = Instant::now();
        let limit = Duration::from_secs(2);
        while self.prefs_pending.load(Ordering::SeqCst) > 0 && start.elapsed() < limit {
            std::thread::sleep(Duration::from_millis(2));
        }
        let store = (self.prefs_pending.load(Ordering::SeqCst) == 0).then(|| self.store.clone());
        let journal = self.journal.clone();
        let (tx, rx) = channel::<()>();
        std::thread::spawn(move || {
            if let Some(j) = journal {
                j.flush();
            }
            if let Some(store) = store {
                store.flush();
            }
            let _ = tx.send(());
        });
        let _ = rx.recv_timeout(limit);
        if let Some(h) = self.watch.borrow_mut().take() {
            let start = Instant::now();
            while !h.is_finished() && start.elapsed() < limit {
                std::thread::sleep(Duration::from_millis(5));
            }
            if h.is_finished() {
                let _ = h.join();
            }
        }
    }

    fn toggle_theme(&self) {
        let Some(ui) = self.ui() else { return };
        let theme = ui.global::<Theme>();
        let dark = !theme.get_dark();
        theme.set_dark(dark);
        self.save_prefs(move |p| p.theme = Some(if dark { "dark" } else { "light" }.into()));
    }

    // ---------- About's install check ----------

    /// "Check this install": one at a time, on a worker (it reads the files and may go online);
    /// the window looks for the answer every CHECK_POLL_MS meanwhile and goes on. Closing About
    /// leaves it running: the answer lands in the rows, which About shows when it opens again.
    fn check_install(&self) {
        let Some(ui) = self.ui() else { return };
        let seq = {
            let mut st = self.st.borrow_mut();
            if st.check_rx.is_some() {
                return;
            }
            st.check_seq += 1;
            st.check_seq
        };
        let (tx, rx) = channel();
        self.st.borrow_mut().check_rx = Some(rx);
        ui.set_checking(true);
        let (inspect, fetch, release) = (self.svc.inspect.clone(), self.svc.fetch.clone(), self.svc.release.clone());
        let installed = !self.svc.mode.portable();
        std::thread::spawn(move || {
            let local = inspect(&installed);
            // The exe updated or replaced under this one while it ran: nothing to compare (FED3).
            let rows = if local.replaced {
                crate::check::replaced_rows(&release, &local)
            } else {
                let fetched = fetch_within(fetch, crate::check::list_path(release.app), release.wait);
                crate::check::rows(&release, &local, fetched)
            };
            let _ = tx.send((seq, rows));
        });
        let w = self.me.borrow().clone();
        self.check_timer.start(TimerMode::Repeated, Duration::from_millis(CHECK_POLL_MS), move || {
            if let Some(a) = w.upgrade() {
                a.poll_check();
            }
        });
    }

    /// The check's answer, once it is there: the rows, and the button back.
    fn poll_check(&self) {
        let got = {
            let st = self.st.borrow();
            let Some(rx) = st.check_rx.as_ref() else { return };
            match rx.try_recv() {
                Ok((seq, rows)) => Some((seq == st.check_seq).then_some(rows)),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => Some(Some(Rows::stopped())),
            }
        };
        let Some(rows) = got else { return };
        self.check_timer.stop();
        self.st.borrow_mut().check_rx = None;
        if let Some(rows) = rows {
            self.show_rows(&rows);
        }
        if let Some(ui) = self.ui() {
            ui.set_checking(false);
            ui.set_checked(true);
        }
    }

    fn show_rows(&self, rows: &Rows) {
        let dot = |d: Dot| match d {
            Dot::Idle => CheckDot::Idle,
            Dot::Ok => CheckDot::Ok,
            Dot::Warn => CheckDot::Warn,
            Dot::Danger => CheckDot::Danger,
        };
        let all: Vec<CheckRow> = rows.all().iter().map(|(name, r)| CheckRow { name: s(name), text: s(&r.text), dot: dot(r.dot) }).collect();
        self.check_rows.set_vec(all);
    }

    // ---------- toasts ----------

    /// A toast, bottom right: errors stay 10 s, the rest 5 s.
    pub fn toast(&self, text: &str, kind: ToastKind, reveal: Option<PathBuf>) {
        let id = {
            let mut st = self.st.borrow_mut();
            st.toast_seq += 1;
            let id = st.toast_seq;
            if let Some(p) = reveal.clone() {
                st.toast_paths.insert(id, p);
            }
            id
        };
        while self.toasts.row_count() >= 3 {
            let old = self.toasts.row_data(0).map(|t| t.id).unwrap_or(0);
            self.drop_toast(old);
        }
        self.toasts.push(ToastItem { id, text: s(text), kind, action: if reveal.is_some() { s("Show") } else { s("") } });
        self.arm_toast(id, if kind == ToastKind::Error { 10_000 } else { 5_000 });
    }

    /// A toast's timer, `ms` from now. Only its newest timer counts, and while a dialog is open
    /// it waits (`dialogs_closed` gives it its full time again).
    fn arm_toast(&self, id: i32, ms: u64) {
        let generation = {
            let mut st = self.st.borrow_mut();
            let t = st.toast_time.entry(id).or_insert((0, ms));
            t.0 += 1;
            t.0
        };
        let w = self.me();
        Timer::single_shot(Duration::from_millis(ms), move || {
            let Some(a) = w.upgrade() else { return };
            let current = a.st.borrow().toast_time.get(&id).is_some_and(|t| t.0 == generation);
            if current && !a.dialog_open() {
                a.drop_toast(id);
            }
        });
    }

    fn dialogs_closed(&self) {
        let all: Vec<(i32, u64)> = self.st.borrow().toast_time.iter().map(|(id, t)| (*id, t.1)).collect();
        for (id, ms) in all {
            self.arm_toast(id, ms);
        }
    }

    fn drop_toast(&self, id: i32) {
        if let Some(i) = self.toasts.iter().position(|t| t.id == id) {
            self.toasts.remove(i);
        }
        let mut st = self.st.borrow_mut();
        st.toast_time.remove(&id);
        st.toast_paths.remove(&id);
    }

    fn toast_action(&self, id: i32) {
        let p = self.st.borrow().toast_paths.get(&id).cloned();
        if let Some(p) = p {
            (self.svc.reveal)(&p);
        }
        self.drop_toast(id);
    }

    pub fn toast_texts(&self) -> Vec<String> {
        self.toasts.iter().map(|t| t.text.to_string()).collect()
    }

    // ---------- workers ----------

    /// Run `work` off the UI thread; each message it sends comes back to `handle` (tests: at
    /// once, or held until `release`). A burst of messages is one wake-up of the window.
    fn bg(&self, work: impl FnOnce(&dyn Fn(Msg)) + Send + 'static) {
        if self.svc.manual {
            if self.svc.hold.get() {
                self.held_jobs.borrow_mut().push(Box::new(work));
            } else {
                let out = RefCell::new(Vec::new());
                work(&|m| out.borrow_mut().push(m));
                for m in out.into_inner() {
                    self.handle(m);
                }
            }
            return;
        }
        let inbox = self.inbox.clone();
        let _ = std::thread::Builder::new().name("worker".into()).stack_size(1024 * 1024).spawn(move || {
            work(&|m| {
                let first = {
                    let mut i = lock(&inbox);
                    i.push(m);
                    i.len() == 1
                };
                if first {
                    let _ = slint::invoke_from_event_loop(|| {
                        APP.with(|a| {
                            if let Some(app) = a.borrow().upgrade() {
                                app.drain();
                            }
                        })
                    });
                }
            });
        });
    }

    /// Tests: the work held back so far.
    pub fn held(&self) -> usize {
        self.held_jobs.borrow().len()
    }

    /// Tests: let the held work answer, in the order it was started.
    pub fn release(&self) {
        loop {
            let jobs = std::mem::take(&mut *self.held_jobs.borrow_mut());
            if jobs.is_empty() {
                return;
            }
            for j in jobs {
                let out = RefCell::new(Vec::new());
                j(&|m| out.borrow_mut().push(m));
                for m in out.into_inner() {
                    self.handle(m);
                }
            }
        }
    }

    /// Tests: let only the newest held work answer, then the older ones (threads finish in any
    /// order).
    /// Tests: let only held work number `i` (in the order it was started) answer now; the rest
    /// stay held. (A worker reads the PC when it runs: the test changes the PC in between.)
    pub fn release_at(&self, i: usize) {
        let job = {
            let mut held = self.held_jobs.borrow_mut();
            if i >= held.len() {
                return;
            }
            held.remove(i)
        };
        let out = RefCell::new(Vec::new());
        job(&|m| out.borrow_mut().push(m));
        for m in out.into_inner() {
            self.handle(m);
        }
    }

    pub fn release_newest_first(&self) {
        let jobs = std::mem::take(&mut *self.held_jobs.borrow_mut());
        for j in jobs.into_iter().rev() {
            let out = RefCell::new(Vec::new());
            j(&|m| out.borrow_mut().push(m));
            for m in out.into_inner() {
                self.handle(m);
            }
        }
    }

    fn drain(&self) {
        let msgs = std::mem::take(&mut *lock(&self.inbox));
        for m in msgs {
            self.handle(m);
        }
    }

    fn handle(&self, m: Msg) {
        match m {
            Msg::Read { seq, snap } => self.read_done(seq, *snap),
            Msg::Probed { seq, results } => self.probed(seq, results),
            Msg::Found { seq, results } => self.found(seq, results),
            Msg::AddChecked { seq, ip, answers } => self.add_checked(seq, ip, *answers),
            Msg::Drivers { list } => self.add_drivers(list),
            Msg::Fixed { seq, kind, printer, outcome, journal, garbled, snap } => {
                self.fixed(seq, kind, printer, outcome, journal, *snap);
                if garbled {
                    self.toast("journal.json was damaged: it is kept as journal.json.broken, and this PC's fixes are saved in its place.", ToastKind::Error, None);
                }
                if let Some(n) = self.journal.as_ref().map(|j| j.take_trimmed()).filter(|&n| n > 0) {
                    self.toast(&journal::trimmed_words(n), ToastKind::Info, None);
                }
            }
            Msg::Journal { journal, broken } => self.journal_loaded(journal, broken),
            Msg::Changed => self.refresh(),
        }
    }

    // ---------- reading ----------

    /// Refresh and F5: read everything again and ask every network printer again.
    pub fn refresh_all(&self) {
        self.st.borrow_mut().probe_next_read = true;
        self.refresh();
    }

    /// Read everything again (the spooler changed, a queue to watch, after a fix). Printers are
    /// asked again only when their address changed (or Refresh asked for it).
    pub fn refresh(&self) {
        let seq = {
            let mut st = self.st.borrow_mut();
            st.read_seq += 1;
            st.reading = true;
            st.read_seq
        };
        self.render();
        let sys = self.svc.system.clone();
        self.bg(move |send| send(Msg::Read { seq, snap: Box::new(sys.read()) }));
    }

    fn read_done(&self, seq: u64, snap: Snapshot) {
        let probe_needed = {
            let mut st = self.st.borrow_mut();
            if seq != st.read_seq {
                return; // an older read's answer
            }
            st.reading = false;
            st.read_at = Some((self.svc.now)());
            let now = st.read_at.unwrap();
            // Stuck jobs: each printer's queue against what it was.
            let mut stuck = HashMap::new();
            if let List::Printers(v) = &snap.list {
                for p in v {
                    if let Some(Ok(jobs)) = snap.queues.get(&p.name)
                        && let Some(s) = st.tracker.observe(&p.name, jobs, p.paused(), now)
                    {
                        stuck.insert(p.name.clone(), s);
                    }
                }
                let names: Vec<Vec<u16>> = v.iter().map(|p| p.name.clone()).collect();
                let gone: Vec<Vec<u16>> = st.probes.keys().filter(|k| !names.contains(k)).cloned().collect();
                for g in gone {
                    st.probes.remove(&g);
                    st.tracker.forget(&g);
                }
            }
            st.stuck = stuck;
            // A printer whose address changed (or that is new) needs asking.
            let need = Self::addresses(&snap).into_iter().any(|(name, addr, _, _)| match (st.probes.get(&name), addr) {
                (None, Address::Ip(_) | Address::Host(_)) => true,
                (Some((Probe::Done(a), _)), Address::Ip(ip)) => a.at != ip,
                _ => false,
            });
            st.snap = Some(snap);
            if st.selected.as_ref().is_some_and(|sel| !Self::printers_of(&st).iter().any(|p| &p.name == sel)) {
                st.selected = None;
            }
            need || st.probe_seq == 0 || std::mem::take(&mut st.probe_next_read)
        };
        if probe_needed {
            self.probe_all();
        }
        self.render();
    }

    fn printers_of(st: &State) -> Vec<Printer> {
        match st.snap.as_ref().map(|s| &s.list) {
            Some(List::Printers(v)) => v.clone(),
            _ => Vec::new(),
        }
    }

    fn port_of<'a>(snap: &'a Snapshot, p: &Printer) -> Option<&'a Port> {
        let first = p.first_port();
        snap.ports.iter().find(|x| x.name.eq_ignore_ascii_case(first))
    }

    fn kind_of(snap: &Snapshot, p: &Printer) -> Kind {
        if p.connection {
            return Kind::Shared;
        }
        let monitor = Self::port_of(snap, p).map(|x| x.monitor.clone()).unwrap_or_default();
        ports::classify(p.first_port(), &monitor, &p.driver)
    }

    /// Every printer's address: (name, address, IPP path, SNMP community).
    fn addresses(snap: &Snapshot) -> Vec<(Vec<u16>, Address, String, String)> {
        let List::Printers(v) = &snap.list else { return Vec::new() };
        v.iter()
            .map(|p| {
                let kind = Self::kind_of(snap, p);
                let port = Self::port_of(snap, p).cloned().unwrap_or(Port { name: p.first_port().to_string(), ..Port::default() });
                (p.name.clone(), ports::address(kind, &port), ports::ipp_path(kind, &port), Self::community(Some(&port)))
            })
            .collect()
    }

    /// The SNMP community a printer is asked with: its TCP/IP port's own (what Windows' SNMP
    /// check uses: AUDIT-1 PRINT-4), else `public`.
    fn community(port: Option<&Port>) -> String {
        port.and_then(|p| p.tcp.as_ref()).map(|t| t.community.as_str()).filter(|c| !c.is_empty() && c.len() <= 255).unwrap_or(crate::snmp::COMMUNITY).to_string()
    }

    // ---------- the probes ----------

    /// Ask every network printer with an address (newest run wins).
    pub fn probe_all(&self) {
        let (seq, work) = {
            let mut st = self.st.borrow_mut();
            let Some(snap) = &st.snap else { return };
            let todo: Vec<(Vec<u16>, Address, String, String)> = Self::addresses(snap).into_iter().filter(|(_, a, _, _)| matches!(a, Address::Ip(_) | Address::Host(_))).collect();
            st.probe_seq += 1;
            st.probing = !todo.is_empty();
            for (name, _, _, _) in &todo {
                // What was known stays shown as "Checking…" until the new answer: never latched.
                let resolved = st.probes.get(name).and_then(|p| p.1.clone());
                st.probes.insert(name.clone(), (Probe::Checking, resolved));
            }
            (st.probe_seq, todo)
        };
        self.render();
        if work.is_empty() {
            return;
        }
        let net = self.svc.system.net();
        let stop = self.stop.clone();
        self.bg(move |send| {
            let results = Mutex::new(Vec::new());
            for chunk in work.chunks(PROBE_PARALLEL) {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::scope(|sc| {
                    for (name, addr, path, community) in chunk {
                        let net = net.clone();
                        let results = &results;
                        sc.spawn(move || {
                            let r = match addr {
                                Address::Ip(ip) => Probed::Answers(Box::new(crate::probe::ask(net, *ip, path, community)), None),
                                Address::Host(h) => match net.resolve(h) {
                                    Ok(ips) => {
                                        let ip = ips.iter().find(|a| a.is_ipv4()).or(ips.first()).copied().unwrap();
                                        Probed::Answers(Box::new(crate::probe::ask(net, ip, path, community)), Some(ips))
                                    }
                                    Err(e) => Probed::NoAddress(e),
                                },
                                _ => return,
                            };
                            lock(results).push((name.clone(), r));
                        });
                    }
                });
                // One wake-up per batch.
                let batch = std::mem::take(&mut *lock(&results));
                send(Msg::Probed { seq, results: batch });
            }
        });
    }

    fn probed(&self, seq: u64, results: Vec<(Vec<u16>, Probed)>) {
        {
            let mut st = self.st.borrow_mut();
            if seq != st.probe_seq {
                return;
            }
            for (name, r) in results {
                let entry = match r {
                    Probed::Answers(a, resolved) => (Probe::Done(a), resolved),
                    Probed::NoAddress(e) => (Probe::NoAddress(e), None),
                };
                st.probes.insert(name, entry);
            }
            st.probing = st.probes.values().any(|p| p.0 == Probe::Checking);
        }
        self.render();
    }

    fn start_timers(&self) {
        let w = self.me();
        self.probe_timer.start(TimerMode::Repeated, PROBE_EVERY, move || {
            let Some(a) = w.upgrade() else { return };
            if !(a.svc.minimized)() && !a.st.borrow().probing {
                a.probe_all();
            }
        });
        let w = self.me();
        self.queue_timer.start(TimerMode::Repeated, QUEUE_EVERY, move || {
            let Some(a) = w.upgrade() else { return };
            let any_jobs = a.st.borrow().snap.as_ref().is_some_and(|s| s.queues.values().any(|q| q.as_ref().is_ok_and(|j| !j.is_empty())));
            if any_jobs && !a.st.borrow().reading {
                a.refresh();
            }
        });
    }

    // ---------- the rows ----------

    /// The list as the window shows it: every printer with its kind, group, address and real
    /// status, in display order.
    fn entries(&self, st: &State) -> Vec<Entry0> {
        let Some(snap) = &st.snap else { return Vec::new() };
        let List::Printers(v) = &snap.list else { return Vec::new() };
        let now = (self.svc.now)();
        let mut out: Vec<Entry0> = v
            .iter()
            .map(|p| {
                let kind = Self::kind_of(snap, p);
                let port = Self::port_of(snap, p).cloned();
                let address = ports::address(kind, port.as_ref().unwrap_or(&Port { name: p.first_port().into(), ..Port::default() }));
                let (probe, resolved) = match (&address, st.probes.get(&p.name)) {
                    (Address::Ip(_) | Address::Host(_), Some((pr, r))) => (pr.clone(), r.clone()),
                    (Address::Ip(_) | Address::Host(_), None) => (Probe::Checking, None),
                    (Address::Unknown(why), _) => (Probe::NoAddress(why.clone()), None),
                    (Address::None, _) => (Probe::NotNetwork, None),
                };
                let shown = Self::address_text(&address, resolved.as_deref());
                let ipv4 = match &probe {
                    Probe::Done(a) => a.at.is_ipv4(),
                    _ => matches!(address, Address::Ip(IpAddr::V4(_))),
                };
                let snmp_on = port.as_ref().and_then(|x| x.tcp.as_ref()).is_some_and(|t| t.snmp);
                let known = Self::known_of(st, p, port.as_ref(), &address);
                let line = status::real_status(&Facts { spooler: &snap.spooler, printer: p, kind, address: &shown, ipv4, snmp_on, known: &known, probe: &probe, stuck: st.stuck.get(&p.name), now });
                Entry0 { printer: p.clone(), kind, group: Group::of(kind, p.connection), port, address, line }
            })
            .collect();
        // A total order: group, default first, the lower-cased name, the exact units.
        out.sort_by_key(|e| crate::printers::sort_key(&e.printer, e.kind));
        out
    }

    /// What Windows knows of a printer's device (AUDIT-1 PRINT-3): the WSD record's MAC and
    /// printer-uuid, the identity recorded when VibePrint set it up on its current port (the
    /// journal), an mDNS name as its address, its driver's maker.
    fn known_of(st: &State, p: &Printer, port: Option<&Port>, address: &Address) -> status::Known {
        let name = p.name_string();
        // The newest setup that still stands: an undo records no device, and the entry it undid
        // is "undone" (AUDIT-1 R-PRINT-8: after Undo of a Point at, the identity the Switch
        // recorded is what Windows knows again).
        let setup = st
            .journal
            .iter()
            .filter(|j| j.state == "done" && j.undoes.is_none() && matches!(j.fix.as_str(), "port-to-tcp" | "port-address" | "printer-add") && j.printer == name && j.new.get("port").is_some_and(|x| x.eq_ignore_ascii_case(p.first_port())))
            .max_by_key(|j| j.id);
        let rec = |k: &str| setup.and_then(|j| j.new.get(k)).filter(|v| !v.is_empty()).cloned();
        let wsd = port.and_then(|x| x.wsd.as_ref());
        status::Known {
            mac: wsd.and_then(|w| w.mac).or_else(|| rec("mac").and_then(|m| crate::net::parse_mac(&m))),
            // The WSD record's uuid is the IPP printer-uuid (AUDIT-1 R-PRINT-2).
            uuid: wsd.map(|w| w.uuid.trim().to_string()).filter(|u| !u.is_empty()).or_else(|| rec("uuid")),
            serial: rec("serial"),
            model: rec("model"),
            mdns_name: matches!(address, Address::Host(h) if h.trim_end_matches('.').to_ascii_lowercase().ends_with(".local")),
            driver_maker: crate::drivers::maker_of(&p.driver),
        }
    }

    /// The identity of the device at `ip`, as a fix that points a printer there records it
    /// (the journal's "mac", "model", "uuid"): what Add by IP, a probe or Find heard there.
    fn device_at(st: &State, ip: IpAddr) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        let mut put = |k: &str, v: Option<String>| {
            if let Some(v) = v.map(|v| clean_max(&v, 120)).filter(|v| !v.is_empty()) {
                m.entry(k.to_string()).or_insert(v);
            }
        };
        let from = |a: &Answers| {
            let uuid = match &a.ipp {
                Some(crate::ipp::Outcome::Answered(x)) => x.uuid.clone(),
                _ => None,
            };
            let serial = match &a.snmp {
                crate::snmp::Outcome::Answered(s) => s.serial.clone(),
                _ => None,
            };
            (a.mac.map(|x| crate::net::mac_text(&x)), a.model(), uuid, serial)
        };
        let mut heard = Vec::new();
        if let Some((aip, a)) = &st.add.answers
            && IpAddr::V4(*aip) == ip
        {
            heard.push(from(a));
        }
        for (pr, _) in st.probes.values() {
            if let Probe::Done(a) = pr
                && a.at == ip
            {
                heard.push(from(a));
            }
        }
        if let Some(f) = st.find.as_ref().and_then(|r| r.found.iter().find(|f| f.ip.map(IpAddr::V4) == Some(ip))) {
            heard.push((f.mac.map(|x| crate::net::mac_text(&x)), f.model.clone(), f.uuid.clone(), None));
        }
        for (mac, model, uuid, serial) in heard {
            put("mac", mac);
            put("model", model);
            put("uuid", uuid);
            put("serial", serial);
        }
        m
    }

    /// "192.168.1.50", "printer.local (192.168.1.50)", "WSD device, address unknown".
    fn address_text(a: &Address, resolved: Option<&[IpAddr]>) -> String {
        match a {
            Address::Ip(ip) => ip.to_string(),
            Address::Host(h) => match resolved {
                Some(r) if !r.is_empty() => format!("{h} ({})", r.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", ")),
                _ => h.clone(),
            },
            Address::Unknown(w) => w.clone(),
            Address::None => String::new(),
        }
    }

    fn selected_index(st: &State, entries: &[Entry0]) -> Option<usize> {
        match &st.selected {
            Some(sel) => entries.iter().position(|e| &e.printer.name == sel),
            None => (!entries.is_empty()).then_some(0),
        }
    }

    fn row_clicked(&self, i: i32) {
        // `i` is the row's id: the entry index (group headers carry -1).
        let name = {
            let st = self.st.borrow();
            self.entries(&st).get(i as usize).map(|e| e.printer.name.clone())
        };
        if let Some(n) = name {
            self.st.borrow_mut().selected = Some(n);
        }
        self.render();
    }

    /// A key nothing focused took: Up/Down/Home/End move the selection, F5 reads again, Ctrl+C
    /// copies the report. True when used.
    fn key(&self, t: &str, ctrl: bool, _shift: bool) -> bool {
        use slint::platform::Key;
        let k = |key: Key| SharedString::from(key) == t;
        if ctrl && (t == "c" || t == "C") {
            self.copy_report();
            return true;
        }
        if k(Key::F5) {
            self.refresh_all();
            return true;
        }
        let (n, cur) = {
            let st = self.st.borrow();
            let e = self.entries(&st);
            (e.len(), Self::selected_index(&st, &e).unwrap_or(0))
        };
        if n == 0 {
            return false;
        }
        let next = if k(Key::UpArrow) {
            cur.saturating_sub(1)
        } else if k(Key::DownArrow) {
            (cur + 1).min(n - 1)
        } else if k(Key::Home) {
            0
        } else if k(Key::End) {
            n - 1
        } else {
            return false;
        };
        self.row_clicked(next as i32);
        self.st.borrow_mut().scroll_seq += 1;
        self.render();
        true
    }

    // ---------- the fixes ----------

    /// The fixes that apply to an entry, in order: its status line's own first.
    fn fixes_for(&self, st: &State, e: &Entry0) -> Vec<(FixKind, String, bool)> {
        let mut v: Vec<(FixKind, String, bool)> = Vec::new();
        let answers = match st.probes.get(&e.printer.name) {
            Some((Probe::Done(a), _)) => Some(a.as_ref()),
            _ => None,
        };
        // Running, or its state unknown while the printers were listed (AUDIT-1 PRINT-6).
        let spooler_up = st.snap.as_ref().is_some_and(|s| s.spooler.running() || (matches!(s.spooler, Spooler::Unknown(_)) && matches!(s.list, List::Printers(_))));
        if !spooler_up {
            return v;
        }
        let queue = st.snap.as_ref().and_then(|s| s.queues.get(&e.printer.name)).and_then(|q| q.as_ref().ok());
        let jobs = queue.map_or(0, Vec::len);
        let mine = queue.map_or(0, |q| q.iter().filter(|j| j.mine).count());
        let local = !e.printer.connection;
        match e.line.fix {
            Some(Fix::UseOnline) if local => v.push((FixKind::UseOnline, "Use online".into(), false)),
            Some(Fix::SwitchToTcp) if local => {
                if let Some(a) = answers
                    && let IpAddr::V4(ip) = a.at
                    && let Ok((protocol, snmp)) = crate::fixes::protocol_for(a)
                {
                    v.push((FixKind::SwitchToTcp { ip, protocol, snmp }, "Switch to a TCP/IP port…".into(), true));
                }
            }
            Some(Fix::SnmpOff) if local => v.push((FixKind::SnmpOff, "Turn off the SNMP check…".into(), true)),
            Some(Fix::RestartSpooler) => v.push((FixKind::RestartSpooler, "Restart spooler…".into(), true)),
            Some(Fix::Find) => v.push((FixKind::Search, "Search the LAN".into(), false)),
            _ => {}
        }
        // "Point at the new address": a Find match for this printer's TCP/IP port.
        if local
            && e.kind == Kind::Tcp
            && let Some(ip) = self.moved_to(st, e)
        {
            v.push((FixKind::PointAt { ip }, format!("Point at {ip}…"), true));
        }
        // A shared printer's other jobs are cleared on the PC that shares it: here only your own
        // (AUDIT-1 PRINT-9).
        if jobs > 0 && (local || mine > 0) {
            v.push((FixKind::ClearQueue, if local { "Clear queue…".into() } else { "Clear my jobs…".into() }, false));
        }
        if local && e.kind != Kind::Cloud {
            v.push((FixKind::TestPage, "Print test page".into(), false));
        }
        v
    }

    /// The address Find found this TCP/IP printer at, when it moved (same MAC or a "maybe").
    fn moved_to(&self, st: &State, e: &Entry0) -> Option<Ipv4Addr> {
        let results = st.find.as_ref()?;
        let installed = self.installed(st);
        let me = installed.iter().position(|i| i.name == e.printer.name)?;
        results.found.iter().find_map(|f| match find::match_found(f, &installed) {
            Match::Moved(i) | Match::Maybe(i) if i == me => f.ip.filter(|ip| Some(IpAddr::V4(*ip)) != e.address.ip()),
            _ => None,
        })
    }

    fn fix_clicked(&self, id: i32) {
        let (kind, printer) = {
            let st = self.st.borrow();
            let entries = self.entries(&st);
            let Some(i) = Self::selected_index(&st, &entries) else { return };
            let e = &entries[i];
            let fixes = self.fixes_for(&st, e);
            let Some((kind, _, _)) = fixes.into_iter().nth(id as usize) else { return };
            (kind, Some(e.printer.name.clone()))
        };
        if kind == FixKind::Search {
            self.find();
            return;
        }
        self.plan_fix(kind, printer);
    }

    /// Show what a fix will do (the confirm dialog), planned against the newest read.
    fn plan_fix(&self, kind: FixKind, printer: Option<Vec<u16>>) {
        if self.st.borrow().fix_running.is_some() {
            self.toast("Another fix is still running.", ToastKind::Info, None);
            return;
        }
        let plan = {
            let st = self.st.borrow();
            let entries = self.entries(&st);
            let e = printer.as_ref().and_then(|n| entries.iter().find(|e| &e.printer.name == n));
            let snap = st.snap.clone().unwrap_or_default();
            let name = e.map(|e| e.printer.display()).unwrap_or_default();
            let port = e.and_then(|e| e.port.clone()).unwrap_or_default();
            let old_address = e.map(|e| Self::address_text(&e.address, None)).unwrap_or_default();
            let jobs: Vec<QJob> = printer.as_ref().and_then(|n| snap.queues.get(n)).and_then(|q| q.as_ref().ok()).cloned().unwrap_or_default();
            let sharing: Vec<String> = match (&snap.list, e) {
                (List::Printers(v), Some(e)) => v.iter().filter(|p| p.name != e.printer.name && p.first_port().eq_ignore_ascii_case(e.printer.first_port())).map(Printer::display).collect(),
                _ => Vec::new(),
            };
            let entry = match &kind {
                FixKind::Undo { entry } => st.journal.iter().find(|x| x.id == *entry).cloned(),
                _ => None,
            };
            let server = e.filter(|e| e.printer.connection).map(|e| e.printer.server.trim_start_matches('\\').to_string()).unwrap_or_default();
            crate::fixes::plan(&kind, &crate::fixes::Context { name: &name, port: &port, old_address: &old_address, jobs: &jobs, spooler: &snap.spooler, sharing: &sharing, entry: entry.as_ref(), server: &server })
        };
        {
            let mut st = self.st.borrow_mut();
            let port = printer.as_ref().and_then(|n| Self::printers_of(&st).into_iter().find(|p| &p.name == n)).map(|p| p.first_port().to_string()).unwrap_or_default();
            let old_address = {
                let entries = self.entries(&st);
                printer.as_ref().and_then(|n| entries.iter().find(|e| &e.printer.name == n)).map(|e| Self::address_text(&e.address, None)).unwrap_or_default()
            };
            let device = match &kind {
                FixKind::SwitchToTcp { ip, .. } | FixKind::PointAt { ip } | FixKind::AddByIp { ip, .. } => Self::device_at(&st, IpAddr::V4(*ip)),
                _ => BTreeMap::new(),
            };
            st.planned = Some(Planned { kind: kind.clone(), printer, port, old_address, device });
        }
        if let Some(ui) = self.ui() {
            ui.set_confirm(ConfirmInfo {
                title: s(&plan.title),
                steps: ModelRc::new(VecModel::from(plan.steps.iter().map(s).collect::<Vec<_>>())),
                admin: plan.admin,
                button: s(&plan.button),
                note: s(&plan.note),
            });
            ui.set_confirm_open(true);
        }
    }

    fn confirm_cancel(&self) {
        self.st.borrow_mut().planned = None;
        if let Some(ui) = self.ui() {
            ui.set_confirm_open(false);
        }
    }

    fn confirm_ok(&self) {
        let Some(plan) = self.st.borrow_mut().planned.take() else { return };
        if let Some(ui) = self.ui() {
            ui.set_confirm_open(false);
        }
        self.run_fix(plan);
    }

    /// Run a confirmed fix on a worker: read again, refuse when what it was planned on changed,
    /// journal it as pending, do it (unelevated where it can, else the helper), journal what
    /// happened, read again and say what is now true.
    fn run_fix(&self, plan: Planned) {
        let seq = {
            let mut st = self.st.borrow_mut();
            if st.fix_running.is_some() {
                return;
            }
            st.fix_seq += 1;
            st.fix_running = Some(plan.kind.clone());
            st.fix_seq
        };
        self.render();
        let sys = self.svc.system.clone();
        let hwnd = (self.svc.hwnd)();
        let stop = self.stop.clone();
        let journal = self.journal.clone();
        let (machine, entries) = {
            let st = self.st.borrow();
            (st.machine.clone(), st.journal.clone())
        };
        let now = self.now();
        let pc = sys.computer_name();
        let when = self.date_time(now);
        let shown_silent = self.st.borrow().snap.as_ref().is_some_and(|s| matches!(s.spooler, Spooler::Silent(_)));
        self.bg(move |send| {
            let kind = plan.kind.clone();
            let printer = plan.printer.clone();
            let (outcome, wrote, garbled, snap) = crate::fixes::run(&crate::fixes::Run { sys: sys.as_ref(), plan: &crate::fixes::Plan0 { kind: &plan.kind, printer: plan.printer.as_deref(), port: &plan.port, old_address: &plan.old_address, device: &plan.device }, hwnd, stop: &stop, journal: journal.as_ref(), machine: &machine, entries: &entries, now, pc: &pc, when: &when, shown_silent });
            // The fix's own read after is what the window shows (AUDIT-1 PRINT-13).
            send(Msg::Fixed { seq, kind, printer, outcome, journal: wrote, garbled, snap: Box::new(snap) });
        });
    }

    fn fixed(&self, seq: u64, kind: FixKind, printer: Option<Vec<u16>>, outcome: FixOutcome, journal: Option<Journal>, snap: Snapshot) {
        {
            let mut st = self.st.borrow_mut();
            if seq != st.fix_seq {
                return;
            }
            st.fix_running = None;
            if let Some(j) = journal {
                st.journal = j.of(&st.machine);
            }
        }
        // The read that came with it is the newest: take it as one.
        let rseq = {
            let mut st = self.st.borrow_mut();
            st.read_seq += 1;
            st.read_seq
        };
        self.read_done(rseq, snap);
        match &outcome {
            FixOutcome::Done(words) => self.toast(words, ToastKind::Ok, None),
            FixOutcome::NotDone(words) => self.toast(words, if words.starts_with("Not done: administrator") { ToastKind::Info } else { ToastKind::Error }, None),
            FixOutcome::Unknown(words) => self.toast(words, ToastKind::Error, None),
        }
        // The printer is asked again (its port or address may be new).
        if matches!(outcome, FixOutcome::Done(_)) && !matches!(kind, FixKind::TestPage) {
            if let Some(p) = printer {
                self.st.borrow_mut().probes.remove(&p);
            }
            self.probe_all();
        }
        if matches!(kind, FixKind::AddByIp { .. }) && matches!(outcome, FixOutcome::Done(_)) {
            self.add_close();
        }
        self.render();
    }

    // ---------- Find ----------

    fn find(&self) {
        let seq = {
            let mut st = self.st.borrow_mut();
            if st.finding {
                st.find_open = true;
                drop(st);
                self.render();
                return;
            }
            st.find_seq += 1;
            st.finding = true;
            st.find_open = true;
            st.find_started = Some(Instant::now());
            st.found_selected = None;
            st.find_seq
        };
        let stop = Arc::new(AtomicBool::new(false));
        *self.find_stop.borrow_mut() = stop.clone();
        let w = self.me();
        self.find_timer.start(TimerMode::Repeated, Duration::from_secs(1), move || {
            if let Some(a) = w.upgrade() {
                a.render();
            }
        });
        self.render();
        let net = self.svc.system.net();
        // Stop, closing the panel and closing the window all set this flag (finish_prefs too).
        self.bg(move |send| {
            let adapters = net.adapters();
            let results = find::run(net.as_ref(), &adapters, &stop);
            send(Msg::Found { seq, results });
        });
    }

    fn find_stop(&self) {
        self.find_stop.borrow().store(true, Ordering::SeqCst);
    }

    fn find_close(&self) {
        self.find_stop();
        self.st.borrow_mut().find_open = false;
        self.render();
    }

    fn found(&self, seq: u64, mut results: find::Results) {
        {
            let installed = {
                let st = self.st.borrow();
                if seq != st.find_seq {
                    return;
                }
                self.installed(&st)
            };
            // What can be acted on first: a printer that moved, then a maybe, then devices not
            // installed, then the installed ones where they are (a stable order otherwise).
            let rank = |f: &Found| match find::match_found(f, &installed) {
                Match::Moved(_) => 0,
                Match::Maybe(_) => 1,
                Match::None | Match::NotIt(_) => 2,
                Match::Same(_) => 3,
            };
            results.found.sort_by_key(|f| (rank(f), f.ip.map(u32::from).unwrap_or(u32::MAX)));
            let mut st = self.st.borrow_mut();
            st.finding = false;
            st.find = Some(results);
            st.found_selected = st.find.as_ref().filter(|r| !r.found.is_empty()).map(|_| 0);
        }
        self.find_timer.stop();
        self.render();
    }

    fn found_clicked(&self, i: i32) {
        self.st.borrow_mut().found_selected = Some(i.max(0) as usize);
        self.render();
    }

    /// A key in Find's results (X15A11Y-2: the keyboard picks a device, as in the printer list):
    /// the row it picked, for the list to bring into view, or -1 when the key is not one of
    /// Up/Down/Home/End.
    fn found_key(&self, t: &str) -> i32 {
        let (cur, n) = {
            let st = self.st.borrow();
            (st.found_selected, st.find.as_ref().map_or(0, |r| r.found.len()))
        };
        let Some(i) = list_step(t, cur, n) else { return -1 };
        self.found_clicked(i as i32);
        i as i32
    }

    /// The installed printers as Find's matching sees them.
    fn installed(&self, st: &State) -> Vec<Installed> {
        let entries = self.entries(st);
        let snap = st.snap.as_ref();
        entries
            .iter()
            .map(|e| {
                let probe = st.probes.get(&e.printer.name).map(|p| &p.0);
                let known = Self::known_of(st, &e.printer, e.port.as_ref(), &e.address);
                // A different device at its address is not this printer answering, and its MAC
                // and model are not this printer's.
                let other = match probe {
                    Some(Probe::Done(a)) => matches!(status::ident(&known, &status::Device::of(a, a.model().as_deref())), status::Ident::Other(_)),
                    _ => false,
                };
                let (answers, model) = match probe {
                    Some(Probe::Done(a)) if other => (Some(false), None),
                    Some(Probe::Done(a)) => (Some(a.answers()), a.model()),
                    _ => (None, None),
                };
                let ip = match probe {
                    Some(Probe::Done(a)) => Some(a.at),
                    _ => e.address.ip(),
                };
                // The MAC: WSD's PnP-X, else the ARP answer, else the neighbour cache.
                let mac = known
                    .mac
                    .or(match probe {
                        Some(Probe::Done(a)) if !other => a.mac,
                        _ => None,
                    })
                    .or_else(|| ip.filter(|_| !other).and_then(|ip| snap.and_then(|s| s.neighbours.iter().find(|n| n.0 == ip).map(|n| n.1))));
                let mut models = vec![e.printer.driver.clone()];
                models.extend(model);
                Installed { name: e.printer.name.clone(), display: e.printer.display(), ip, mac, models, answers, pointable: matches!(e.kind, Kind::Tcp | Kind::Wsd) && !e.printer.connection, known }
            })
            .collect()
    }

    /// The actions for the selected found device: Add…, Point <printer> here…, Open web page.
    fn found_actions(&self, st: &State) -> Vec<(i32, String, bool)> {
        let Some(f) = st.found_selected.and_then(|i| st.find.as_ref().and_then(|r| r.found.get(i))) else { return Vec::new() };
        let installed = self.installed(st);
        let m = find::match_found(f, &installed);
        let mut v = Vec::new();
        if f.ip.is_some() && !matches!(m, Match::Same(_)) {
            v.push((1, "Add…".into(), true));
        }
        if let (Match::Moved(i) | Match::Maybe(i), Some(_)) = (&m, f.ip)
            && installed[*i].pointable
        {
            v.push((2, format!("Point '{}' here…", clean_max(&installed[*i].display, 40)), true));
        }
        if f.adminurl.as_deref().and_then(crate::host::safe_web_url).is_some() {
            v.push((3, "Open its web page".into(), false));
        }
        v
    }

    fn found_action(&self, id: i32) {
        let (f, target) = {
            let st = self.st.borrow();
            let Some(f) = st.found_selected.and_then(|i| st.find.as_ref().and_then(|r| r.found.get(i))).cloned() else { return };
            let installed = self.installed(&st);
            let target = find::match_found(&f, &installed).printer().map(|i| (installed[i].name.clone(), installed[i].pointable));
            (f, target)
        };
        match id {
            1 => self.add_open(Some(f)),
            2 => {
                let (Some(ip), Some((name, true))) = (f.ip, target) else { return };
                // A TCP/IP port is pointed at the new address; a WSD printer gets a TCP/IP port
                // to it (the switch).
                let kind = {
                    let st = self.st.borrow();
                    let entries = self.entries(&st);
                    entries.iter().find(|e| e.printer.name == name).map(|e| e.kind)
                };
                match kind {
                    Some(Kind::Tcp) => self.plan_fix(FixKind::PointAt { ip }, Some(name)),
                    Some(Kind::Wsd) => {
                        let protocol = if f.ports.contains(&9100) {
                            Some(Protocol::Raw)
                        } else if f.ports.contains(&515) {
                            Some(Protocol::Lpr)
                        } else {
                            None
                        };
                        match protocol {
                            Some(protocol) => self.plan_fix(FixKind::SwitchToTcp { ip, protocol, snmp: false }, Some(name)),
                            // Not "use Add by IP": it refuses IPP-only printers too (fixes::protocol_for, copy-ux M7).
                            None => self.toast("The printer answers IPP only: Windows' Add printer can add it as an IPP printer.", ToastKind::Info, None),
                        }
                    }
                    _ => {}
                }
            }
            3 => {
                if let Some(u) = f.adminurl.as_deref().and_then(crate::host::safe_web_url) {
                    (self.svc.open)(Opening::Web(u));
                }
            }
            _ => {}
        }
    }

    // ---------- Add by IP ----------

    fn add_open(&self, from: Option<Found>) {
        {
            let mut st = self.st.borrow_mut();
            st.add = AddState { seq: st.add.seq + 1, ..AddState::default() };
            if let Some(f) = &from {
                st.add.ip_text = f.ip.map(|i| i.to_string()).unwrap_or_default();
                st.add.name = clean_max(&f.model.clone().unwrap_or_else(|| f.title()), 100).replace([',', '!', '\\'], " ");
            }
            st.add.ip_first = st.add.ip_text.clone();
            st.add.name_first = st.add.name.clone();
        }
        if let Some(ui) = self.ui() {
            let st = self.st.borrow();
            ui.set_add_ip(s(&st.add.ip_text));
            ui.set_add_name(s(&st.add.name));
            ui.set_add_open(true);
        }
        let sys = self.svc.system.clone();
        self.bg(move |send| send(Msg::Drivers { list: sys.drivers() }));
        let t = self.st.borrow().add.ip_text.clone();
        if !t.is_empty() {
            self.add_ip_edited(&t);
        }
        self.render();
    }

    fn add_close(&self) {
        {
            let mut st = self.st.borrow_mut();
            st.add.seq += 1;
            st.add.checking = false;
        }
        if let Some(ui) = self.ui() {
            ui.set_add_open(false);
        }
    }

    fn add_drivers(&self, list: Vec<String>) {
        {
            let mut st = self.st.borrow_mut();
            st.add.drivers = list;
            Self::add_pick(&mut st.add);
        }
        self.render();
    }

    /// Preselect the driver that fits the model (the user's own pick stays).
    fn add_pick(a: &mut AddState) {
        if a.driver.is_some() {
            return;
        }
        let model = a.answers.as_ref().and_then(|x| x.1.model()).unwrap_or_else(|| a.name.clone());
        a.driver = crate::drivers::pick(&model, &a.drivers);
    }

    fn add_ip_edited(&self, t: &str) {
        let (seq, ip) = {
            let mut st = self.st.borrow_mut();
            st.add.seq += 1;
            st.add.ip_text = t.to_string();
            st.add.answers = None;
            let ip = crate::helper::valid_ipv4(&typed_ip(t));
            st.add.checking = ip.is_some();
            (st.add.seq, ip)
        };
        self.render();
        let Some(ip) = ip else { return };
        let net = self.svc.system.net();
        self.bg(move |send| {
            let a = crate::probe::ask(net, IpAddr::V4(ip), crate::ipp::DEFAULT_PATH, crate::snmp::COMMUNITY);
            send(Msg::AddChecked { seq, ip, answers: Box::new(a) });
        });
    }

    fn add_checked(&self, seq: u64, ip: Ipv4Addr, answers: Answers) {
        {
            let mut st = self.st.borrow_mut();
            if seq != st.add.seq {
                return; // the address was changed since: an old answer
            }
            st.add.checking = false;
            if !st.add.name_edited
                && st.add.name.is_empty()
                && let Some(m) = answers.model()
            {
                st.add.name = clean_max(&m, 100).replace([',', '!', '\\'], " ");
            }
            st.add.answers = Some((ip, answers));
            Self::add_pick(&mut st.add);
        }
        if let Some(ui) = self.ui() {
            ui.set_add_name(s(&self.st.borrow().add.name));
        }
        self.render();
    }

    /// Escape in a field: it puts back what it held when the dialog opened and goes no further;
    /// with nothing to put back it passes on (the dialog cancels).
    fn add_escaped(&self, ip: bool) -> bool {
        let (cur, first) = {
            let st = self.st.borrow();
            if ip { (st.add.ip_text.clone(), st.add.ip_first.clone()) } else { (st.add.name.clone(), st.add.name_first.clone()) }
        };
        if cur == first {
            return false;
        }
        if let Some(ui) = self.ui() {
            if ip {
                ui.set_add_ip(s(&first));
            } else {
                ui.set_add_name(s(&first));
            }
        }
        if ip {
            self.add_ip_edited(&first);
        } else {
            let mut st = self.st.borrow_mut();
            st.add.name = first;
            drop(st);
            self.render();
        }
        true
    }

    fn add_name_edited(&self, t: &str) {
        let mut st = self.st.borrow_mut();
        st.add.name = t.to_string();
        st.add.name_edited = true;
        drop(st);
        self.render();
    }

    fn add_driver_changed(&self, i: i32) {
        self.st.borrow_mut().add.driver = (i >= 0).then_some(i as usize);
        self.render();
    }

    /// What Add by IP would do now: Ok(the fix) or Err(why not).
    fn add_ready(st: &State) -> Result<FixKind, String> {
        let a = &st.add;
        let Some(ip) = crate::helper::valid_ipv4(&typed_ip(&a.ip_text)) else {
            return Err(if a.ip_text.trim().is_empty() { String::new() } else { "Not an address a printer can have (a unicast IPv4 address).".into() });
        };
        if a.checking {
            return Err(format!("Checking {ip}…"));
        }
        let Some((at, ans)) = &a.answers else { return Err(String::new()) };
        if *at != ip {
            return Err(String::new());
        }
        let (protocol, snmp) = crate::fixes::protocol_for(ans).map_err(|e| if ans.anything() { e } else { format!("No answer at {ip}: is the printer on?") })?;
        let name: Vec<u16> = w(a.name.trim());
        if !crate::helper::valid_new_name(&name) {
            return Err("A name of 1 to 220 characters, without \\ , or !.".into());
        }
        if Self::printers_of(st).iter().any(|p| crate::shd::same_printer(&p.name, &name)) {
            return Err("A printer with that name exists.".into());
        }
        let Some(driver) = a.driver.and_then(|i| a.drivers.get(i)).cloned() else { return Err("No driver for this printer is installed: Windows' Add printer can fetch one.".into()) };
        Ok(FixKind::AddByIp { ip, name, driver, protocol, snmp })
    }

    fn add_confirm(&self) {
        let r = Self::add_ready(&self.st.borrow());
        if let Ok(kind) = r {
            self.plan_fix(kind, None);
        }
    }

    // ---------- the journal ----------

    fn load_journal(&self) {
        let Some(j) = self.journal.clone() else { return };
        self.bg(move |send| {
            let journal = j.load();
            send(Msg::Journal { journal, broken: j.broken() });
        });
    }

    fn journal_loaded(&self, journal: Journal, broken: bool) {
        {
            let mut st = self.st.borrow_mut();
            st.journal = journal.of(&st.machine);
        }
        if broken {
            self.toast("journal.json could not be read: it will be kept as journal.json.broken, and a new journal starts with the next fix.", ToastKind::Error, None);
        }
        self.render();
    }

    fn journal_open(&self) {
        {
            let mut st = self.st.borrow_mut();
            st.journal_selected = st.journal.last().map(|e| e.id);
        }
        if let Some(ui) = self.ui() {
            ui.set_journal_open(true);
        }
        self.render();
    }

    fn journal_close(&self) {
        if let Some(ui) = self.ui() {
            ui.set_journal_open(false);
        }
    }

    fn journal_clicked(&self, i: i32) {
        {
            let mut st = self.st.borrow_mut();
            let id = st.journal.iter().rev().nth(i.max(0) as usize).map(|e| e.id);
            st.journal_selected = id;
        }
        self.render();
    }

    /// A key in the journal's list (X15A11Y-2: an older entry can be picked for Undo without a
    /// mouse): the row it picked (newest first, as shown), or -1 when the key is not one of
    /// Up/Down/Home/End.
    fn journal_key(&self, t: &str) -> i32 {
        let (cur, n) = {
            let st = self.st.borrow();
            (st.journal_selected.and_then(|id| st.journal.iter().rev().position(|e| e.id == id)), st.journal.len().min(JOURNAL_SHOWN))
        };
        let Some(i) = list_step(t, cur, n) else { return -1 };
        self.journal_clicked(i as i32);
        i as i32
    }

    /// Whether the selected entry can be undone now (against the newest read).
    fn undo_of(&self, st: &State, e: &Entry) -> Result<journal::Undo, String> {
        let snap = st.snap.clone().unwrap_or_default();
        let printers = Self::printers_of(st);
        let port_of = |name: &str| printers.iter().find(|p| p.name_string() == name).map(|p| p.first_port().to_string());
        let tcp_of = |port: &str| snap.ports.iter().find(|p| p.name.eq_ignore_ascii_case(port)).and_then(|p| p.tcp.as_ref()).map(|t| (t.target().to_string(), t.snmp, t.community.clone()));
        let exists = |port: &str| snap.ports.iter().any(|p| p.name.eq_ignore_ascii_case(port)) || port.to_ascii_uppercase().starts_with("WSD-");
        journal::undo(e, &st.journal, &journal::Now { port_of: &port_of, tcp_of: &tcp_of, port_exists: &exists })
    }

    fn journal_undo(&self) {
        let target = {
            let st = self.st.borrow();
            let Some(e) = st.journal_selected.and_then(|id| st.journal.iter().find(|x| x.id == id)).cloned() else { return };
            match self.undo_of(&st, &e) {
                Ok(_) => Some(e),
                Err(why) => {
                    drop(st);
                    self.toast(&format!("No undo: {why}."), ToastKind::Info, None);
                    None
                }
            }
        };
        if let Some(e) = target {
            self.journal_close();
            let printer = (!e.printer.is_empty()).then(|| w(&e.printer));
            self.plan_fix(FixKind::Undo { entry: e.id }, printer);
        }
    }

    // ---------- Copy report ----------

    pub fn report(&self) -> String {
        let st = self.st.borrow();
        let entries = self.entries(&st);
        let now = self.now();
        let mut pc = vec![("PC".to_string(), self.svc.system.computer_name()), ("Read".to_string(), self.date_time(st.read_at.unwrap_or(now)))];
        if let Some(snap) = &st.snap {
            pc.push(("Print Spooler".into(), status::spooler_line(&snap.spooler).map(|l| l.text).unwrap_or_else(|| "running".into())));
        }
        if self.svc.mode.portable() {
            pc.push(("Mode".into(), "portable".into()));
        }
        let printers: Vec<crate::report::Printer> = entries
            .iter()
            .map(|e| {
                let (_, pairs, jobs, _) = self.detail(&st, e, usize::MAX);
                let mut sections: Vec<(String, Vec<(String, String)>)> = Vec::new();
                for p in pairs {
                    if p.section {
                        sections.push((p.key.to_string(), Vec::new()));
                    } else if let Some(last) = sections.last_mut() {
                        last.1.push((p.key.to_string(), p.value.to_string()));
                    }
                }
                sections.push(("Queue".into(), jobs.iter().map(|j| (j.document.to_string(), format!("{} · {}", j.detail, j.status))).collect()));
                crate::report::Printer { name: e.printer.display(), group: e.group.title().into(), default: e.printer.default, line: e.line.text.clone(), sections }
            })
            .collect();
        crate::report::text(&pc, &printers)
    }

    fn copy_report(&self) -> bool {
        let r = self.report();
        (self.svc.copy)(&r)
    }

    // ---------- rendering ----------

    /// The detail of one entry: the header, the fields by section, the jobs, the notes.
    /// `limit`: the most jobs listed (the window lists 200; the report every one read).
    fn detail(&self, st: &State, e: &Entry0, limit: usize) -> (DetailInfo, Vec<DetailPair>, Vec<JobRow>, Vec<String>) {
        let pair = |k: &str, v: String, mono: bool| DetailPair { key: s(k), value: s(clean_max(&v, 600)), mono, section: false };
        let section = |k: &str| DetailPair { key: s(k), value: s(""), mono: false, section: true };
        let p = &e.printer;
        let now = self.now();
        let mut pairs = vec![section("WINDOWS")];
        pairs.push(pair("State", p.windows_words(), false));
        if p.work_offline() {
            pairs.push(pair("Use offline", "On: Windows was told to use this printer offline".into(), false));
        }
        if p.default {
            pairs.push(pair("Default", "This is the default printer".into(), false));
        }
        if p.connection {
            pairs.push(pair("Shared by", clean_max(p.server.trim_start_matches('\\'), 80), true));
        }
        if !p.location.trim().is_empty() {
            pairs.push(pair("Location", clean_max(&p.location, 200), false));
        }
        // ---- what the printer says ----
        let probe = st.probes.get(&p.name).map(|x| x.0.clone());
        let mut notes = Vec::new();
        if e.kind.network() {
            pairs.push(section("THE PRINTER SAYS"));
            match &probe {
                Some(Probe::Done(a)) => {
                    pairs.push(pair("Asked at", a.at.to_string(), true));
                    pairs.push(pair("Ping", a.ping.words(), false));
                    pairs.push(pair("Ports", a.ports_words(), true));
                    match &a.ipp {
                        Some(crate::ipp::Outcome::Answered(x)) => {
                            pairs.push(pair("IPP state", x.words(), false));
                            if !x.reasons.is_empty() {
                                pairs.push(pair("IPP reasons", x.reasons.join(", "), true));
                            }
                            if let Some(m) = &x.make_model {
                                pairs.push(pair("Model", m.clone(), false));
                            }
                            for (name, level) in &x.markers {
                                pairs.push(pair(if name.is_empty() { "Supply" } else { name }, crate::ipp::level_words(*level), false));
                            }
                        }
                        Some(o) => pairs.push(pair("IPP", o.words(), false)),
                        None => pairs.push(pair("IPP", "not asked (port 631 is not open)".into(), false)),
                    }
                    match &a.snmp {
                        crate::snmp::Outcome::Answered(x) => {
                            let mut v = x.words();
                            if !x.errors.is_empty() {
                                v = x.errors.join(", ");
                            }
                            pairs.push(pair("SNMP", v, false));
                            if let Some(d) = &x.descr {
                                pairs.push(pair("Describes itself as", d.clone(), false));
                            }
                        }
                        crate::snmp::Outcome::Silent => pairs.push(pair("SNMP", format!("no answer (community {})", clean_max(&Self::community(e.port.as_ref()), 40)), false)),
                        crate::snmp::Outcome::Failed(why) => pairs.push(pair("SNMP", why.clone(), false)),
                    }
                    if let Some(m) = a.mac {
                        let maker = crate::oui::lookup(&m).short();
                        pairs.push(pair("MAC", if maker.is_empty() { crate::net::mac_text(&m) } else { format!("{} ({maker})", crate::net::mac_text(&m)) }, true));
                    }
                }
                Some(Probe::Checking) | None if matches!(e.address, Address::Ip(_) | Address::Host(_)) => pairs.push(pair("Asking", format!("{}…", Self::address_text(&e.address, None)), false)),
                Some(Probe::NoAddress(why)) => pairs.push(pair("Not asked", why.clone(), false)),
                _ => pairs.push(pair(
                    "Not asked",
                    match &e.address {
                        Address::Unknown(why) => why.clone(),
                        _ => "its address is not known".into(),
                    },
                    false,
                )),
            }
        }
        // ---- the port ----
        pairs.push(section("PORT"));
        pairs.push(pair("Port", if p.pooled() { format!("{} (pooled: {})", p.first_port(), p.port) } else { p.port.clone() }, true));
        pairs.push(pair("Kind", e.kind.words().into(), false));
        if let Some(port) = &e.port {
            if !port.monitor.is_empty() {
                pairs.push(pair("Monitor", port.monitor.clone(), false));
            }
            if let Some(t) = &port.tcp {
                let resolved = st.probes.get(&p.name).and_then(|x| x.1.clone());
                pairs.push(pair("Address", Self::address_text(&e.address, resolved.as_deref()), true));
                if p.first_port().to_ascii_uppercase().starts_with("IP_") && !p.first_port().eq_ignore_ascii_case(&format!("IP_{}", t.target())) {
                    notes.push(format!("The port's name says {}, but it sends to {}.", clean_max(&p.first_port()[3..], 80), clean_max(t.target(), 80)));
                }
                pairs.push(pair("Protocol", t.protocol_words(), false));
                pairs.push(pair("SNMP check", if t.snmp { format!("on (community {})", clean_max(&t.community, 40)) } else { "off".into() }, false));
            }
            if let Some(wsd) = &port.wsd {
                pairs.push(pair("Device", if wsd.ips.is_empty() { "WSD device, address unknown".into() } else { wsd.ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ") }, true));
                if let Some(m) = wsd.mac {
                    pairs.push(pair("Device MAC", crate::net::mac_text(&m), true));
                }
                if !wsd.present {
                    notes.push("Windows has not seen the WSD device lately: these are its last known values.".into());
                }
            }
        }
        if matches!(e.kind, Kind::Ipp) && e.port.as_ref().and_then(|x| x.tcp.as_ref()).is_none() {
            pairs.push(pair("Address", Self::address_text(&e.address, None), true));
        }
        // ---- the driver ----
        pairs.push(section("DRIVER"));
        match st.snap.as_ref().and_then(|s| s.drivers.get(&p.name)) {
            Some(Ok(d)) => {
                pairs.push(pair("Driver", d.name.clone(), false));
                pairs.push(pair("Kind", d.kind_words(), false));
                if let Some(v) = &d.version {
                    pairs.push(pair("Version", v.clone(), true));
                }
                if let Some(t) = d.date {
                    pairs.push(pair("Date", crate::host::date(t, 0), true));
                }
            }
            Some(Err(why)) => pairs.push(pair("Driver", format!("{} ({why})", p.driver), false)),
            None => pairs.push(pair("Driver", if p.driver.is_empty() { "not known".into() } else { p.driver.clone() }, false)),
        }
        // ---- the queue ----
        let mut jobs = Vec::new();
        match st.snap.as_ref().and_then(|s| s.queues.get(&p.name)) {
            Some(Ok(v)) => {
                let stuck = st.stuck.get(&p.name).map(|x| x.job.id);
                let mut v = v.clone();
                v.sort_by_key(|j| (j.position, j.id));
                for (i, j) in v.iter().take(limit).enumerate() {
                    let pages = if j.total_pages > 0 { format!("{} of {} pages", j.pages_printed.min(j.total_pages), j.total_pages) } else { "pages unknown".into() };
                    let detail = format!("{} · {pages} · {} · {}", clean_max(&j.owner, 40), crate::fixes::size_words(j.size), self.date_time(j.submitted));
                    let status = crate::queue::status_words(j.status, &j.status_text);
                    let st_code = if stuck == Some(j.id) || crate::queue::blocked(j.status) { status::BROKEN } else { status::QUIET };
                    jobs.push(JobRow { id: i as i32, document: s(clean_max(&j.document, 120)), detail: s(&detail), status: s(&status), state: st_code, a11y: s(format!("{detail}, {status}")) });
                }
                if v.len() > limit {
                    notes.push(format!("{} more jobs are not listed here.", v.len() - limit));
                }
                // EnumJobs reads the first 500: the queue's own count says if there are more.
                if p.jobs as usize > v.len() {
                    notes.push(format!("The queue holds {} jobs; the first {} were read.", p.jobs, v.len()));
                }
            }
            Some(Err(why)) => notes.push(format!("The queue: {why}.")),
            None => {}
        }
        if e.kind.network() {
            notes.push(status::FIXED_ADDRESS_TIP.into());
        }
        let d = DetailInfo {
            title: s(p.display()),
            state: e.line.state,
            state_word: s(Self::state_word(e.line.state)),
            line: s(&e.line.text),
            notes: ModelRc::new(VecModel::from(notes.iter().map(s).collect::<Vec<_>>())),
            queue_title: s(match jobs.len() {
                0 => "QUEUE · empty".to_string(),
                1 => "QUEUE · 1 job".to_string(),
                n => format!("QUEUE · {n} jobs"),
            }),
        };
        let _ = now;
        (d, pairs, jobs, notes)
    }

    fn state_word(state: i32) -> &'static str {
        match state {
            status::CHECKING => "checking",
            status::OK => "ok",
            status::WARN => "attention",
            status::BROKEN => "problem",
            status::UNKNOWN => "unknown",
            _ => "",
        }
    }

    /// Hand the window everything it shows, from the state. Called after every change.
    fn render(&self) {
        let Some(ui) = self.ui() else { return };
        let st = self.st.borrow();
        let entries = self.entries(&st);
        let sel = Self::selected_index(&st, &entries);
        let first_read = st.snap.is_none();
        // ---- the bar ----
        ui.set_refreshing(st.reading);
        ui.set_finding(st.finding);
        ui.set_fix_running(st.fix_running.is_some());
        ui.set_portable(self.svc.mode.portable());
        ui.set_portable_tip(s(match &self.svc.mode {
            Mode::Installed => String::new(),
            Mode::Portable { .. } => format!("Portable: settings and the journal are kept beside the exe, in VibePrint-data. {PORTABLE_TRACE}"),
            Mode::ReadOnly { .. } => format!("Portable, read-only: settings and the journal are not kept. {PORTABLE_TRACE}"),
        }));
        // ---- the spooler line ----
        let spooler = st.snap.as_ref().map(|s| s.spooler.clone());
        let sl = spooler.as_ref().and_then(status::spooler_line);
        ui.set_spooler_line(s(sl.as_ref().map(|l| l.text.clone()).unwrap_or_default()));
        ui.set_spooler_fix(s(match &spooler {
            Some(Spooler::Stopped) => "Start spooler…",
            Some(Spooler::Disabled) => "Turn on and start…",
            Some(Spooler::Silent(_)) => "Restart spooler…",
            _ => "",
        }));
        // ---- the rows ----
        let mut rows: Vec<PrinterRow> = Vec::new();
        let mut last_group = None;
        for (i, e) in entries.iter().enumerate() {
            if last_group != Some(e.group) {
                let n = entries.iter().filter(|x| x.group == e.group).count();
                rows.push(PrinterRow { id: -1, header: true, name: s(format!("{} · {n}", e.group.title())), tag: s(""), port: s(""), line: s(""), state: 2, selected: false, a11y: s("") });
                last_group = Some(e.group);
            }
            let port = match (&e.address, e.kind) {
                (Address::None, k) => k.words().to_string(),
                (Address::Unknown(_), k) => format!("{} · address unknown", k.words()),
                (a, k) => format!("{} · {}", k.words(), clean_max(&Self::address_text(a, st.probes.get(&e.printer.name).and_then(|x| x.1.as_deref())), 60)),
            };
            let tag = if e.printer.default { "default" } else { "" };
            let a11y = [e.line.text.clone(), port.clone(), tag.to_string()].into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join(", ");
            rows.push(PrinterRow { id: i as i32, header: false, name: s(e.printer.display()), tag: s(tag), port: s(&port), line: s(&e.line.text), state: e.line.state, selected: sel == Some(i), a11y: s(a11y) });
        }
        // The selected row's top: the heights of the rows above it (titles 30, printers 52).
        let scroll_top = match sel.and_then(|i| rows.iter().position(|r| r.id == i as i32)) {
            Some(r) => rows[..r].iter().map(|x| if x.header { 30.0 } else { 52.0 }).sum::<f32>(),
            None => -1.0,
        };
        ui.set_rows(ModelRc::new(VecModel::from(rows)));
        ui.set_rows_empty(s(if first_read {
            "Reading the printers…"
        } else if matches!(st.snap.as_ref().map(|s| &s.list), Some(List::NoSpooler)) {
            "The printers cannot be listed while the Print Spooler is not running."
        } else if matches!(st.snap.as_ref().map(|s| &s.spooler), Some(Spooler::Silent(_))) {
            "The printers cannot be listed while the Print Spooler does not answer."
        } else if let Some(List::Failed(_)) = st.snap.as_ref().map(|s| &s.list) {
            "The printers could not be listed."
        } else {
            "No printers. Find searches the LAN; Add by IP adds one."
        }));
        ui.set_scroll_top(scroll_top);
        ui.set_scroll_seq(st.scroll_seq);
        // ---- the detail ----
        match sel.and_then(|i| entries.get(i)) {
            Some(e) => {
                let (d, pairs, jobs, _) = self.detail(&st, e, 200);
                ui.set_detail(d);
                ui.set_detail_pairs(ModelRc::new(VecModel::from(pairs)));
                ui.set_jobs(ModelRc::new(VecModel::from(jobs)));
                let fixes = self.fixes_for(&st, e);
                let busy = st.fix_running.is_some();
                let buttons: Vec<FixButton> = fixes.iter().enumerate().map(|(i, (k, t, admin))| FixButton { id: i as i32, text: s(t), admin: *admin, primary: i == 0 && e.line.fix.is_some() && !matches!(k, FixKind::TestPage), enabled: !busy }).collect();
                let (a, b): (Vec<FixButton>, Vec<FixButton>) = buttons.into_iter().partition(|x| x.id < 2);
                ui.set_fixes_a(ModelRc::new(VecModel::from(a)));
                ui.set_fixes_b(ModelRc::new(VecModel::from(b)));
            }
            None => {
                ui.set_detail(DetailInfo::default());
                ui.set_detail_pairs(ModelRc::default());
                ui.set_jobs(ModelRc::default());
                ui.set_fixes_a(ModelRc::default());
                ui.set_fixes_b(ModelRc::default());
            }
        }
        // ---- Find ----
        ui.set_find_open(st.find_open);
        let installed = self.installed(&st);
        let secs = st.find_started.map_or(0, |t| t.elapsed().as_secs());
        ui.set_find_status(s(match (&st.find, st.finding) {
            (_, true) => format!("Searching the LAN… {secs} s"),
            (Some(r), false) => {
                let n = r.found.len();
                let found = if n == 1 { "1 device found".to_string() } else { format!("{n} devices found") };
                format!("{found}{} · {}", if r.stopped { " (stopped early: partial)" } else { "" }, r.searched.join(" · "))
            }
            (None, false) => String::new(),
        }));
        let found_rows: Vec<FoundRow> = st
            .find
            .as_ref()
            .map(|r| {
                r.found
                    .iter()
                    .enumerate()
                    .map(|(i, f)| {
                        let m = find::match_found(f, &installed);
                        let words = find::match_words(f, &m, &installed);
                        let ip = f.ip.map(|x| x.to_string()).or(f.v6.first().map(|x| x.to_string())).unwrap_or_default();
                        let mut sub = Vec::new();
                        if let Some(m) = &f.model
                            && m != &f.title()
                        {
                            sub.push(m.clone());
                        }
                        if let Some(mac) = f.mac {
                            sub.push(match &f.maker {
                                Some(mk) => format!("{} ({mk})", crate::net::mac_text(&mac)),
                                None => crate::net::mac_text(&mac),
                            });
                        }
                        sub.push(f.answered_words());
                        let state = match m {
                            Match::Same(_) => status::OK,
                            Match::Moved(_) | Match::Maybe(_) | Match::NotIt(_) => status::WARN,
                            Match::None => status::QUIET,
                        };
                        let sub = sub.into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join(" · ");
                        FoundRow { id: i as i32, title: s(f.title()), sub: s(&sub), ip: s(&ip), verdict: s(&words), state, selected: st.found_selected == Some(i), a11y: s(format!("{ip}, {sub}, {words}")) }
                    })
                    .collect()
            })
            .unwrap_or_default();
        ui.set_found_note(s(st.found_selected.and_then(|i| found_rows.get(i)).map(|f| f.verdict.to_string()).unwrap_or_default()));
        ui.set_found(ModelRc::new(VecModel::from(found_rows)));
        let acts: Vec<FixButton> = self.found_actions(&st).into_iter().map(|(id, t, admin)| FixButton { id, text: s(t), admin, primary: id == 2, enabled: st.fix_running.is_none() }).collect();
        ui.set_found_actions(ModelRc::new(VecModel::from(acts)));
        // ---- Add by IP ----
        let ready = Self::add_ready(&st);
        let a = &st.add;
        let check = match (&a.answers, a.checking) {
            (_, true) => "Checking…".to_string(),
            (Some((ip, ans)), false) => {
                if ans.answers() {
                    let (words, _) = ans.state();
                    let model = ans.model().map(|m| format!("{} · ", clean_max(&m, 60))).unwrap_or_default();
                    format!("{model}{words} · {}", ans.ports_words())
                } else {
                    format!("No answer at {ip}.")
                }
            }
            (None, false) => String::new(),
        };
        ui.set_add_info(AddInfo {
            check: s(&check),
            drivers: ModelRc::new(VecModel::from(a.drivers.iter().map(|d| s(clean_max(d, 80))).collect::<Vec<_>>())),
            driver: a.driver.map_or(-1, |i| i as i32),
            no_driver: !a.drivers.is_empty() && a.driver.is_none() && a.answers.is_some(),
            problem: s(ready.as_ref().err().cloned().unwrap_or_default()),
            ready: ready.is_ok() && st.fix_running.is_none(),
            busy: st.fix_running.as_ref().is_some_and(|k| matches!(k, FixKind::AddByIp { .. })),
            protocol: s(match &ready {
                Ok(FixKind::AddByIp { protocol, snmp, .. }) => format!("{}{}", protocol.words(), if *snmp { ", SNMP check on" } else { "" }),
                _ => String::new(),
            }),
        });
        // ---- the journal ----
        let jrows: Vec<JournalRow> = st
            .journal
            .iter()
            .rev()
            .take(JOURNAL_SHOWN)
            .enumerate()
            .map(|(i, e)| {
                let state = match e.state.as_str() {
                    "done" => status::OK,
                    "pending" => status::CHECKING,
                    "failed" | "unknown" => status::BROKEN,
                    "declined" | "refused" => status::WARN,
                    _ => status::QUIET,
                };
                let what = journal::words(e);
                let when = self.date_time(e.at);
                // The file may have been edited by hand: everything from it is outside text.
                let (printer, st_word, note) = (clean_max(&e.printer, 80), clean_max(&e.state, 20), clean_max(&e.note, 300));
                JournalRow { id: i as i32, when: s(&when), what: s(&what), printer: s(&printer), state: s(&st_word), state_code: state, selected: st.journal_selected == Some(e.id), a11y: s(format!("{when}, {printer}, {st_word}, {note}")) }
            })
            .collect();
        ui.set_journal_rows(ModelRc::new(VecModel::from(jrows)));
        let undo = st.journal_selected.and_then(|id| st.journal.iter().find(|x| x.id == id)).map(|e| self.undo_of(&st, e));
        ui.set_journal_note(s(match &undo {
            Some(Ok(_)) => String::new(),
            Some(Err(why)) => format!("No undo: {why}."),
            None => if st.journal.is_empty() { "No fixes on this PC yet.".to_string() } else { String::new() },
        }));
        ui.set_journal_can_undo(matches!(undo, Some(Ok(_))) && st.fix_running.is_none());
        // ---- the status line ----
        let mut left = Vec::new();
        if self.svc.mode.portable() {
            left.push("Portable".to_string());
        }
        if let Some(k) = &st.fix_running {
            left.push(crate::fixes::running_words(k));
        } else if st.reading && first_read {
            left.push("Reading the printers…".into());
        } else {
            let n = entries.len();
            left.push(match st.snap.as_ref().map(|s| &s.list) {
                Some(List::NoSpooler) => "printers not listed".into(),
                Some(List::Failed(_)) => "printers not read".into(),
                _ if n == 1 => "1 printer".into(),
                _ => format!("{n} printers"),
            });
            if let Some(t) = st.read_at {
                left.push(format!("checked {}", self.clock(t)));
            }
            if let Some(sp) = &spooler {
                left.push(sp.short());
            }
            if st.probing {
                left.push("asking the network printers…".into());
            }
        }
        ui.set_status_left(s(left.join(" · ")));
        ui.set_status_right(s(""));
    }
}
