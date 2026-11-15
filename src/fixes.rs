//! The fixes (SPEC section 4): what each will do in words (the confirm dialog), and the run:
//! read again and refuse when what it was planned on changed (what was read is a plan, not a
//! fact), journal it as pending, do it (unelevated where a user may, else one named helper job),
//! journal what happened, and say in words what is now true.

use crate::controller::{FixKind, FixOutcome, System};
use crate::helper::{Job, JobResult, Outcome, Params, Protocol};
use crate::journal::{self, Entry, Journal};
use crate::ports::{Kind, Port};
use crate::printers::{List, Spooler};
use crate::probe::Answers;
use crate::queue::Job as QJob;
use crate::text::clean_max;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// The protocol a new TCP/IP port uses: RAW 9100 when 9100 answered, else LPR 515 (queue `lp`)
/// when 515 answered; the SNMP check only when SNMP answered. IPP alone: refused.
pub fn protocol_for(a: &Answers) -> Result<(Protocol, bool), String> {
    let snmp = a.snmp_answers();
    if a.open(9100) {
        Ok((Protocol::Raw, snmp))
    } else if a.open(515) {
        Ok((Protocol::Lpr, snmp))
    } else if a.open(631) {
        Err("The printer answers IPP only: Windows' Add printer can add it as an IPP printer.".into())
    } else {
        Err("Neither port 9100 nor 515 answers.".into())
    }
}

/// "2.0 GB", "48 KB", "512 bytes".
pub fn size_words(b: u64) -> String {
    const K: f64 = 1024.0;
    let f = b as f64;
    if f >= K * K * K {
        format!("{:.1} GB", f / (K * K * K))
    } else if f >= K * K {
        format!("{:.1} MB", f / (K * K))
    } else if f >= K {
        format!("{:.0} KB", f / K)
    } else {
        format!("{b} bytes")
    }
}

/// The status line while a fix runs.
pub fn running_words(k: &FixKind) -> String {
    let what = match k {
        FixKind::ClearQueue => "Clearing the queue",
        FixKind::RestartSpooler => "Restarting the Print Spooler",
        FixKind::UseOnline => "Setting it online",
        FixKind::SwitchToTcp { .. } => "Switching to a TCP/IP port",
        FixKind::PointAt { .. } => "Pointing the port at the new address",
        FixKind::SnmpOff => "Turning off the SNMP check",
        FixKind::TestPage => "Printing a test page",
        FixKind::AddByIp { .. } => "Adding the printer",
        FixKind::Undo { .. } => "Undoing",
        FixKind::Search => "Searching",
    };
    format!("{what}… (answer the administrator prompt if one comes)")
}

/// What the confirm dialog needs to say.
pub struct Context<'a> {
    pub name: &'a str,
    pub port: &'a Port,
    pub old_address: &'a str,
    pub jobs: &'a [QJob],
    pub spooler: &'a Spooler,
    /// Other printers on the same port (they move with it).
    pub sharing: &'a [String],
    pub entry: Option<&'a Entry>,
    /// A shared connection's server ("PC-EIER"); empty for a printer of this PC.
    pub server: &'a str,
}

/// The confirm dialog's words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Words {
    pub title: String,
    pub steps: Vec<String>,
    /// One administrator prompt (the shield).
    pub admin: bool,
    pub button: String,
    pub note: String,
}

fn quote(n: &str) -> String {
    format!("'{}'", clean_max(n, 80))
}

/// What a fix will do, step by step.
pub fn plan(kind: &FixKind, c: &Context) -> Words {
    let name = quote(c.name);
    let undo_note = "It is written to the Journal, where Undo can put it back while nothing else changed it.".to_string();
    match kind {
        FixKind::ClearQueue if !c.server.is_empty() => {
            // A shared printer: its queue lives on the PC that shares it (AUDIT-1 PRINT-9).
            let mine = c.jobs.iter().filter(|j| j.mine).count();
            let others = c.jobs.len() - mine;
            let mut steps = vec![format!("Delete your own {} (no administrator rights needed).", crate::text::count(mine, "job", "jobs"))];
            if others > 0 {
                steps.push(format!(
                    "The {} of other users stay{}: a shared printer's queue lives on the PC that shares it ({}), and they are cleared there.",
                    crate::text::count(others, "job", "jobs"),
                    if others == 1 { "s" } else { "" },
                    clean_max(c.server, 60)
                ));
            }
            Words { title: format!("Clear your jobs from {name}?"), steps, admin: false, button: "Clear my jobs".into(), note: "Deleted jobs are gone: they have to be printed again.".into() }
        }
        FixKind::ClearQueue => {
            let mine = c.jobs.iter().filter(|j| j.mine).count();
            let others = c.jobs.len() - mine;
            let mut steps = Vec::new();
            if mine > 0 {
                steps.push(format!("Delete your own {} (no administrator rights needed).", crate::text::count(mine, "job", "jobs")));
            }
            if others > 0 || mine == 0 {
                steps.push(format!(
                    "For the {} of other users, or any that will not go: the spooler's own purge (one administrator prompt).",
                    if others > 0 { crate::text::count(others, "job", "jobs") } else { "jobs".into() }
                ));
                steps.push("If jobs are still there after 10 s: stop the Print Spooler, delete only this printer's spool files, start it again. Shadow files of a layout VibePrint does not know are left and listed.".into());
            }
            Words { title: format!("Clear the queue of {name}?"), steps, admin: others > 0 || mine == 0, button: "Clear queue".into(), note: "Deleted jobs are gone: they have to be printed again.".into() }
        }
        FixKind::RestartSpooler => {
            let mut steps = Vec::new();
            if *c.spooler == Spooler::Disabled {
                steps.push("Its start type is Disabled: set it to Automatic first.".into());
            }
            // A spooler that does not answer is up, only hung (X15CON-3).
            let up = c.spooler.running() || matches!(c.spooler, Spooler::Silent(_));
            if up {
                steps.push("Stop the Print Spooler service (waiting up to 30 s), then start it again.".into());
            } else {
                steps.push("Start the Print Spooler service.".into());
            }
            Words { title: "Restart the Print Spooler?".into(), steps, admin: true, button: if up { "Restart".into() } else { "Start".into() }, note: "A job being printed starts over.".into() }
        }
        FixKind::UseOnline => Words {
            title: format!("Use {name} online?"),
            steps: vec!["Clear Windows' \"Use printer offline\" for it.".into(), "If Windows refuses that without administrator rights: one administrator prompt.".into()],
            admin: false,
            button: "Use online".into(),
            note: String::new(),
        },
        FixKind::SwitchToTcp { ip, protocol, snmp } => Words {
            title: format!("Switch {name} to a TCP/IP port?"),
            steps: vec![
                format!("Make a Standard TCP/IP port to {ip} ({}, SNMP check {}), named IP_{ip}; one that exists with the same address is reused as it is (its own protocol and SNMP check).", protocol.words(), if *snmp { "on" } else { "off" }),
                format!("Point {name} at it."),
                format!("Its WSD port {} is kept: Undo points the printer back at it.", clean_max(&c.port.name, 60)),
            ],
            admin: true,
            button: "Switch".into(),
            note: undo_note,
        },
        FixKind::PointAt { ip } => {
            let mut steps = vec![format!("Change the TCP/IP port {} from {} to {ip}; everything else about it stays.", clean_max(&c.port.name, 60), clean_max(c.old_address, 60))];
            if !c.sharing.is_empty() {
                steps.push(format!("{} use{} this port too: {} move{} with it.", c.sharing.iter().map(|s| quote(s)).collect::<Vec<_>>().join(", "), if c.sharing.len() == 1 { "s" } else { "" }, if c.sharing.len() == 1 { "it" } else { "they" }, if c.sharing.len() == 1 { "s" } else { "" }));
            }
            Words { title: format!("Point {name} at {ip}?"), steps, admin: true, button: "Point it there".into(), note: undo_note }
        }
        FixKind::SnmpOff => Words {
            title: format!("Turn off the SNMP check for {name}?"),
            steps: vec![
                format!("Turn off the SNMP status check on the port {}: Windows then stops calling the printer offline when SNMP does not answer.", clean_max(&c.port.name, 60)),
                "Everything else about the port stays.".into(),
            ],
            admin: true,
            button: "Turn it off".into(),
            note: undo_note,
        },
        FixKind::TestPage => Words {
            title: format!("Print a test page on {name}?"),
            steps: vec!["One page from this PC: the printer, its driver, port and address, this PC's name, the date and time, a 1 cm grid and the alphabet.".into()],
            admin: false,
            button: "Print".into(),
            note: String::new(),
        },
        FixKind::AddByIp { ip, name: new, driver, protocol, snmp } => Words {
            title: format!("Add {} at {ip}?", quote(&String::from_utf16_lossy(new))),
            steps: vec![
                format!("Make a Standard TCP/IP port to {ip} ({}, SNMP check {}), named IP_{ip}; one that exists with the same address is reused as it is (its own protocol and SNMP check).", protocol.words(), if *snmp { "on" } else { "off" }),
                format!("Add the printer with the driver {}.", quote(driver)),
            ],
            admin: true,
            button: "Add".into(),
            note: "Undo in the Journal deletes it again (only this printer, while it still uses that port). Drivers are never installed or deleted here.".into(),
        },
        FixKind::Undo { .. } => {
            let what = c.entry.map(journal::words).unwrap_or_default();
            Words { title: "Undo this fix?".into(), steps: vec![format!("Undo: {what}.")], admin: true, button: "Undo".into(), note: String::new() }
        }
        FixKind::Search => Words { title: String::new(), steps: Vec::new(), admin: false, button: String::new(), note: String::new() },
    }
}

/// What a confirmed fix was planned on.
pub struct Plan0<'a> {
    pub kind: &'a FixKind,
    pub printer: Option<&'a [u16]>,
    pub port: &'a str,
    pub old_address: &'a str,
    /// The identity of the device the printer is pointed at ("mac", "model", "uuid"): recorded
    /// with the fix, so the status can tell it from another device later (AUDIT-1 PRINT-3).
    pub device: &'a BTreeMap<String, String>,
}

/// Everything a run needs.
pub struct Run<'a> {
    pub sys: &'a dyn System,
    pub plan: &'a Plan0<'a>,
    pub hwnd: isize,
    pub stop: &'a AtomicBool,
    pub journal: Option<&'a journal::Store>,
    pub machine: &'a str,
    pub entries: &'a [Entry],
    pub now: i64,
    pub pc: &'a str,
    pub when: &'a str,
    /// The window shows a spooler that does not answer (`Spooler::Silent`).
    pub shown_silent: bool,
}

fn map(pairs: &[(&str, String)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}

/// Run a fix: the outcome in words, the journal as it now is (when it was written), whether
/// journal.json turned out garbled on the way (kept aside: the window says so), and the read
/// of what is now true (the window shows exactly that read: AUDIT-1 PRINT-13).
pub fn run(r: &Run) -> (FixOutcome, Option<Journal>, bool, crate::controller::Snapshot) {
    // Restarting a spooler that does not answer: no read first. The read that hung may still
    // hold the one-read guard, so it would wait out READ_LIMIT before the restart even began
    // (X15RFAMBC-2); a hung spooler is running, so there is nothing to turn on either.
    let mut fresh = if r.shown_silent && *r.plan.kind == FixKind::RestartSpooler {
        crate::controller::Snapshot::silent(crate::controller::READ_LIMIT)
    } else {
        r.sys.read()
    };
    // A spooler state that could not be read is "could not tell": once more (AUDIT-1 PRINT-6).
    if matches!(fresh.spooler, Spooler::Unknown(_)) {
        fresh = r.sys.read();
    }
    let (outcome, journal, garbled, after) = run_on(r, &fresh);
    (outcome, journal, garbled, after.unwrap_or(fresh))
}

/// Whether the helper takes `p` for `job` as the app would send it (never relaunch elevated
/// for a request it must refuse: AUDIT-1 PRINT-9).
pub fn helper_takes(job: Job, p: &Params) -> bool {
    crate::helper::parse_request(&crate::helper::request(job, &[0; 16], p)[5..], job).is_some()
}

fn run_on(r: &Run, fresh: &crate::controller::Snapshot) -> (FixOutcome, Option<Journal>, bool, Option<crate::controller::Snapshot>) {
    let kind = r.plan.kind;
    let name_units = r.plan.printer.map(<[u16]>::to_vec);
    let name = name_units.as_ref().map(|n| String::from_utf16_lossy(n)).unwrap_or_default();
    let shown = quote(&name);
    match &fresh.spooler {
        _ if *kind == FixKind::RestartSpooler => {}
        Spooler::Running => {}
        // Its state could not be read, but the printers were listed: the spooler is up.
        Spooler::Unknown(_) if matches!(fresh.list, List::Printers(_)) => {}
        Spooler::Unknown(why) => return (FixOutcome::NotDone(format!("Not done: the Print Spooler's state could not be read ({}). Try again.", clean_max(why, 120))), None, false, None),
        Spooler::Silent(_) => return (FixOutcome::NotDone("Not done: the Print Spooler does not answer. Restart it first.".into()), None, false, None),
        _ => return (FixOutcome::NotDone("Not done: the Print Spooler is not running.".into()), None, false, None),
    }
    let printers = match &fresh.list {
        List::Printers(v) => v.clone(),
        _ => Vec::new(),
    };
    let printer = name_units.as_ref().and_then(|n| printers.iter().find(|p| &p.name == n)).cloned();
    if name_units.is_some() && printer.is_none() && !matches!(kind, FixKind::Undo { .. }) {
        return (FixOutcome::NotDone(format!("Not done: {shown} is not there any more.")), None, false, None);
    }
    let port_now = |p: &str| fresh.ports.iter().find(|x| x.name.eq_ignore_ascii_case(p)).cloned();
    let changed = |why: String| (FixOutcome::NotDone(format!("Not done: {why} since it was read. Look again and try once more.")), None, false, None);
    // What was read is a plan: check it still holds.
    match kind {
        FixKind::UseOnline if !printer.as_ref().is_some_and(|p| p.work_offline()) => return changed(format!("{shown} is no longer set to use offline")),
        FixKind::SwitchToTcp { .. } => {
            let cur = printer.as_ref().map(|p| p.first_port().to_string()).unwrap_or_default();
            if !cur.eq_ignore_ascii_case(r.plan.port) {
                return changed(format!("its port changed (it is {cur} now)"));
            }
        }
        FixKind::PointAt { .. } | FixKind::SnmpOff => {
            let cur = printer.as_ref().map(|p| p.first_port().to_string()).unwrap_or_default();
            let t = port_now(&cur).and_then(|p| p.tcp);
            match (&t, kind) {
                (None, _) => return changed("its port is no longer a Standard TCP/IP port".into()),
                (Some(t), FixKind::PointAt { .. }) if t.target() != r.plan.old_address => return changed(format!("its port's address changed (it is {} now)", t.target())),
                (Some(t), FixKind::SnmpOff) if !t.snmp => return changed("its SNMP check was turned off".into()),
                _ => {}
            }
        }
        FixKind::AddByIp { ip, name: new, protocol, .. } => {
            if printers.iter().any(|p| crate::shd::same_printer(&p.name, new)) {
                return changed("a printer with that name was added".into());
            }
            let port = if *protocol == Protocol::Raw { 9100 } else { 515 };
            if r.sys.net().connect(SocketAddr::new(IpAddr::V4(*ip), port), crate::probe::CONNECT_WAIT) != crate::probe::PortState::Open {
                return (FixOutcome::NotDone(format!("Not added: {ip} stopped answering on port {port}.")), None, false, None);
            }
        }
        _ => {}
    }
    // Undo: still what the fix set?
    let undo = match kind {
        FixKind::Undo { entry } => {
            let Some(e) = r.entries.iter().find(|x| x.id == *entry) else { return (FixOutcome::NotDone("No undo: the entry is not in the journal any more.".into()), None, false, None) };
            let port_of = |n: &str| printers.iter().find(|p| p.name_string() == n).map(|p| p.first_port().to_string());
            let tcp_of = |p: &str| port_now(p).and_then(|x| x.tcp).map(|t| (t.target().to_string(), t.snmp, t.community.clone()));
            let exists = |p: &str| port_now(p).is_some() || p.to_ascii_uppercase().starts_with("WSD-");
            match journal::undo(e, r.entries, &journal::Now { port_of: &port_of, tcp_of: &tcp_of, port_exists: &exists }) {
                Ok(u) => Some((e.clone(), u)),
                Err(why) => return (FixOutcome::NotDone(format!("No undo: {why}.")), None, false, None),
            }
        }
        _ => None,
    };
    // The journal: pending first.
    let fix_name = match (kind, &undo) {
        (_, Some((_, journal::Undo::PortSet { .. }))) => "port-set",
        (_, Some((_, journal::Undo::PortAddress { .. }))) => "port-address",
        (_, Some((_, journal::Undo::Snmp { on: true, .. }))) => "port-snmp-on",
        (_, Some((_, journal::Undo::Snmp { on: false, .. }))) => "port-snmp-off",
        (_, Some((_, journal::Undo::Delete { .. }))) => "printer-delete",
        (FixKind::ClearQueue, _) => "queue-clear",
        (FixKind::RestartSpooler, _) => "spooler-restart",
        (FixKind::UseOnline, _) => "printer-online",
        (FixKind::SwitchToTcp { .. }, _) => "port-to-tcp",
        (FixKind::PointAt { .. }, _) => "port-address",
        (FixKind::SnmpOff, _) => "port-snmp-off",
        (FixKind::TestPage, _) => "test-page",
        (FixKind::AddByIp { .. }, _) => "printer-add",
        _ => "other",
    };
    let cur_port = printer.as_ref().map(|p| p.first_port().to_string()).unwrap_or_default();
    let (old, new) = match (kind, &undo) {
        (_, Some((e, u))) => match u {
            journal::Undo::PortSet { port, .. } => (map(&[("port", e.new.get("port").cloned().unwrap_or_default())]), map(&[("port", port.clone())])),
            journal::Undo::PortAddress { port, address } => (map(&[("address", e.new.get("address").cloned().unwrap_or_default())]), map(&[("port", port.clone()), ("address", address.clone())])),
            journal::Undo::Snmp { port, .. } => (BTreeMap::new(), map(&[("port", port.clone())])),
            journal::Undo::Delete { printer, port } => (map(&[("name", printer.clone()), ("port", port.clone())]), BTreeMap::new()),
        },
        (FixKind::SwitchToTcp { ip, protocol, snmp }, _) => (map(&[("port", cur_port.clone())]), map(&[("address", ip.to_string()), ("protocol", protocol.word().into()), ("snmp", snmp.to_string())])),
        (FixKind::PointAt { ip }, _) => (map(&[("address", r.plan.old_address.to_string())]), map(&[("port", cur_port.clone()), ("address", ip.to_string())])),
        // The community is recorded: Undo puts exactly it back (AUDIT-1 PRINT-12).
        (FixKind::SnmpOff, _) => (
            map(&[("snmp", "on".into()), ("community", port_now(&cur_port).and_then(|p| p.tcp).map(|t| t.community).unwrap_or_default())]),
            map(&[("port", cur_port.clone())]),
        ),
        (FixKind::AddByIp { ip, name: n, driver, .. }, _) => (BTreeMap::new(), map(&[("name", String::from_utf16_lossy(n)), ("address", ip.to_string()), ("driver", driver.clone())])),
        (FixKind::UseOnline, _) => (map(&[("offline", "on".into())]), map(&[("offline", "off".into())])),
        _ => (BTreeMap::new(), BTreeMap::new()),
    };
    let id = journal::next_id(r.entries, (r.now.max(0) as u64) * 1000);
    let mut entry = Entry {
        id,
        at: r.now,
        fix: fix_name.into(),
        printer: match (&undo, kind) {
            (Some((e, _)), _) => e.printer.clone(),
            (_, FixKind::AddByIp { name: n, .. }) => String::from_utf16_lossy(n),
            _ => name.clone(),
        },
        old,
        new,
        state: "pending".into(),
        note: String::new(),
        undoes: undo.as_ref().map(|(e, _)| e.id),
    };
    let write = |e: Entry| {
        if let Some(j) = r.journal {
            let pc = r.machine.to_string();
            j.change(Arc::new(move |jj: &mut Journal| jj.put(&pc, e.clone())));
        }
    };
    write(entry.clone());
    // Do it.
    let helper = |job: Job, p: Params| {
        if !helper_takes(job, &p) {
            return Outcome::Failed("the helper would refuse that request, so it was not started".into());
        }
        r.sys.job(job, &p, r.hwnd, r.stop)
    };
    let pname = || name_units.clone();
    // The journal's word when the step answered: a clear that left jobs is not done (FEC4).
    let mut state_when_ok = "done";
    let outcome: Result<String, Outcome> = match kind {
        FixKind::TestPage => {
            let p = printer.clone().unwrap();
            let port = port_now(p.first_port());
            let kind = crate::ports::classify(p.first_port(), port.as_ref().map(|x| x.monitor.as_str()).unwrap_or(""), &p.driver);
            let address = port.as_ref().map(|x| crate::ports::address(kind, x)).map(|a| match a {
                crate::ports::Address::Ip(ip) => ip.to_string(),
                crate::ports::Address::Host(h) => h,
                _ => String::new(),
            });
            let lines = crate::testpage::lines(&p.display(), &p.driver, p.first_port(), &address.unwrap_or_default(), r.pc, r.when);
            match r.sys.test_page(&p.name, &lines) {
                Ok(()) => Ok(format!("The test page went to {shown}: check that it came out and that its squares are 1 cm.")),
                Err(e) => Err(Outcome::Failed(e)),
            }
        }
        FixKind::UseOnline => match r.sys.set_online(name_units.as_ref().unwrap()) {
            Ok(()) => Ok(String::new()),
            Err(_) => match helper(Job::PrinterOnline, Params { printer: pname(), ..Params::default() }) {
                Outcome::Done(_) => Ok(String::new()),
                o => Err(o),
            },
        },
        FixKind::ClearQueue => {
            let n = name_units.clone().unwrap();
            let jobs: Vec<QJob> = fresh.queues.get(&n).and_then(|q| q.as_ref().ok()).cloned().unwrap_or_default();
            let mut deleted = 0;
            for j in jobs.iter().filter(|j| j.mine) {
                if r.sys.delete_job(&n, j.id).is_ok() {
                    deleted += 1;
                }
            }
            let left = match &r.sys.read().queues.get(&n) {
                Some(Ok(v)) => v.len(),
                _ => jobs.len() - deleted,
            };
            entry.new = map(&[("deleted", deleted.to_string())]);
            if left == 0 {
                Ok(format!("The queue of {shown} is empty ({} of your own deleted).", deleted))
            } else if let Some(p) = printer.as_ref().filter(|p| p.connection) {
                // A shared printer's queue lives on the PC that shares it: other users' jobs are
                // cleared there, never by the helper here (AUDIT-1 PRINT-9).
                let server = clean_max(p.server.trim_start_matches('\\'), 60);
                if deleted == 0 && jobs.iter().any(|j| j.mine) {
                    Err(Outcome::Failed("your own jobs could not be deleted".into()))
                } else {
                    Ok(format!(
                        "{} of your own deleted from {shown}; {} of other users {} still there: they are cleared on the PC that shares it ({server}), where its queue lives.",
                        deleted,
                        crate::text::count(left, "job", "jobs"),
                        if left == 1 { "is" } else { "are" }
                    ))
                }
            } else {
                match helper(Job::QueueClear, Params { printer: pname(), ..Params::default() }) {
                    Outcome::Done(res) => {
                        entry.new.insert("removed".into(), res.removed_count.to_string());
                        entry.new.insert("left".into(), res.left_count.to_string());
                        state_when_ok = clear_state(&res);
                        Ok(clear_words(&shown, &res))
                    }
                    o => Err(o),
                }
            }
        }
        FixKind::RestartSpooler => {
            let enable = fresh.spooler == Spooler::Disabled;
            match helper(Job::SpoolerRestart, Params { enable: Some(enable), ..Params::default() }) {
                Outcome::Done(res) => Ok(format!("{}{}", if res.enabled { "The Print Spooler was turned on (Automatic) and started." } else { "The Print Spooler was restarted." }, dependents_words(&res))),
                o => Err(o),
            }
        }
        FixKind::SwitchToTcp { ip, protocol, snmp } => match helper(Job::PortToTcp, Params { printer: pname(), port: Some(cur_port.clone()), ipv4: Some(*ip), protocol: Some(*protocol), snmp: Some(*snmp), ..Params::default() }) {
            Outcome::Done(res) => {
                entry.new.insert("port".into(), res.port.clone().unwrap_or_default());
                let how = port_words(&res, *protocol, *snmp, &mut entry.new);
                Ok(format!("{shown} now prints to {} ({ip}, {how}). Its WSD port is kept; Undo is in the Journal.", clean_max(&res.port.unwrap_or_default(), 63)))
            }
            o => Err(o),
        },
        FixKind::PointAt { ip } => match helper(Job::PortAddress, Params { port: Some(cur_port.clone()), ipv4: Some(*ip), ..Params::default() }) {
            Outcome::Done(_) => Ok(format!("The port {cur_port} now sends to {ip}. Undo is in the Journal.")),
            o => Err(o),
        },
        FixKind::SnmpOff => match helper(Job::PortSnmpOff, Params { port: Some(cur_port.clone()), ..Params::default() }) {
            Outcome::Done(_) => Ok(format!("The SNMP check is off for {cur_port}. Undo is in the Journal.")),
            o => Err(o),
        },
        FixKind::AddByIp { ip, name: n, driver, protocol, snmp } => match helper(Job::PrinterAdd, Params { ipv4: Some(*ip), protocol: Some(*protocol), snmp: Some(*snmp), driver: Some(driver.clone()), name: Some(n.clone()), ..Params::default() }) {
            Outcome::Done(res) => {
                entry.new.insert("port".into(), res.port.clone().unwrap_or_default());
                let how = port_words(&res, *protocol, *snmp, &mut entry.new);
                Ok(format!("{} was added at {ip} ({}, {how}). Undo is in the Journal.", quote(&String::from_utf16_lossy(n)), clean_max(&res.port.unwrap_or_default(), 63)))
            }
            o => Err(o),
        },
        FixKind::Undo { .. } => {
            let (_, u) = undo.clone().unwrap();
            let o = match &u {
                journal::Undo::PortSet { printer, port } => helper(Job::PortSet, Params { printer: Some(printer.encode_utf16().collect()), port: Some(port.clone()), ..Params::default() }),
                journal::Undo::PortAddress { port, address } => match crate::helper::valid_ipv4(address) {
                    Some(ip) => helper(Job::PortAddress, Params { port: Some(port.clone()), ipv4: Some(ip), ..Params::default() }),
                    None => Outcome::Failed(format!("the old address {address} is not one the port can take")),
                },
                journal::Undo::Snmp { port, on: false, .. } => helper(Job::PortSnmpOff, Params { port: Some(port.clone()), ..Params::default() }),
                // The community `journal::undo` chose and checked (AUDIT-1 R-PRINT-7).
                journal::Undo::Snmp { port, on: true, community } => helper(Job::PortSnmpOn, Params { port: Some(port.clone()), community: Some(community.clone()), ..Params::default() }),
                journal::Undo::Delete { printer, port } => helper(Job::PrinterDelete, Params { printer: Some(printer.encode_utf16().collect()), port: Some(port.clone()), ..Params::default() }),
            };
            match o {
                Outcome::Done(_) => Ok("Undone.".into()),
                o => Err(o),
            }
        }
        FixKind::Search => Ok(String::new()),
    };
    // What is now true: read again.
    let after = r.sys.read();
    let words = match outcome {
        Ok(w) => {
            entry.state = state_when_ok.into();
            if matches!(kind, FixKind::SwitchToTcp { .. } | FixKind::PointAt { .. } | FixKind::AddByIp { .. }) {
                for (k, v) in r.plan.device {
                    entry.new.entry(k.clone()).or_insert_with(|| clean_max(v, 120));
                }
            }
            let w = if w.is_empty() { now_true(kind, name_units.as_deref(), &after) } else { w };
            entry.note = clean_max(&w, 300);
            match state_when_ok {
                "done" => FixOutcome::Done(w),
                "unknown" => FixOutcome::Unknown(w),
                _ => FixOutcome::NotDone(w),
            }
        }
        Err(o) => {
            let (state, w) = outcome_words(kind, &o);
            entry.state = state.into();
            entry.note = clean_max(&w, 300);
            if state == "unknown" { FixOutcome::Unknown(w) } else { FixOutcome::NotDone(w) }
        }
    };
    write(entry.clone());
    // An undo that was done marks what it undid.
    if entry.state == "done"
        && let Some((mut orig, _)) = undo
    {
        orig.state = "undone".into();
        write(orig);
    }
    let garbled = r.journal.is_some_and(|j| j.take_garbled());
    (words, r.journal.map(|j| j.load()), garbled, Some(after))
}

/// How the printer now prints, from what the helper did: the planned protocol and SNMP check on
/// a new port, a reused port's own (AUDIT-1 PRINT-8). The journal gets the same.
fn port_words(res: &JobResult, protocol: Protocol, snmp: bool, journal: &mut BTreeMap<String, String>) -> String {
    let (how, check) = match (res.reused, &res.reused_protocol) {
        (true, Some(p)) => (clean_max(p, 60), res.reused_snmp),
        (true, None) => ("its own settings, not read".to_string(), None),
        (false, _) => (protocol.words().to_string(), Some(snmp)),
    };
    journal.insert("protocol".into(), if res.reused { how.clone() } else { protocol.word().to_string() });
    journal.insert("snmp".into(), check.map_or("unknown".into(), |c| c.to_string()));
    let check = match check {
        Some(true) => ", SNMP check on",
        Some(false) => ", SNMP check off",
        None => "",
    };
    if res.reused { format!("{how}{check}: a port that was there already, kept as it was") } else { format!("{how}{check}") }
}

/// The words for a fix that did not end in Done: (journal state, words).
pub fn outcome_words(kind: &FixKind, o: &Outcome) -> (&'static str, String) {
    let what = running_words(kind);
    let what = what.split('…').next().unwrap_or("");
    match o {
        Outcome::Declined => ("declined", "Not done: administrator rights were declined.".into()),
        Outcome::Refused(r) => ("refused", format!("Not done: {}.", r.words())),
        Outcome::Failed(e) => ("failed", format!("{what} failed: {}.", clean_max(e, 200))),
        // What it did before the error is said too (AUDIT-1 R-PRINT-6).
        Outcome::FailedAfter(e, r) => {
            let removed = if r.removed_count > 0 { format!(" {} of its spool files had been deleted.", r.removed_count) } else { String::new() };
            ("failed", format!("{what} failed: {}.{removed}{}", clean_max(e, 200), dependents_words(r)))
        }
        Outcome::NeverConnected(e) => ("failed", format!("{what} failed: {}. If Windows asked for another account's password, run VibePrint in an administrator's session.", clean_max(e, 200))),
        Outcome::Gone => ("unknown", format!("{what}: the helper ended before it was done, so what it did is not known. The list is read again: check it, and Restart spooler if it is stopped.")),
        Outcome::Stopped => ("unknown", format!("{what}: stopped as VibePrint closed.")),
        Outcome::Done(_) => ("done", String::new()),
    }
}

/// Names as a list in words, with "and N more" past those listed (the helper sends the first
/// `NAMES` and the whole count).
fn names_words(names: &[String], count: u32, max: usize) -> String {
    let mut s = names.iter().take(4).map(|x| clean_max(x, max)).collect::<Vec<_>>().join(", ");
    let more = (count as usize).saturating_sub(names.len().min(4));
    if more > 0 {
        s.push_str(&format!(" and {more} more"));
    }
    s
}

/// The services that depend on the spooler, as a restart left them.
fn dependents_words(r: &JobResult) -> String {
    let mut s = String::new();
    if !r.restarted.is_empty() {
        s.push_str(&format!(" {} (which depend{} on it) {} started again.", names_words(&r.restarted, r.restarted.len() as u32, 40), if r.restarted.len() == 1 { "s" } else { "" }, if r.restarted.len() == 1 { "was" } else { "were" }));
    }
    if !r.not_restarted.is_empty() {
        s.push_str(&format!(" {} (which depend{} on it) did not start again: start {} in Services.", names_words(&r.not_restarted, r.not_restarted.len() as u32, 40), if r.not_restarted.len() == 1 { "s" } else { "" }, if r.not_restarted.len() == 1 { "it" } else { "them" }));
    }
    s
}

/// queue-clear's result in words. "Cleared" only when no job is left (FEC4): jobs still there
/// is "could not be cleared", a queue not read after is "not known".
pub fn clear_words(shown: &str, r: &JobResult) -> String {
    let removed = r.removed_count;
    let mut s = match (r.remaining, r.stopped) {
        (Some(0), true) => format!("The queue of {shown} was cleared: the spooler was stopped and {removed} of its spool files deleted."),
        (Some(0), false) => format!("The queue of {shown} was cleared."),
        (Some(n), stopped) => {
            let mut s = format!("The queue of {shown} could not be cleared: {} still there.", crate::text::count(n as usize, "job is", "jobs are"));
            if stopped {
                s.push_str(&format!(" The spooler was stopped and {removed} of its spool files deleted."));
            }
            s
        }
        (None, true) => format!("The spooler was stopped and {removed} spool files of {shown} deleted, but its queue could not be read after, so whether it is clear is not known: look at it again."),
        (None, false) => format!("The queue of {shown} could not be read after, so whether it is clear is not known: look at it again."),
    };
    if let Some(e) = r.spool_unread {
        s.push_str(&format!(" The spool folder could not be read ({}).", crate::helper::code_words(e)));
    }
    if r.left_count > 0 {
        s.push_str(&format!(" Left alone (not this printer's for sure): {}.", names_words(&r.left, r.left_count, 60)));
    }
    s.push_str(&dependents_words(r));
    s
}

/// The journal's word for a clear the helper finished: done only when no job is left (FEC4).
fn clear_state(r: &JobResult) -> &'static str {
    match r.remaining {
        Some(0) => "done",
        Some(_) => "failed",
        None => "unknown",
    }
}

/// What is true after a fix, from the read after it.
fn now_true(kind: &FixKind, printer: Option<&[u16]>, after: &crate::controller::Snapshot) -> String {
    let p = match (&after.list, printer) {
        (List::Printers(v), Some(n)) => v.iter().find(|p| p.name == n),
        _ => None,
    };
    match (kind, p) {
        (FixKind::UseOnline, Some(p)) if !p.work_offline() => format!("{} is no longer set to use offline.", quote(&p.display())),
        (FixKind::UseOnline, Some(p)) => format!("Done, but Windows still has {} set to use offline.", quote(&p.display())),
        _ => "Done.".into(),
    }
}

/// The port a printer would be switched to (for words before the run).
pub fn kind_words(k: Kind) -> &'static str {
    k.words()
}

/// An IPv4 address of a Find match (for a fix).
pub fn v4(ip: Option<IpAddr>) -> Option<Ipv4Addr> {
    match ip {
        Some(IpAddr::V4(a)) => Some(a),
        _ => None,
    }
}
