//! The journal (`journal.json`, SPEC section 4): every fix with its old and new values, written
//! before it runs ("pending") and after ("done", "failed", ...), per PC by its MachineGuid (a
//! portable stick's journal holds several PCs; each sees its own). It follows the state-file
//! rules through `prefs::Store`: an unreadable file is never written over (the changes wait in
//! memory), a garbled one is kept aside as `journal.json.broken` and told, every write reads the
//! file afresh and puts this window's changes onto it, whole or not at all.
//!
//! Undo is offered only while what the fix set is still what Windows has (checked against the
//! newest read, and again by the helper). Driver installs and deletes are never done.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The most entries kept per PC (the oldest go).
pub const KEEP: usize = 500;

/// One fix.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Entry {
    /// Unique within this PC's entries (unix milliseconds, bumped on a clash).
    pub id: u64,
    /// Unix seconds.
    pub at: i64,
    /// The job's name ("port-to-tcp", ...), or "jobs-delete" and "test-page" for the
    /// unelevated ones.
    pub fix: String,
    /// The printer's name (empty for the spooler).
    pub printer: String,
    /// What was there before, and what the fix set ("port", "address", "snmp", "name").
    pub old: BTreeMap<String, String>,
    pub new: BTreeMap<String, String>,
    /// "pending", "done", "failed", "declined", "refused", "unknown" (the helper went away),
    /// "undone".
    pub state: String,
    /// The outcome in words.
    pub note: String,
    /// For an undo: the entry it undid.
    pub undoes: Option<u64>,
}

/// The file: each PC's entries under its MachineGuid.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Journal {
    pub pcs: BTreeMap<String, Vec<Entry>>,
}

impl Journal {
    pub fn of(&self, pc: &str) -> Vec<Entry> {
        self.pcs.get(pc).cloned().unwrap_or_default()
    }

    /// Add or replace (by id) one entry of `pc`'s; at most `KEEP` stay.
    pub fn put(&mut self, pc: &str, e: Entry) {
        let v = self.pcs.entry(pc.to_string()).or_default();
        match v.iter_mut().find(|x| x.id == e.id) {
            Some(x) => *x = e,
            None => v.push(e),
        }
        if v.len() > KEEP {
            let n = v.len() - KEEP;
            v.drain(..n);
        }
    }

    /// Room for about `over` more bytes of the written file (RIB-1): the oldest entries of the
    /// other PCs go first (by time, then id), never one of `me`'s, so this PC's pending fixes
    /// and Undo history stay. How many went; 0 when no other PC has any left.
    pub fn make_room(&mut self, me: &str, over: usize) -> usize {
        let mut others: Vec<(i64, u64, &str, usize)> = Vec::new();
        for (pc, v) in self.pcs.iter().filter(|(pc, _)| pc.as_str() != me) {
            for e in v {
                // Its size as written: pretty, three levels in, and the comma after it.
                let b = serde_json::to_vec_pretty(e).unwrap_or_default();
                let lines = b.iter().filter(|&&c| c == b'\n').count() + 1;
                others.push((e.at, e.id, pc.as_str(), b.len() + 6 * lines + 2));
            }
        }
        others.sort_unstable();
        let mut gone: BTreeMap<String, std::collections::BTreeSet<u64>> = BTreeMap::new();
        let mut freed = 0;
        let mut n = 0;
        for (_, id, pc, size) in others {
            if freed >= over {
                break;
            }
            gone.entry(pc.to_string()).or_default().insert(id);
            freed += size;
            n += 1;
        }
        for (pc, ids) in gone {
            if let Some(v) = self.pcs.get_mut(&pc) {
                v.retain(|e| !ids.contains(&e.id));
                if v.is_empty() {
                    self.pcs.remove(&pc);
                }
            }
        }
        n
    }
}

/// The journal file's store.
pub type Store = crate::prefs::Store<Journal>;

/// The journal file's store for this PC (`me`, its MachineGuid): a write that would pass
/// `prefs::MAX_FILE` drops the oldest entries of other PCs first (`Journal::make_room`), so the
/// app never writes a journal it would then call garbled (RIB-1).
pub fn open(path: std::path::PathBuf, me: &str) -> Store {
    let me = me.to_string();
    Store::new(path).with_fit(std::sync::Arc::new(move |j: &mut Journal, over| j.make_room(&me, over)))
}

/// The toast when a write made room (RIB-1).
pub fn trimmed_words(n: usize) -> String {
    format!("journal.json was getting too large to read back: removed the oldest {} of other PCs. This PC's fixes are all kept.", crate::text::count(n, "entry", "entries"))
}

/// A new entry's id: unix milliseconds, past every id `pc` has.
pub fn next_id(existing: &[Entry], now_ms: u64) -> u64 {
    existing.iter().map(|e| e.id + 1).max().unwrap_or(0).max(now_ms)
}

/// A TCP/IP port as the undo check needs it: (address, SNMP check on, community).
pub type TcpNow = (String, bool, String);

/// What Windows has now, as the undo check needs it.
pub struct Now<'a> {
    /// The printer's current port, if it exists.
    pub port_of: &'a dyn Fn(&str) -> Option<String>,
    /// A TCP/IP port's current address, SNMP check and community, if it exists.
    pub tcp_of: &'a dyn Fn(&str) -> Option<TcpNow>,
    /// A port exists.
    pub port_exists: &'a dyn Fn(&str) -> bool,
}

/// How to undo an entry: the job and its parameters' values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Undo {
    /// port-set: point `printer` back at `port`.
    PortSet { printer: String, port: String },
    /// port-address: `port` back to `address`.
    PortAddress { port: String, address: String },
    /// port-snmp-on / -off; turning it on puts back the community recorded when it was turned
    /// off (an entry from before that was recorded: what the port kept, else `public`), one the
    /// helper takes.
    Snmp { port: String, on: bool, community: String },
    /// printer-delete: the printer this app added, while it still uses `port`.
    Delete { printer: String, port: String },
}

/// Whether `e` can be undone now, and how; or why not, in words.
pub fn undo(e: &Entry, all: &[Entry], now: &Now) -> Result<Undo, String> {
    if e.state != "done" {
        return Err("only a fix that was done can be undone".into());
    }
    if all.iter().any(|x| x.undoes == Some(e.id) && x.state == "done") {
        return Err("it was undone already".into());
    }
    let new = |k: &str| e.new.get(k).cloned().unwrap_or_default();
    let old = |k: &str| e.old.get(k).cloned().unwrap_or_default();
    match e.fix.as_str() {
        "port-to-tcp" => {
            let cur = (now.port_of)(&e.printer).ok_or("the printer is not there any more")?;
            if !cur.eq_ignore_ascii_case(&new("port")) {
                return Err(format!("the printer no longer uses {} (it uses {cur} now)", new("port")));
            }
            if !(now.port_exists)(&old("port")) {
                return Err(format!("its old port {} is not there any more", old("port")));
            }
            Ok(Undo::PortSet { printer: e.printer.clone(), port: old("port") })
        }
        "port-address" => {
            let (addr, _, _) = (now.tcp_of)(&new("port")).ok_or("the port is not there any more")?;
            if addr != new("address") {
                return Err(format!("the port points at {addr} now, not {}", new("address")));
            }
            Ok(Undo::PortAddress { port: new("port"), address: old("address") })
        }
        "port-snmp-off" | "port-snmp-on" => {
            let on = e.fix == "port-snmp-on";
            let (_, snmp, kept) = (now.tcp_of)(&new("port")).ok_or("the port is not there any more")?;
            if snmp != on {
                return Err("the port's SNMP check was changed since".into());
            }
            if on {
                return Ok(Undo::Snmp { port: new("port"), on: false, community: String::new() });
            }
            // Turning it back on: never offered for a community the helper would refuse
            // (AUDIT-1 R-PRINT-7: a vendor tool can set one longer or not ASCII).
            let community = [old("community"), kept, "public".into()].into_iter().find(|c| !c.is_empty()).unwrap_or_default();
            if !crate::helper::valid_community(&community) {
                return Err(format!("its SNMP community ('{}') is not one VibePrint can set (1 to 32 plain characters): turn the check on in the port's settings", crate::text::clean_max(&community, 40)));
            }
            Ok(Undo::Snmp { port: new("port"), on: true, community })
        }
        "printer-add" => {
            let cur = (now.port_of)(&new("name")).ok_or("the printer is not there any more")?;
            if !cur.eq_ignore_ascii_case(&new("port")) {
                return Err(format!("the printer uses {cur} now, not the port it was added with"));
            }
            Ok(Undo::Delete { printer: new("name"), port: new("port") })
        }
        _ => Err("this fix has no undo".into()),
    }
}

/// An entry in words for the journal list: "Switched to TCP/IP (IP_192.168.1.142)".
pub fn words(e: &Entry) -> String {
    let new = |k: &str| e.new.get(k).cloned().unwrap_or_default();
    let old = |k: &str| e.old.get(k).cloned().unwrap_or_default();
    let what = match e.fix.as_str() {
        "port-to-tcp" => format!("Switched to a TCP/IP port ({} → {})", old("port"), new("port")),
        "port-set" => format!("Pointed back at {}", new("port")),
        "port-address" => format!("Pointed {} at {} (was {})", new("port"), new("address"), old("address")),
        "port-snmp-off" => format!("Turned the SNMP check off on {}", new("port")),
        "port-snmp-on" => format!("Turned the SNMP check on on {}", new("port")),
        "printer-add" => format!("Added '{}' at {} ({})", new("name"), new("address"), new("port")),
        "printer-delete" => format!("Deleted '{}'", old("name")),
        "printer-online" => "Use online".to_string(),
        "queue-clear" => "Cleared the queue".to_string(),
        "jobs-delete" => format!("Deleted {} of your own jobs", new("count")),
        "spooler-restart" => "Restarted the Print Spooler".to_string(),
        "test-page" => "Printed a test page".to_string(),
        f => f.to_string(),
    };
    crate::text::clean_max(&what, 200)
}
