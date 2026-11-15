//! A printer's queue (`EnumJobsW` level 2) and when a job is stuck. Pure: the tracker is fed
//! each read with the time it was made, so tests drive the clock.
//!
//! A job is stuck when it has an error or blocked status (or has been "deleting" for 2 minutes),
//! or when it is the first job and nothing about it has moved (pages printed, its size, its
//! status) for 2 minutes while the printer is not paused. Bytes printed are not in `JOB_INFO_2`
//! (only the change notification's `JOB_NOTIFY_FIELD_BYTES_PRINTED` has them), so v1 counts pages,
//! size and status as progress (DECISIONS.md).

use std::collections::HashMap;

pub const JOB_STATUS_PAUSED: u32 = 0x1;
pub const JOB_STATUS_ERROR: u32 = 0x2;
pub const JOB_STATUS_DELETING: u32 = 0x4;
pub const JOB_STATUS_SPOOLING: u32 = 0x8;
pub const JOB_STATUS_PRINTING: u32 = 0x10;
pub const JOB_STATUS_OFFLINE: u32 = 0x20;
pub const JOB_STATUS_PAPEROUT: u32 = 0x40;
pub const JOB_STATUS_PRINTED: u32 = 0x80;
pub const JOB_STATUS_DELETED: u32 = 0x100;
pub const JOB_STATUS_BLOCKED_DEVQ: u32 = 0x200;
pub const JOB_STATUS_USER_INTERVENTION: u32 = 0x400;
pub const JOB_STATUS_RESTART: u32 = 0x800;
pub const JOB_STATUS_COMPLETE: u32 = 0x1000;
pub const JOB_STATUS_RETAINED: u32 = 0x2000;

/// How long nothing may move before the first job counts as stuck.
pub const STUCK_AFTER_S: i64 = 120;

/// One job as the window shows it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Job {
    pub id: u32,
    pub document: String,
    pub owner: String,
    pub machine: String,
    pub pages_printed: u32,
    pub total_pages: u32,
    pub size: u64,
    pub status: u32,
    /// The driver's or port monitor's own status text (pStatus), if any.
    pub status_text: String,
    /// Unix seconds (UTC).
    pub submitted: i64,
    pub position: u32,
    /// The job belongs to the user running VibePrint (it can be deleted without admin rights).
    pub mine: bool,
}

/// The status bits in words, the serious ones first ("Error, Paper out").
pub fn status_words(s: u32, text: &str) -> String {
    let mut w: Vec<&str> = Vec::new();
    for (bit, word) in [
        (JOB_STATUS_ERROR, "Error"),
        (JOB_STATUS_BLOCKED_DEVQ, "Blocked"),
        (JOB_STATUS_USER_INTERVENTION, "Needs attention"),
        (JOB_STATUS_PAPEROUT, "Out of paper"),
        (JOB_STATUS_OFFLINE, "Offline"),
        (JOB_STATUS_DELETING, "Deleting"),
        (JOB_STATUS_PAUSED, "Paused"),
        (JOB_STATUS_RESTART, "Restarting"),
        (JOB_STATUS_SPOOLING, "Spooling"),
        (JOB_STATUS_PRINTING, "Printing"),
        (JOB_STATUS_PRINTED, "Printed"),
        (JOB_STATUS_DELETED, "Deleted"),
        (JOB_STATUS_COMPLETE, "Sent to the printer"),
        (JOB_STATUS_RETAINED, "Kept"),
    ] {
        if s & bit != 0 {
            w.push(word);
        }
    }
    let t = crate::text::clean_max(text, 80);
    let mut out = w.join(", ");
    if !t.is_empty() && !out.to_lowercase().contains(&t.to_lowercase()) {
        if out.is_empty() {
            out = t;
        } else {
            out = format!("{out} ({t})");
        }
    }
    if out.is_empty() { "Waiting".into() } else { out }
}

/// An error or blocked status: stuck at once.
pub fn blocked(s: u32) -> bool {
    s & (JOB_STATUS_ERROR | JOB_STATUS_BLOCKED_DEVQ | JOB_STATUS_USER_INTERVENTION | JOB_STATUS_PAPEROUT | JOB_STATUS_OFFLINE) != 0
}

/// Why a job is stuck.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Why {
    /// Its status says so (the words).
    Status(String),
    /// Deleting, and still there.
    Deleting,
    /// Nothing moved.
    NoProgress,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stuck {
    pub job: Job,
    pub why: Why,
    /// Since when (unix seconds).
    pub since: i64,
    /// `since` is when it began (watched, or the job's submission with nothing printed); else it
    /// is only when VibePrint first saw it so, and the line says "at least".
    pub exact: bool,
}

impl Stuck {
    pub fn minutes(&self, now: i64) -> i64 {
        ((now - self.since).max(0)) / 60
    }

    /// "A job is stuck: 'Faktura 1043.pdf' (Ola), 2 of 3 pages, for 14 minutes."
    pub fn line(&self, now: i64) -> String {
        let j = &self.job;
        let mut s = format!("A job is stuck: '{}'", crate::text::clean_max(&j.document, 60));
        if !j.owner.is_empty() {
            s.push_str(&format!(" ({})", crate::text::clean_max(&j.owner, 40)));
        }
        if j.total_pages > 0 {
            s.push_str(&format!(", {} of {} page{}", j.pages_printed.min(j.total_pages), j.total_pages, if j.total_pages == 1 { "" } else { "s" }));
        }
        let m = self.minutes(now);
        s.push_str(&match (m, self.exact) {
            (0, true) => ", for less than a minute".to_string(),
            (1, true) => ", for 1 minute".to_string(),
            (m, true) => format!(", for {m} minutes"),
            // Since when is not known: only how long VibePrint has seen it so.
            (0, false) => String::new(),
            (1, false) => ", for at least 1 minute".to_string(),
            (m, false) => format!(", for at least {m} minutes"),
        });
        match &self.why {
            Why::Status(w) => s.push_str(&format!(": {}.", w.to_lowercase())),
            Why::Deleting => s.push_str(": it is being deleted but does not go."),
            Why::NoProgress => s.push('.'),
        }
        s
    }
}

/// What moved last for one printer's first job.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    id: u32,
    submitted: i64,
    pages: u32,
    size: u64,
    status: u32,
    since: i64,
    exact: bool,
}

/// Remembers, per printer, what its first job looked like and since when; and when each job was
/// first seen in an error.
#[derive(Default, Debug)]
pub struct Tracker {
    first: HashMap<Vec<u16>, Seen>,
    /// (printer, job, submitted) -> (first seen in error, that is when it began).
    errors: HashMap<(Vec<u16>, u32, i64), (i64, bool)>,
    /// Jobs seen before without an error (an error seen later began between two reads).
    fine: std::collections::HashSet<(Vec<u16>, u32, i64)>,
}

impl Tracker {
    /// One read of `printer`'s queue at `now`: the stuck job, if any. `paused`: the printer is
    /// paused (nothing is expected to move).
    pub fn observe(&mut self, printer: &[u16], jobs: &[Job], paused: bool, now: i64) -> Option<Stuck> {
        let key = printer.to_vec();
        // Errors: the first job (in queue order) whose status says it is blocked.
        self.errors.retain(|(p, id, sub), _| p != &key || jobs.iter().any(|j| j.id == *id && j.submitted == *sub));
        self.fine.retain(|(p, id, sub)| p != &key || jobs.iter().any(|j| j.id == *id && j.submitted == *sub));
        let mut ordered: Vec<&Job> = jobs.iter().collect();
        ordered.sort_by_key(|j| (j.position, j.id));
        let mut found = None;
        for j in &ordered {
            let deleting = j.status & JOB_STATUS_DELETING != 0;
            let jk = (key.clone(), j.id, j.submitted);
            if blocked(j.status) || deleting {
                let was_fine = self.fine.contains(&jk);
                let (since, exact) = *self.errors.entry(jk).or_insert((now, was_fine));
                if found.is_none() {
                    if blocked(j.status) {
                        found = Some(Stuck { job: (*j).clone(), why: Why::Status(status_words(j.status & !JOB_STATUS_PRINTING & !JOB_STATUS_SPOOLING, &j.status_text)), since, exact });
                    } else if now - since >= STUCK_AFTER_S {
                        found = Some(Stuck { job: (*j).clone(), why: Why::Deleting, since, exact });
                    }
                }
            } else {
                self.fine.insert(jk);
            }
        }
        if found.is_some() {
            return found;
        }
        // No progress: the first job.
        let Some(first) = ordered.first() else {
            self.first.remove(&key);
            return None;
        };
        let same = |s: &Seen| s.id == first.id && s.submitted == first.submitted;
        let moved = |s: &Seen| s.pages != first.pages_printed || s.size != first.size || s.status != first.status;
        let seen = match self.first.get(&key) {
            Some(s) if same(s) && !moved(s) => s.clone(),
            Some(s) if same(s) => Seen { pages: first.pages_printed, size: first.size, status: first.status, since: now, exact: true, ..s.clone() },
            _ => {
                // First sight: a job that has printed nothing and is not being written counts from
                // when it was submitted; otherwise from now.
                let fresh = first.pages_printed == 0 && first.status & JOB_STATUS_SPOOLING == 0 && first.submitted > 0;
                Seen { id: first.id, submitted: first.submitted, pages: first.pages_printed, size: first.size, status: first.status, since: if fresh { first.submitted.min(now) } else { now }, exact: fresh }
            }
        };
        // Paused (the printer or the job) or still being written: nothing is expected to move, so
        // the clock waits with it.
        let held = paused || first.status & (JOB_STATUS_PAUSED | JOB_STATUS_SPOOLING) != 0;
        let seen = if held { Seen { since: now, exact: true, ..seen } } else { seen };
        self.first.insert(key, seen.clone());
        (!held && now - seen.since >= STUCK_AFTER_S).then(|| Stuck { job: (*first).clone(), why: Why::NoProgress, since: seen.since, exact: seen.exact })
    }

    /// Forget a printer (it went away).
    pub fn forget(&mut self, printer: &[u16]) {
        self.first.remove(printer);
        self.errors.retain(|(p, _, _), _| p != printer);
        self.fine.retain(|(p, _, _)| p != printer);
    }
}

#[cfg(windows)]
pub mod sys {
    use super::Job;
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Graphics::Printing::*;

    unsafe fn wstr(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        // SAFETY: a NUL-terminated string inside the caller's buffer.
        unsafe {
            let len = (0..).take_while(|&i| *p.add(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
        }
    }

    /// A SYSTEMTIME (UTC) as unix seconds.
    fn unix(st: &windows_sys::Win32::Foundation::SYSTEMTIME) -> i64 {
        let mut ft = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        // SAFETY: plain structs.
        if unsafe { windows_sys::Win32::System::Time::SystemTimeToFileTime(st, &mut ft) } == 0 {
            return 0;
        }
        crate::drivers::filetime_unix(((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64).unwrap_or(0)
    }

    /// The user running VibePrint (jobs are theirs when the spooler names them so).
    pub fn user_name() -> String {
        use windows_sys::Win32::System::WindowsProgramming::GetUserNameW;
        let mut buf = [0u16; 257];
        let mut n = buf.len() as u32;
        // SAFETY: a buffer and its length.
        if unsafe { GetUserNameW(buf.as_mut_ptr(), &mut n) } == 0 {
            return String::new();
        }
        String::from_utf16_lossy(&buf[..(n as usize).saturating_sub(1)])
    }

    /// The first 500 jobs of printer `name` (EnumJobsW level 2).
    pub fn jobs(name: &[u16], me: &str) -> Result<Vec<Job>, u32> {
        let h = crate::printers::sys::open(name, PRINTER_ACCESS_USE)?;
        let mut need = 0u32;
        let mut count = 0u32;
        // SAFETY: a size query, then a buffer of that size (8-aligned).
        unsafe { EnumJobsW(h.0, 0, 500, 2, std::ptr::null_mut(), 0, &mut need, &mut count) };
        if need == 0 {
            let e = unsafe { GetLastError() };
            return if e == 0 || e == ERROR_INSUFFICIENT_BUFFER { Ok(Vec::new()) } else { Err(e) };
        }
        let mut buf = vec![0u64; (need as usize).div_ceil(8)];
        if unsafe { EnumJobsW(h.0, 0, 500, 2, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut need, &mut count) } == 0 {
            return Err(unsafe { GetLastError() });
        }
        // SAFETY: `count` JOB_INFO_2W records; strings inside `buf`.
        let rows = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const JOB_INFO_2W, count as usize) };
        Ok(rows
            .iter()
            .map(|r| unsafe {
                let owner = wstr(r.pUserName);
                Job {
                    id: r.JobId,
                    document: wstr(r.pDocument),
                    mine: !me.is_empty() && owner.eq_ignore_ascii_case(me),
                    owner,
                    machine: wstr(r.pMachineName),
                    pages_printed: r.PagesPrinted,
                    total_pages: r.TotalPages,
                    size: r.Size as u64,
                    status: r.Status,
                    status_text: wstr(r.pStatus),
                    submitted: unix(&r.Submitted),
                    position: r.Position,
                }
            })
            .collect())
    }

    /// Delete one job (a user's own: no admin rights needed).
    pub fn delete_job(name: &[u16], id: u32) -> Result<(), u32> {
        let h = crate::printers::sys::open(name, PRINTER_ACCESS_USE)?;
        // SAFETY: an open printer handle; no job info, only the command.
        if unsafe { SetJobW(h.0, id, 0, std::ptr::null(), JOB_CONTROL_DELETE) } == 0 { Err(unsafe { GetLastError() }) } else { Ok(()) }
    }
}
